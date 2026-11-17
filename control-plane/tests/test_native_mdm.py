"""Real Postgres + synthetic PKI protocol/security tests, not iPhone tests."""
import json
import plistlib
import ssl
import threading
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy import select

from app import native_mdm as n
from app import mdm_ops
from app.db import session_scope
from app.models import Device, MDMEnrollment, MDMProvision, MDMCommand, Tenant, utcnow
from app.native_mdm_server import TLSServer, handler_for, tls_context
from mdm.identity import PKCS12Issuer, ProfileSigner, verify_signed_profile
from mdm.profiles import REQUIRED_EVIDENCE, ManualSupervisionDeclaration
from mdm.ade_identity import ADEIdentityVerifier
from mdm.adapter import SimulatedMDMAdapter
from mdm.reconciler import reconcile
from mdm.tests.pki_fixtures import make_ca, leaf, write_identity

UDID = "00008030-001234567890ABCD"
TOPIC = "com.apple.mgmt.synthetic-test"


@pytest.fixture
def runtime(tmp_path):
    ca, key = make_ca()
    signer, signerkey = leaf(ca, key)
    trust = tmp_path/"trust.pem"
    trust.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    r = n.EnrollmentRuntime(issuer=PKCS12Issuer(ca, key),
        signer=ProfileSigner(signer, signerkey, [ca]), signer_trust_file=str(trust),
        base_url="https://localhost:8443", organization="SYNTHETIC TEST ONLY",
        allowed_topics={1: TOPIC}, token_encryption_key=Fernet.generate_key(),
        authorization_reference="SYNTHETIC TEST ONLY - NOT APPLE APPROVAL")
    r.test_ca, r.test_cakey = ca, key
    return r


@pytest.fixture
def fleet(engine, runtime):
    with session_scope(engine) as s:
        a, b = Tenant(name="native-a"), Tenant(name="native-b")
        s.add_all([a,b]); s.flush()
        devices = [Device(tenant_id=a.id, name="phone"), Device(tenant_id=a.id, name="phone2"), Device(tenant_id=b.id, name="other")]
        s.add_all(devices); s.flush()
        result = a.id, b.id, [d.id for d in devices]
    runtime.topics = {result[0]: TOPIC, result[1]: TOPIC+"-b"}
    return result


def issued(engine, runtime, fleet, mode="ordinary", **kwargs):
    a,b,devices = fleet
    if mode == "manual_supervised":
        kwargs.setdefault("declaration", ManualSupervisionDeclaration("S1", True, "operator", utcnow(), REQUIRED_EVIDENCE))
    with session_scope(engine) as s:
        return n.issue(s, runtime, tenant_id=a, device_id=devices[0],
            udid=UDID, serial="S1", mode=mode, **kwargs)


def downloaded(engine, runtime, token):
    with session_scope(engine) as s:
        signed = n.download_profile(s, runtime, token)
    profile = plistlib.loads(verify_signed_profile(signed, runtime.signer_trust_file))
    identity = profile["PayloadContent"][0]
    key, cert, chain = pkcs12.load_key_and_certificates(identity["PayloadContent"], identity["Password"].encode())
    return profile, key, cert


def msg(engine, runtime, cert, path="/checkin", **body):
    peer = cert.public_bytes(serialization.Encoding.DER) if cert else None
    with session_scope(engine) as s:
        return n.device_message(s, runtime, peer, path, plistlib.dumps({"UDID": UDID, **body}))


def enrolled(engine, runtime, fleet):
    token, pk = issued(engine, runtime, fleet)
    _,key,cert = downloaded(engine, runtime, token)
    msg(engine,runtime,cert,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")
    msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"a"*32,PushMagic="magic",UnlockToken=b"unlock")
    return pk,key,cert


def test_end_to_end_lifecycle_queue_and_supervision(engine,runtime,fleet):
    token,pk = issued(engine,runtime,fleet)
    profile,key,cert = downloaded(engine,runtime,token)
    assert "PayloadRemovalDisallowed" not in profile
    with session_scope(engine) as s:
        p=s.scalar(select(MDMProvision)); e=s.get(MDMEnrollment,pk)
        assert p.stage == "profile_served" and e.state == "pending"
        assert p.cert_sha256 and p.cert_der and e.supervision_verified is False
        assert token not in p.ticket_hash and p.ticket_hash == n.digest(token)
    msg(engine,runtime,cert,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")
    with session_scope(engine) as s:
        assert s.get(MDMEnrollment,pk).state == "pending"
    msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"a"*32,PushMagic="magic",UnlockToken=b"unlock")
    with session_scope(engine) as s:
        e=s.get(MDMEnrollment,pk); p=s.scalar(select(MDMProvision))
        assert e.state == "enrolled" and e.supervision_verified is False
        assert "magic" not in p.push_ciphertext
        first=mdm_ops.issue_command(s,fleet[0],pk,"DeviceInformation",{},None)
        second=mdm_ops.issue_command(s,fleet[0],pk,"ProfileList",{},None)
        firstid,secondid=first.id,second.id
    wire=plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Idle"))
    assert wire["CommandUUID"] == str(firstid)
    assert wire["Command"]["RequestType"] == "DeviceInformation"
    assert "IsSupervised" in wire["Command"]["Queries"]
    assert plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Idle")) == wire
    wire2=plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Acknowledged",CommandUUID=str(firstid),QueryResponses={"UDID":UDID,"SerialNumber":"S1","IsSupervised":True}))
    assert wire2["CommandUUID"] == str(secondid)
    with session_scope(engine) as s:
        e=s.get(MDMEnrollment,pk)
        assert e.supervision_verified is True
        assert s.get(MDMCommand,firstid).status == "acknowledged"
        assert s.get(MDMCommand,firstid).applied is False
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,path="/mdm",Status="Acknowledged",CommandUUID=str(firstid))
    assert msg(engine,runtime,cert,path="/mdm",Status="NotNow",CommandUUID=str(secondid)) == b""
    assert plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Idle"))["CommandUUID"] == str(secondid)
    msg(engine,runtime,cert,MessageType="CheckOut")
    with session_scope(engine) as s:
        assert s.get(MDMEnrollment,pk).state == "unenrolled"
        p=s.scalar(select(MDMProvision)); assert p.revoked_at and p.push_ciphertext is None
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,path="/mdm",Status="Idle")


def test_token_rotation_retains_unlock_and_bad_topic_rolls_back(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"b"*32,PushMagic="new")
    with session_scope(engine) as s:
        p=s.scalar(select(MDMProvision))
        secret=json.loads(runtime.fernet.decrypt(p.push_ciphertext.encode()))
        assert secret == {"token":(b"b"*32).hex(),"push_magic":"new","unlock_token":b"unlock".hex()}
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC+"wrong",Token=b"b"*32,PushMagic="bad")
    with session_scope(engine) as s:
        assert "bad" not in runtime.fernet.decrypt(s.scalar(select(MDMProvision)).push_ciphertext.encode()).decode()


@pytest.mark.parametrize("mode",["ordinary","manual_supervised"])
def test_profile_one_use_and_default_vs_manual(engine,runtime,fleet,mode):
    token,pk=issued(engine,runtime,fleet,mode)
    profile,key,cert=downloaded(engine,runtime,token)
    assert profile.get("PayloadRemovalDisallowed",False) == (mode == "manual_supervised")
    with pytest.raises(n.TransportError,match="used"):
        downloaded(engine,runtime,token)
    with session_scope(engine) as s:
        with pytest.raises(n.TransportError):
            n.issue(s,runtime,tenant_id=fleet[0],device_id=fleet[2][0],udid=UDID,serial="S1")


def test_cross_tenant_device_udid_and_revoke_guards(engine,runtime,fleet):
    token,pk=issued(engine,runtime,fleet)
    with session_scope(engine) as s:
        with pytest.raises(n.TransportError):
            n.issue(s,runtime,tenant_id=fleet[1],device_id=fleet[2][0],udid=UDID+"x",serial="S1")
        with pytest.raises(n.TransportError):
            n.issue(s,runtime,tenant_id=fleet[1],device_id=fleet[2][2],udid=UDID,serial="S1")
        with pytest.raises(n.TransportError):
            n.revoke(s,tenant_id=fleet[1],enrollment_pk=pk)
    _,key,cert=downloaded(engine,runtime,token)
    with session_scope(engine) as s:
        n.revoke(s,tenant_id=fleet[0],enrollment_pk=pk)
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")


def test_expiry_invalid_identity_and_order(engine,runtime,fleet):
    token,pk=issued(engine,runtime,fleet)
    with session_scope(engine) as s:
        p=s.scalar(select(MDMProvision)); p.ticket_expires_at=utcnow()-timedelta(seconds=1)
    with pytest.raises(n.TransportError,match="expired"):
        downloaded(engine,runtime,token)
    with session_scope(engine) as s:
        p=s.scalar(select(MDMProvision)); p.ticket_expires_at=utcnow()+timedelta(minutes=1)
    _,key,cert=downloaded(engine,runtime,token)
    for peer in [None, leaf(runtime.test_ca,runtime.test_cakey)[0]]:
        with pytest.raises(n.TransportError):
            msg(engine,runtime,peer,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"a"*32,PushMagic="magic")
    for body in [{"Topic":"wrong","SerialNumber":"S1"},{"Topic":TOPIC,"SerialNumber":"other"},{"Topic":TOPIC,"SerialNumber":"S1","UDID":"forged"}]:
        with pytest.raises(n.TransportError):
            msg(engine,runtime,cert,MessageType="Authenticate",**body)
    msg(engine,runtime,cert,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")
    # Transport retry after a lost 200 is idempotent, not another enrollment.
    msg(engine,runtime,cert,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")
    with session_scope(engine) as s:
        s.get(Device,fleet[2][0]).state="offboarded"
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"a"*32,PushMagic="magic")


def test_concurrent_download_exactly_one(engine,runtime,fleet):
    token,pk=issued(engine,runtime,fleet)
    barrier=threading.Barrier(2)
    def redeem():
        barrier.wait()
        try:
            downloaded(engine,runtime,token)
            return "ok"
        except n.TransportError:
            return "rejected"
    with ThreadPoolExecutor(2) as pool:
        result=list(pool.map(lambda _:redeem(),range(2)))
    assert sorted(result)==["ok","rejected"]


def test_native_not_sent_to_nanomdm_or_reconciled(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    adapter=SimulatedMDMAdapter()
    with session_scope(engine) as s:
        command=mdm_ops.issue_command(s,fleet[0],pk,"ProfileList",{},None,adapter=adapter)
        assert command.status=="queued" and adapter.calls==[]
        assert reconcile(s,fleet[0],[{"command_id":command.id,"status":"Acknowledged"}]).skipped==1
        assert command.status=="queued"
        for name in ["DeclarativeManagement","InstallApplication","EraseDevice"]:
            with pytest.raises(mdm_ops.MDMError):
                mdm_ops.issue_command(s,fleet[0],pk,name,{},None,adapter=adapter)


def test_other_tenant_command_cannot_ack(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    with session_scope(engine) as s:
        other=MDMEnrollment(tenant_id=fleet[1],device_id=fleet[2][2],enrollment_id="other",state="enrolled")
        s.add(other);s.flush()
        c=MDMCommand(tenant_id=fleet[1],enrollment_pk=other.id,command="ProfileList",status="delivered")
        s.add(c);s.flush(); cid=c.id
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,path="/mdm",Status="Acknowledged",CommandUUID=str(cid))
    with session_scope(engine) as s:
        assert s.get(MDMCommand,cid).status=="delivered"


def test_actual_tls_profile_download_peer_certificate_and_spoofed_header(engine,runtime,fleet,tmp_path):
    token,pk=issued(engine,runtime,fleet)
    servercert,serverkey=leaf(runtime.test_ca,runtime.test_cakey,server=True)
    certfile,keyfile=write_identity(tmp_path,"server",servercert,serverkey)
    context=tls_context(cert_file=certfile,key_file=keyfile,identity_ca_file=runtime.signer_trust_file)
    server=TLSServer(("127.0.0.1",0),handler_for(engine,runtime),context)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    port=server.server_address[1]
    trust=ssl.create_default_context(cafile=runtime.signer_trust_file)
    url=f"https://localhost:{port}"
    body=plistlib.dumps({"UDID":UDID,"MessageType":"Authenticate","Topic":TOPIC,"SerialNumber":"S1"})
    try:
        with httpx.Client(verify=trust,trust_env=False) as c:
            response=c.get(url+"/enroll/"+token)
            assert response.status_code==200
            assert response.headers["cache-control"]=="no-store"
            profile=plistlib.loads(verify_signed_profile(response.content,runtime.signer_trust_file))
            ident=profile["PayloadContent"][0]
            key,cert,_=pkcs12.load_key_and_certificates(ident["PayloadContent"],ident["Password"].encode())
            certpath,keypath=write_identity(tmp_path,"device",cert,key)
            assert c.put(url+"/checkin",content=body,headers={"X-Client-Cert":"forged"}).status_code==403
        trust.load_cert_chain(certpath,keypath)
        with httpx.Client(verify=trust,trust_env=False) as c:
            assert c.put(url+"/checkin",content=body).status_code==200
            assert c.put(url+"/checkin",content=b"not plist").status_code==400
            assert c.get(url+"/enroll/"+token).status_code==409
            assert c.put(url+"/mdm?bypass=1",content=body).status_code==404
        # Same trusted CA but unissued client certificate is still rejected.
        unissued,ukey=leaf(runtime.test_ca,runtime.test_cakey)
        cp,kp=write_identity(tmp_path,"unissued",unissued,ukey)
        untrusted=ssl.create_default_context(cafile=runtime.signer_trust_file);untrusted.load_cert_chain(cp,kp)
        with httpx.Client(verify=untrusted,trust_env=False) as c:
            assert c.put(url+"/checkin",content=body).status_code==403
        # A certificate from another CA fails the TLS handshake, not a header check.
        otherca,otherkey=make_ca(); bad,bkey=leaf(otherca,otherkey)
        cp,kp=write_identity(tmp_path,"wrongca",bad,bkey)
        wrong=ssl.create_default_context(cafile=runtime.signer_trust_file);wrong.load_cert_chain(cp,kp)
        with httpx.Client(verify=wrong,trust_env=False) as c:
            with pytest.raises(httpx.TransportError):
                c.put(url+"/checkin",content=body)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)


def test_ade_handoff_and_envelope_replay(engine,runtime,fleet):
    from cryptography.hazmat.primitives import hashes
    machine,mkey=leaf(runtime.test_ca,runtime.test_cakey)
    pins={(fleet[0],"S1"):machine.fingerprint(hashes.SHA256()).hex()}
    runtime.ade_verifier=ADEIdentityVerifier(apple_root_file=runtime.signer_trust_file,
        assigned_device_lookup=lambda t,s:{"assigned":t==fleet[0],"udid":UDID},signer_pins=pins)
    token,pk=issued(engine,runtime,fleet,mode="ade")
    with pytest.raises(n.TransportError):
        downloaded(engine,runtime,token)
    envelope=ProfileSigner(machine,mkey,[runtime.test_ca]).sign(plistlib.dumps({"SERIAL":"S1","UDID":UDID}))
    with session_scope(engine) as s:
        signed=n.download_profile(s,runtime,token,machineinfo=envelope)
    assert "PayloadRemovalDisallowed" not in plistlib.loads(verify_signed_profile(signed,runtime.signer_trust_file))
    with session_scope(engine) as s:
        n.revoke(s,tenant_id=fleet[0],enrollment_pk=pk)
    token2,pk2=issued(engine,runtime,fleet,mode="ade")
    with session_scope(engine) as s:
        with pytest.raises(n.TransportError,match="already used"):
            n.download_profile(s,runtime,token2,machineinfo=envelope)


def test_push_boundaries_and_token_failure(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    class Fake:
        def push(self,**kw):
            assert kw=={"topic":TOPIC,"token":(b"a"*32).hex(),"push_magic":"magic"}
            return {"accepted":False,"classification":"bad_token"}
    with session_scope(engine) as s:
        with pytest.raises(n.TransportError):
            n.customer_push(s,runtime,Fake(),tenant_id=fleet[1],enrollment_pk=pk)
        result=n.customer_push(s,runtime,Fake(),tenant_id=fleet[0],enrollment_pk=pk)
        assert not result["accepted"]
    with session_scope(engine) as s:
        assert s.scalar(select(MDMProvision)).push_ciphertext is None


def test_native_authenticated_routes_disabled_and_tenant_scope(engine,runtime,fleet):
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app
    from app import security
    from app.models import User,Role
    from mfa_support import mfa_login
    headers={"X-KosherGuard-Request":"1"}
    with session_scope(engine) as s:
        s.add(User(tenant_id=fleet[0],email="native-owner@example.test",password_hash=security.hash_password("a long enough password"),role=Role.owner))
    settings=Settings({"KG_DATABASE_URL":"postgresql://unused","KG_PUBLICATIONS_ROOT":"/tmp/native-tests"})
    c=TestClient(create_app(settings,engine=engine,native_mdm_runtime=runtime))
    payload={"udid":UDID,"serial":"S1"}
    assert c.post(f"/api/mdm/devices/{fleet[2][0]}/native-enrollment",json=payload,headers=headers).status_code==401
    assert mfa_login(c,json={"email":"native-owner@example.test","password":"a long enough password"},headers=headers).status_code==200
    assert c.post(f"/api/mdm/devices/{fleet[2][0]}/native-enrollment",json=payload).status_code==403
    assert c.post(f"/api/mdm/devices/{fleet[2][2]}/native-enrollment",json=payload,headers=headers).status_code==404
    issued=c.post(f"/api/mdm/devices/{fleet[2][0]}/native-enrollment",json=payload,headers=headers)
    assert issued.status_code==200 and issued.json()["one_use"] is True
    pk=issued.json()["enrollment_pk"]
    assert c.get("/api/mdm/native-enrollments").json()["enrollments"][0]["enrollment_pk"]==pk
    assert c.delete(f"/api/mdm/native-enrollments/{pk}",headers=headers).json()["removed_from_device"] is False
    disabled=TestClient(create_app(settings,engine=engine))
    disabled.cookies.update(c.cookies)  # Same persisted verified session; runtime config differs only.
    assert disabled.post(f"/api/mdm/devices/{fleet[2][1]}/native-enrollment",json=payload,headers=headers).status_code==503


def test_private_config_permissions_and_repo_guard(tmp_path):
    from app.native_mdm_config import private_file
    from mdm.identity import ProvisioningError
    path=tmp_path/"secrets.json";path.write_text("{}")
    path.chmod(0o644)
    with pytest.raises(ProvisioningError):private_file(path)
    path.chmod(0o600)
    assert private_file(path)==path
    from app.native_mdm_config import REPO_ROOT
    with pytest.raises(ProvisioningError):private_file(REPO_ROOT/"control-plane/app/main.py")


def test_notnow_retries_before_later_queued_command(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    with session_scope(engine) as s:
        first=mdm_ops.issue_command(s,fleet[0],pk,"InstallProfile",{"profile":{"PayloadType":"Configuration","PayloadContent":[]}},None)
        second=mdm_ops.issue_command(s,fleet[0],pk,"ProfileList",{},None)
        firstid,secondid=first.id,second.id
    assert plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Idle"))["CommandUUID"]==str(firstid)
    assert msg(engine,runtime,cert,path="/mdm",Status="NotNow",CommandUUID=str(firstid))==b""
    with session_scope(engine) as s:
        assert s.get(MDMCommand,secondid).status=="queued"
    assert plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Idle"))["CommandUUID"]==str(firstid)
    assert plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Acknowledged",CommandUUID=str(firstid)))["CommandUUID"]==str(secondid)


def test_tls_listener_bounds_unauthenticated_slow_connections(engine,runtime,tmp_path):
    import socket,time
    cert,key=leaf(runtime.test_ca,runtime.test_cakey,server=True)
    cp,kp=write_identity(tmp_path,"bound-server",cert,key)
    context=tls_context(cert_file=cp,key_file=kp,identity_ca_file=runtime.signer_trust_file)
    server=TLSServer(("127.0.0.1",0),handler_for(engine,runtime),context,max_workers=1,handshake_timeout=0.3,requests_per_minute=10)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    address=server.server_address
    slow=socket.create_connection(address);slow.settimeout(1)
    try:
        deadline=time.monotonic()+1
        while server._admission.acquire(blocking=False):
            server._admission.release()
            assert time.monotonic()<deadline
            time.sleep(.01)
        second=socket.create_connection(address);second.settimeout(1)
        try:
            assert second.recv(1)==b""  # rejected before a second handshake/worker
        finally:second.close()
        slow.close()
        time.sleep(.35)
        context=ssl.create_default_context(cafile=runtime.signer_trust_file)
        with httpx.Client(verify=context,trust_env=False) as c:
            assert c.get(f"https://localhost:{address[1]}/unknown").status_code==404
        assert len(server._rate)<=1024
        for _ in range(100):server._rate_allowed("same-ip")
        assert len(server._rate["same-ip"])<=10
    finally:
        slow.close();server.shutdown();server.server_close();thread.join(timeout=2)


def test_exact_duplicate_command_reply_is_idempotent_conflicting_replay_rejects(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    with session_scope(engine) as s:
        c=mdm_ops.issue_command(s,fleet[0],pk,"ProfileList",{},None);cid=c.id
        other=mdm_ops.issue_command(s,fleet[0],pk,"DeviceInformation",{},None);oid=other.id
    msg(engine,runtime,cert,path="/mdm",Status="Idle")
    reply={"Status":"Acknowledged","CommandUUID":str(cid)}
    first=msg(engine,runtime,cert,path="/mdm",**reply)
    assert plistlib.loads(first)["CommandUUID"]==str(oid)
    assert msg(engine,runtime,cert,path="/mdm",**reply)==first
    with pytest.raises(n.TransportError):
        msg(engine,runtime,cert,path="/mdm",Status="Error",CommandUUID=str(cid))


def test_native_identity_rotation_overlap_and_new_tokenupdate_promotion(engine,runtime,fleet):
    pk,key,oldcert=enrolled(engine,runtime,fleet)
    with session_scope(engine) as s:
        cid=n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
        c=s.get(MDMCommand,cid)
        assert "PRIVATE KEY" not in c.payload and "cms_base64" not in c.payload
        assert "_native_encrypted_profile" in c.payload
    wire=plistlib.loads(msg(engine,runtime,oldcert,path="/mdm",Status="Idle"))
    signed=wire["Command"]["Payload"]
    profile=plistlib.loads(verify_signed_profile(signed,runtime.signer_trust_file))
    identity=profile["PayloadContent"][0]
    newkey,newcert,_=pkcs12.load_key_and_certificates(identity["PayloadContent"],identity["Password"].encode())
    assert newcert!=oldcert
    # Old key works during replacement; mere ACK doesn't discard it.
    msg(engine,runtime,oldcert,path="/mdm",Status="Acknowledged",CommandUUID=str(cid))
    msg(engine,runtime,oldcert,path="/mdm",Status="Idle")
    msg(engine,runtime,newcert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"c"*32,PushMagic="renewed")
    msg(engine,runtime,newcert,path="/mdm",Status="Idle")
    with pytest.raises(n.TransportError):
        msg(engine,runtime,oldcert,path="/mdm",Status="Idle")
    with session_scope(engine) as s:
        p=s.scalar(select(MDMProvision))
        assert p.pending_cert_der is None and p.pending_cert_sha256 is None
        assert p.cert_der==newcert.public_bytes(serialization.Encoding.DER)


def test_checkin_waits_for_device_lock_and_observes_offboarding(engine,runtime,fleet):
    import time
    pk,key,cert=enrolled(engine,runtime,fleet)
    locked=threading.Event();release=threading.Event()
    def offboard():
        with session_scope(engine) as s:
            device=s.scalar(select(Device).where(Device.id==fleet[2][0]).with_for_update())
            locked.set();assert release.wait(3)
            device.state="offboarded"
            s.get(MDMEnrollment,pk).state="offboarded"
            n.cleanup_enrollment(s,tenant_id=fleet[0],enrollment_pk=pk,reason="offboarded")
    def tokenupdate():
        try:
            msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"d"*32,PushMagic="must-not-reactivate")
            return "accepted"
        except n.TransportError:return "rejected"
    with ThreadPoolExecutor(2) as pool:
        future=pool.submit(offboard);assert locked.wait(2)
        update=pool.submit(tokenupdate)
        time.sleep(.05);assert not update.done()
        release.set();future.result(timeout=3)
        assert update.result(timeout=3)=="rejected"
    with session_scope(engine) as s:
        p=s.scalar(select(MDMProvision))
        assert p.stage=="offboarded" and p.push_ciphertext is None
        assert s.get(MDMEnrollment,pk).state=="offboarded"


def test_durable_push_outbox_registry_backoff_and_expiry_health(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    class Fake:
        topic=TOPIC
        calls=0
        def push(self,**kwargs):
            self.calls+=1
            return {"accepted":False,"classification":"retryable"}
    transport=Fake()
    with session_scope(engine) as s:
        mdm_ops.issue_command(s,fleet[0],pk,"ProfileList",{},None)
        assert s.scalar(select(MDMProvision)).push_state=="due"
    with session_scope(engine) as s:
        result=n.dispatch_customer_pushes(s,runtime,transport,tenant_id=fleet[0])
        assert result[0]["state"]=="backoff"
    with session_scope(engine) as s:
        assert n.dispatch_customer_pushes(s,runtime,transport,tenant_id=fleet[0])==[]
        p=s.scalar(select(MDMProvision));assert p.push_attempts==1 and p.push_next_at
        p.push_next_at=utcnow()-timedelta(seconds=1)
        with pytest.raises(n.TransportError):n.dispatch_customer_pushes(s,runtime,transport,tenant_id=fleet[1])
    with session_scope(engine) as s:
        assert n.dispatch_customer_pushes(s,runtime,transport,tenant_id=fleet[0])[0]["state"]=="backoff"
        p=s.scalar(select(MDMProvision));assert p.push_attempts==2
        p.cert_expires_at=utcnow()+timedelta(days=6)
        assert n.scan_identity_expiry(s,tenant_id=fleet[0])[0]["health"]=="renewal_due"
    with session_scope(engine) as s:
        assert n.scan_identity_expiry(s,tenant_id=fleet[0])==[]
        p=s.scalar(select(MDMProvision));p.cert_expires_at=utcnow()-timedelta(seconds=1)
        assert n.scan_identity_expiry(s,tenant_id=fleet[0])[0]["health"]=="expired"
    assert transport.calls==2


def test_only_definitely_undelivered_renewal_can_be_canceled(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    with session_scope(engine) as s:
        cid=n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
        n.cancel_undelivered_renewal(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
        assert s.scalar(select(MDMProvision)).pending_cert_der is None
        assert s.get(MDMCommand,cid).payload=="{}"
    with session_scope(engine) as s:
        cid=n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
    msg(engine,runtime,cert,path="/mdm",Status="Idle")
    with session_scope(engine) as s:
        with pytest.raises(n.TransportError):
            n.cancel_undelivered_renewal(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
        assert s.scalar(select(MDMProvision)).pending_cert_der is not None


def test_pending_identity_authenticate_notnow_failure_keeps_old_pin(engine,runtime,fleet):
    pk,key,old=enrolled(engine,runtime,fleet)
    with session_scope(engine) as s:
        cid=n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
        with pytest.raises(n.TransportError):n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
    wire=plistlib.loads(msg(engine,runtime,old,path="/mdm",Status="Idle"))
    profile=plistlib.loads(verify_signed_profile(wire["Command"]["Payload"],runtime.signer_trust_file))
    ident=profile["PayloadContent"][0]
    _,new,_=pkcs12.load_key_and_certificates(ident["PayloadContent"],ident["Password"].encode())
    msg(engine,runtime,new,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")
    with session_scope(engine) as s:
        assert s.scalar(select(MDMProvision)).stage=="enrolled"
        assert s.scalar(select(MDMProvision)).cert_der==old.public_bytes(serialization.Encoding.DER)
    assert msg(engine,runtime,old,path="/mdm",Status="NotNow",CommandUUID=str(cid))==b""
    assert plistlib.loads(msg(engine,runtime,old,path="/mdm",Status="Idle"))["CommandUUID"]==str(cid)
    msg(engine,runtime,old,path="/mdm",Status="Error",CommandUUID=str(cid))
    msg(engine,runtime,old,path="/mdm",Status="Idle")
    with session_scope(engine) as s:
        p=s.scalar(select(MDMProvision))
        assert p.pending_cert_der==new.public_bytes(serialization.Encoding.DER)
        assert p.cert_der==old.public_bytes(serialization.Encoding.DER)
    # A failed/ambiguous device response does NOT retire either pin on a guess.
    with pytest.raises(n.TransportError):
        msg(engine,runtime,new,MessageType="TokenUpdate",Topic=TOPIC+"wrong",Token=b"c"*32,PushMagic="bad")
    msg(engine,runtime,old,path="/mdm",Status="Idle")


def test_manual_renewal_requires_fresh_matching_declaration_and_near_expiry_rejects(engine,runtime,fleet):
    token,pk=issued(engine,runtime,fleet,mode="manual_supervised")
    _,key,cert=downloaded(engine,runtime,token)
    msg(engine,runtime,cert,MessageType="Authenticate",Topic=TOPIC,SerialNumber="S1")
    msg(engine,runtime,cert,MessageType="TokenUpdate",Topic=TOPIC,Token=b"x"*32,PushMagic="magic")
    with session_scope(engine) as s:
        with pytest.raises(n.TransportError):n.renew_identity(s,runtime,tenant_id=fleet[1],enrollment_pk=pk)
        with pytest.raises(n.TransportError):n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk)
        wrong=ManualSupervisionDeclaration("WRONG",True,"operator",utcnow(),REQUIRED_EVIDENCE)
        with pytest.raises(n.TransportError):n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk,declaration=wrong)
        p=s.scalar(select(MDMProvision));p.cert_expires_at=utcnow()+timedelta(hours=12)
        good=ManualSupervisionDeclaration("S1",True,"operator",utcnow(),REQUIRED_EVIDENCE)
        with pytest.raises(n.TransportError):n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk,declaration=good)
        p.cert_expires_at=utcnow()+timedelta(days=10)
        cid=n.renew_identity(s,runtime,tenant_id=fleet[0],enrollment_pk=pk,declaration=good)
    profile=plistlib.loads(verify_signed_profile(plistlib.loads(msg(engine,runtime,cert,path="/mdm",Status="Idle"))["Command"]["Payload"],runtime.signer_trust_file))
    assert profile["PayloadRemovalDisallowed"] is True


def test_push_exhaustion_cert_error_no_delivery_and_offboard_stops_dispatch(engine,runtime,fleet):
    pk,key,cert=enrolled(engine,runtime,fleet)
    class Fake:
        topic=TOPIC
        result={"accepted":True,"delivered":False}
        def push(self,**kw):return self.result
    transport=Fake()
    with session_scope(engine) as s:
        mdm_ops.issue_command(s,fleet[0],pk,"ProfileList",{},None)
        p=s.scalar(select(MDMProvision));p.push_attempts=7
        assert n.dispatch_customer_pushes(s,runtime,transport,tenant_id=fleet[0])[0]["state"]=="exhausted"
        assert s.scalar(select(MDMCommand)).status=="queued"
        p.push_state="due";p.push_next_at=utcnow();p.push_attempts=0
        transport.result={"accepted":False,"classification":"cert_problem"}
        assert n.dispatch_customer_pushes(s,runtime,transport,tenant_id=fleet[0])[0]["state"]=="cert_problem"
        p.push_state="due";p.push_next_at=utcnow()
        n.revoke(s,tenant_id=fleet[0],enrollment_pk=pk)
        assert n.dispatch_customer_pushes(s,runtime,transport,tenant_id=fleet[0])==[]


def test_worker_once_calls_expiry_dispatch_and_closes_customer_transport(engine,runtime,fleet,tmp_path,monkeypatch):
    from app import native_mdm_worker as w
    import contextlib
    calls=[]
    runtime.topics={fleet[0]:TOPIC}
    private=tmp_path/"worker.json"
    private.write_text(json.dumps({"customer_apns_certificate_file":"synthetic.pem","customer_apns_private_key_file":"synthetic.key","customer_instance_reference":"TEST ONLY"}));private.chmod(0o600)
    monkeypatch.setenv("KG_NATIVE_MDM_CONFIG",str(private))
    monkeypatch.setattr(w,"private_file",lambda path: private if str(path)==str(private) else path)
    class FakeEngine:
        def dispose(self):calls.append("dispose")
    class FakeTransport:
        def __init__(self,**kw):assert kw["topic"]==TOPIC
        def close(self):calls.append("close")
    @contextlib.contextmanager
    def scope(eng):yield object()
    monkeypatch.setattr(w,"factory",lambda:(FakeEngine(),runtime,None))
    monkeypatch.setattr(w,"CustomerAPNsTransport",FakeTransport)
    monkeypatch.setattr(w,"session_scope",scope)
    monkeypatch.setattr(w,"scan_identity_expiry",lambda *a,**kw:calls.append(("expiry",kw["tenant_id"])))
    monkeypatch.setattr(w,"dispatch_customer_pushes",lambda *a,**kw:calls.append(("dispatch",kw["tenant_id"])))
    monkeypatch.setattr("sys.argv",["native-worker","--once"])
    w.main()
    assert calls==[("expiry",fleet[0]),("dispatch",fleet[0]),"close","dispose"]


def test_private_configuration_factory_wires_real_issuer_signer_tls_and_ade_lookup(engine,runtime,fleet,tmp_path,monkeypatch):
    from app.native_mdm_config import factory
    ca,ca_key=runtime.test_ca,runtime.test_cakey
    cacert,cakey=write_identity(tmp_path,"factory-ca",ca,ca_key)
    signer,signerkey=leaf(ca,ca_key)
    signercert,signerpath=write_identity(tmp_path,"factory-signer",signer,signerkey)
    server,serverkey=leaf(ca,ca_key,server=True)
    servercert,serverpath=write_identity(tmp_path,"factory-tls",server,serverkey)
    token=tmp_path/"token.key";token.write_bytes(Fernet.generate_key());token.chmod(0o600)
    nanokey=tmp_path/"nanodep.key";nanokey.write_text("synthetic-not-a-real-credential");nanokey.chmod(0o600)
    config={"identity_ca_file":cacert,"identity_key_file":cakey,
        "profile_signer_file":signercert,"profile_signer_key_file":signerpath,
        "profile_chain_file":cacert,"profile_trust_file":cacert,
        "base_url":"https://localhost:8443","organization":"SYNTHETIC",
        "tenant_topics":{str(fleet[0]):TOPIC},"token_encryption_key_file":str(token),
        "authorization_reference":"SYNTHETIC TEST, NOT APPLE APPROVAL",
        "tls_certificate_file":servercert,"tls_private_key_file":serverpath,
        "ade":{"nanodep_url":"https://nanodep.example.test","nanodep_api_key_file":str(nanokey),
               "tenant_id":fleet[0],"dep_name":"customer","profile_uuid":"P1","apple_root_file":cacert}}
    path=tmp_path/"native-config.json";path.write_text(json.dumps(config));path.chmod(0o600)
    monkeypatch.setenv("KG_NATIVE_MDM_CONFIG",str(path))
    monkeypatch.setenv("KG_DATABASE_URL",str(engine.url))
    # Avoid printing/roundtripping any real credential. Engine is local fixture.
    monkeypatch.setattr("app.native_mdm_config.make_engine",lambda url:engine)
    eng,r,context=factory()
    assert eng is engine and r.topics=={fleet[0]:TOPIC}
    assert context.verify_mode==ssl.CERT_OPTIONAL and context.minimum_version==ssl.TLSVersion.TLSv1_2
    from mdm.nanodep import CurrentAssignmentLookup
    assert isinstance(r.ade_verifier.lookup,CurrentAssignmentLookup)
    assert r.ade_verifier.pins=={}  # Fresh attended guardian decision establishes attempt trust.
