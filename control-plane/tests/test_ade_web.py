"""Attended ADE is a same-browser fresh guardian decision, not CMS bearer auth."""
import base64
import plistlib
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import ade_web, native_mdm as n, security
from app.config import Settings
from app.db import session_scope
from app.main import create_app
from app.models import User,Role,AuthSession,MDMWebActivation,MDMProvision,utcnow
from mdm.ade_identity import ADEIdentityVerifier
from mdm.identity import ProfileSigner,verify_signed_profile
from mdm.tests.pki_fixtures import leaf
from test_native_mdm import runtime,fleet,UDID,TOPIC
from mfa_support import mfa_login

HDR={"X-KosherGuard-Request":"1"}
PASSWORD="a long enough password"


@pytest.fixture
def web(engine,runtime,fleet):
    machine,mkey=leaf(runtime.test_ca,runtime.test_cakey)
    envelope=ProfileSigner(machine,mkey,[runtime.test_ca]).sign(plistlib.dumps({"SERIAL":"S1","UDID":UDID}))
    assignments={"S1":{"assigned":True,"udid":UDID}}
    runtime.ade_verifier=ADEIdentityVerifier(apple_root_file=runtime.signer_trust_file,
        assigned_device_lookup=lambda t,s:assignments.get(s) if t==fleet[0] else None,signer_pins={})
    with session_scope(engine) as s:
        user=User(tenant_id=fleet[0],email="ade@example.test",password_hash=security.hash_password(PASSWORD),role=Role.owner)
        s.add(user);s.flush();uid=user.id
        ade_web.approve_inventory(s,tenant_id=fleet[0],device_id=fleet[2][0],serial="S1",udid=UDID,actor_user_id=uid)
    settings=Settings({"KG_DATABASE_URL":"postgresql://unused","KG_PUBLICATIONS_ROOT":"/tmp/ade-web"})
    app=create_app(settings,engine=engine,native_mdm_runtime=runtime)
    client=TestClient(app)
    return client,envelope,assignments,uid,settings


def start(c,envelope):
    r=c.get("/ade/enroll",headers={"x-apple-aspen-deviceinfo":base64.b64encode(envelope).decode()})
    assert r.status_code==200,r.text
    assert "no-store" in r.headers["cache-control"]
    assert r.headers["referrer-policy"]=="no-referrer"
    assert len(c.cookies.get("kg_ade_ceremony"))<100
    return r


def login(c):
    r=mfa_login(c,json={"email":"ade@example.test","password":PASSWORD},headers=HDR)
    assert r.status_code==200,r.text
    return r


def test_fresh_guardian_session_only_and_same_browser_private_delivery(engine,runtime,fleet,web):
    c,envelope,assignments,uid,settings=web
    login(c)  # Existing login BEFORE ceremony must not authorize activation.
    start(c,envelope)
    assert c.get("/api/mdm/ade/ceremony").status_code==403
    login(c)
    info=c.get("/api/mdm/ade/ceremony")
    assert info.status_code==200 and info.json()["device_id"]==fleet[2][0]
    assert c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][0]}).status_code==403
    r=c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][0]},headers=HDR)
    assert r.status_code==200,r.text
    path=r.json()["profile_path"]
    # Captured path/envelope alone does not yield server-issued device key.
    other=TestClient(c.app)
    assert other.get(path).status_code==401
    # Different fresh session even same user + copied ceremony is rejected.
    other.cookies.set("kg_ade_ceremony",c.cookies.get("kg_ade_ceremony"))
    other.app.state._fixture_mfa=c.app.state._fixture_mfa
    login(other)
    assert other.get(path).status_code==409
    profile=c.get(path)
    assert profile.status_code==200,profile.text
    assert profile.headers["content-type"]=="application/x-apple-aspen-config"
    raw=verify_signed_profile(profile.content,runtime.signer_trust_file)
    assert "PayloadRemovalDisallowed" not in plistlib.loads(raw)
    assert c.get(path).status_code in {409,410}
    with session_scope(engine) as s:
        attempt=s.scalar(select(MDMWebActivation))
        assert attempt.used_at and attempt.encrypted_attempt=="{}"
        assert s.scalar(select(MDMProvision)).stage=="profile_served"


def test_reusable_attended_endpoint_requires_new_login_and_explicit_restart(engine,runtime,fleet,web):
    c,envelope,assignments,uid,settings=web
    start(c,envelope);login(c)
    first=c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][0]},headers=HDR)
    assert first.status_code==200
    assert c.get(first.json()["profile_path"]).status_code==200
    # Same envelope can be inventory input again, but cannot deliver key on
    # its own. New guardian approval/session is required on every recovery.
    start(c,envelope)
    assert c.get("/api/mdm/ade/ceremony").status_code==403
    login(c)
    assert c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][0]},headers=HDR).status_code==409
    second=c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][0],"restart":True},headers=HDR)
    assert second.status_code==200,second.text
    assert c.get(second.json()["profile_path"]).status_code==200
    with session_scope(engine) as s:
        provisions=list(s.scalars(select(MDMProvision).order_by(MDMProvision.id)))
        assert len(provisions)==2 and provisions[0].revoked_at and not provisions[1].revoked_at


def test_assignment_revocation_between_approval_and_delivery(engine,runtime,fleet,web):
    c,envelope,assignments,uid,settings=web
    start(c,envelope);login(c)
    r=c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][0]},headers=HDR)
    assert r.status_code==200
    assignments["S1"]["assigned"]=False
    assert c.get(r.json()["profile_path"]).status_code==409
    with session_scope(engine) as s:
        assert s.scalar(select(MDMProvision)).cert_der is None
        assert s.scalar(select(MDMWebActivation)).used_at is None


def test_invalid_cms_and_wrong_tenant_inventory_no_key_issuance(engine,runtime,fleet,web):
    c,envelope,assignments,uid,settings=web
    assert c.get("/ade/enroll").status_code==403
    assert c.get("/ade/enroll",headers={"x-apple-aspen-deviceinfo":base64.b64encode(b"invalid").decode()}).status_code==403
    start(c,envelope);login(c)
    r=c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][2]},headers=HDR)
    assert r.status_code==403
    assert c.post(f"/api/mdm/devices/{fleet[2][0]}/native-enrollment",json={"udid":UDID,"serial":"S1","mode":"ade"},headers=HDR).status_code==409
    with session_scope(engine) as s:
        assert s.scalar(select(MDMProvision)) is None


def test_inventory_correction_is_guarded_and_never_rewrites_live_identity(engine,runtime,fleet,web):
    import pyotp
    c,envelope,assignments,uid,settings=web
    login(c)
    secret=c.app.state._fixture_mfa["ade@example.test"]
    body={"serial":"CORRECTED","udid":"new-device-0001","totp_code":pyotp.TOTP(secret).now(),"confirm":"correct-device-inventory"}
    path=f"/api/mdm/devices/{fleet[2][0]}/apple-inventory"
    assert c.patch(path,json=body).status_code==403
    assert c.patch(path,json={**body,"confirm":"wrong"},headers=HDR).status_code==400
    assert c.patch(path,json=body,headers=HDR).status_code==200
    assert c.patch(f"/api/mdm/devices/{fleet[2][2]}/apple-inventory",json=body,headers=HDR).status_code==404
    # Restore inventory for the actual CMS and start a pending enrollment.
    assert c.patch(path,json={**body,"serial":"S1","udid":UDID},headers=HDR).status_code==200
    start(c,envelope);login(c)
    assert c.post("/api/mdm/ade/authorize",json={"device_id":fleet[2][0]},headers=HDR).status_code==200
    assert c.patch(path,json=body,headers=HDR).status_code==409


def test_local_inventory_release_requires_offboarded_device_and_is_not_apple_release(engine,runtime,fleet,web):
    c,envelope,assignments,uid,settings=web
    with session_scope(engine) as s:
        with pytest.raises(n.TransportError):ade_web.release_inventory(s,tenant_id=fleet[0],device_id=fleet[2][0],actor_user_id=uid)
        with pytest.raises(n.TransportError):ade_web.release_inventory(s,tenant_id=fleet[1],device_id=fleet[2][0],actor_user_id=uid)
    with session_scope(engine) as s:
        from app.models import Device,MDMAppleInventory
        s.get(Device,fleet[2][0]).state="offboarded"
    with session_scope(engine) as s:
        ade_web.release_inventory(s,tenant_id=fleet[0],device_id=fleet[2][0],actor_user_id=uid)
        assert s.scalar(select(MDMAppleInventory)) is None
