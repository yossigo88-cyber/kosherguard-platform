"""Answer 28 tests: enrollment tickets and device identity certificates.

Covers rule 14: invalid, expired, replayed and revoked tickets are
rejected; tickets bind one tenant+device; a serial number alone is not
proof - the single-use token is the redemption authentication, and a
presented identity certificate must parse, be unexpired, bind the
device UDID, and chain-verify when a CA is configured. Concurrency:
simultaneous redeems of one ticket let exactly one succeed.
"""

import os
import sys
import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (EnrollmentTicket, MDMEnrollment, Role, Tenant,  # noqa: E402
                        User, utcnow)
from mfa_support import mfa_login  # noqa: E402

cryptography = pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
UDID = "00008030-001234567890ABCD"


def make_client(engine, email="owner@example.com", tenant_name="fam-a",
                ca_file=None):
    with session_scope(engine) as s:
        tenant = Tenant(name=tenant_name)
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
    if ca_file:
        env["KG_DEVICE_IDENTITY_CA_FILE"] = ca_file
    c = TestClient(create_app(Settings(env), engine=engine))
    r = mfa_login(c, json={"email": email, "password": PASSWORD}, headers=HDR)
    assert r.status_code == 200, r.text
    return c


@pytest.fixture()
def client(engine):
    return make_client(engine)


def mk_device(c, name="phone-1"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


def issue(c, device_id, **kw):
    r = c.post(f"/api/mdm/devices/{device_id}/enrollment-tickets",
               json=kw, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ca(tmp_path):
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KG Test CA")])
    now = utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256()))
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, str(ca_file)


def make_cert(cn, ca_key, ca_cert, expired=False, self_signed=False):
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = utcnow()
    if expired:
        not_before = now - timedelta(days=10)
        not_after = now - timedelta(days=1)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=30)
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(subject if self_signed else ca_cert.subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before).not_valid_after(not_after)
               .add_extension(x509.SubjectAlternativeName(
                   [x509.DNSName(cn)]), critical=False))
    signer = key if self_signed else ca_key
    cert = builder.sign(signer, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class TestTicketIssue:
    def test_issue_and_list(self, client):
        dev = mk_device(client)
        body = issue(client, dev, expires_minutes=30)
        assert body["ticket"]
        assert body["device_id"] == dev
        listing = client.get("/api/mdm/enrollment-tickets").json()["tickets"]
        assert len(listing) == 1
        assert listing[0]["id"] == body["id"]
        assert listing[0]["used_at"] is None
        # The raw token is never in the listing, only metadata.
        assert "ticket" not in listing[0]

    def test_issue_requires_devices_capability(self, engine, client):
        with session_scope(engine) as s:
            tenant_id = s.query(User).filter_by(
                email="owner@example.com").one().tenant_id
            s.add(User(tenant_id=tenant_id, email="viewer@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.viewer))
        v = TestClient(client.app)
        r = mfa_login(v, json={"email": "viewer@example.com",
                               "password": PASSWORD}, headers=HDR)
        assert r.status_code == 200, r.text
        dev = mk_device(client)
        r = v.post(f"/api/mdm/devices/{dev}/enrollment-tickets",
                   json={}, headers=HDR)
        assert r.status_code == 403

    def test_issue_other_tenants_device_404(self, engine, client):
        other = make_client(engine, "other@example.com", "fam-b")
        dev_b = mk_device(other, "other-phone")
        r = client.post(f"/api/mdm/devices/{dev_b}/enrollment-tickets",
                        json={}, headers=HDR)
        assert r.status_code == 404


class TestTicketRedeem:
    def test_redeem_success_and_replay_rejected(self, engine, client):
        dev = mk_device(client)
        body = issue(client, dev)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": body["ticket"], "device_udid": UDID})
        assert r.status_code == 200, r.json()
        assert r.json()["state"] == "pending"
        with session_scope(engine) as s:
            enr = s.query(MDMEnrollment).filter_by(device_udid=UDID).one()
            assert enr.enrollment_ticket_id == body["id"]
            ticket = s.get(EnrollmentTicket, body["id"])
            assert ticket.used_at is not None
        replay = client.post("/api/mdm/enroll",
                             json={"ticket": body["ticket"],
                                   "device_udid": UDID})
        assert replay.status_code == 409

    def test_redeem_invalid_ticket_403(self, client):
        r = client.post("/api/mdm/enroll",
                        json={"ticket": "not-a-real-token",
                              "device_udid": UDID})
        assert r.status_code == 403

    def test_redeem_expired_410(self, engine, client):
        dev = mk_device(client)
        body = issue(client, dev, expires_minutes=5)
        with session_scope(engine) as s:
            ticket = s.get(EnrollmentTicket, body["id"])
            ticket.expires_at = utcnow() - timedelta(minutes=1)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": body["ticket"], "device_udid": UDID})
        assert r.status_code == 410

    def test_redeem_revoked_410(self, client):
        dev = mk_device(client)
        body = issue(client, dev)
        r = client.delete(f"/api/mdm/enrollment-tickets/{body['id']}",
                          headers=HDR)
        assert r.status_code == 200
        r = client.post("/api/mdm/enroll",
                        json={"ticket": body["ticket"], "device_udid": UDID})
        assert r.status_code == 410

    def test_concurrent_redeem_single_use(self, engine, client):
        """Real disposable-PostgreSQL concurrency: two redeems of the
        SAME ticket at once. The FOR UPDATE lock + used_at guard must
        let exactly one succeed; the other gets 409."""
        dev = mk_device(client)
        body = issue(client, dev)
        clients = [TestClient(client.app), TestClient(client.app)]
        barrier = threading.Barrier(2)
        results = {}

        def redeem(i):
            barrier.wait(timeout=10)
            resp = clients[i].post("/api/mdm/enroll",
                                   json={"ticket": body["ticket"],
                                         "device_udid": UDID})
            results[i] = resp.status_code

        threads = [threading.Thread(target=redeem, args=(i,))
                   for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            count = s.query(MDMEnrollment).filter_by(
                device_udid=UDID).count()
            assert count == 1

    def test_udid_conflict_with_existing_enrollment(self, engine, client):
        dev = mk_device(client)
        first = issue(client, dev)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": first["ticket"],
                              "device_udid": UDID})
        assert r.status_code == 200
        second = issue(client, dev)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": second["ticket"],
                              "device_udid": "00008030-DIFFERENTUDID"})
        assert r.status_code == 409
        # Same UDID re-binds cleanly (e.g. re-issue after a failed setup).
        third = issue(client, dev)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": third["ticket"],
                              "device_udid": UDID})
        assert r.status_code == 200


class TestCheckinBinding:
    def test_redeem_does_not_activate_or_verify(self, engine, client):
        """A redeemed ticket binds a UDID to a PENDING record only -
        a self-asserted UDID plus ticket is not device proof. The
        enrollment stays pending until an authenticated MDM check-in,
        and supervision verification is still refused on it."""
        from app import mdm_ops
        dev = mk_device(client)
        body = issue(client, dev)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": body["ticket"],
                              "device_udid": UDID})
        assert r.status_code == 200
        assert r.json()["state"] == "pending"
        with session_scope(engine) as s:
            enr = s.query(MDMEnrollment).filter_by(device_udid=UDID).one()
            assert enr.state == "pending"
            with pytest.raises(mdm_ops.MDMError) as exc:
                mdm_ops.mark_supervision_verified(
                    s, enr.tenant_id, enr.id, True)
            assert exc.value.status == 409

    def test_cross_tenant_udid_collision_refused_at_checkin(self, engine,
                                                            client):
        """Two tenants redeeming tickets with the same UDID: the
        authenticated check-in binding refuses the ambiguous match
        rather than mis-binding a device to the wrong tenant."""
        from app import ddm_ops
        other = make_client(engine, "b2@example.com", "fam-b2")
        d1 = mk_device(client)
        d2 = mk_device(other, "b2-phone")
        t1 = issue(client, d1)
        t2 = issue(other, d2)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": t1["ticket"], "device_udid": UDID})
        assert r.status_code == 200
        r = other.post("/api/mdm/enroll",
                       json={"ticket": t2["ticket"], "device_udid": UDID})
        assert r.status_code == 200
        with session_scope(engine) as s:
            with pytest.raises(ddm_ops.DDMError) as exc:
                ddm_ops.resolve_or_bind(s, UDID)
            assert exc.value.status == 409


class TestIdentityCertificates:
    def test_ca_signed_cert_verified(self, engine, tmp_path):
        ca_key, ca_cert, ca_file = make_ca(tmp_path)
        c = make_client(engine, "ca@example.com", "fam-ca", ca_file=ca_file)
        dev = mk_device(c)
        body = issue(c, dev)
        pem = make_cert(UDID, ca_key, ca_cert)
        r = c.post("/api/mdm/enroll",
                   json={"ticket": body["ticket"], "device_udid": UDID,
                         "certificate_pem": pem})
        assert r.status_code == 200, r.json()
        assert r.json()["identity_cert_status"] == "verified"

    def test_cert_without_ca_recorded_chain_unverified(self, engine, tmp_path):
        ca_key, ca_cert, _ = make_ca(tmp_path)
        c = make_client(engine, "noca@example.com", "fam-noca")
        dev = mk_device(c)
        body = issue(c, dev)
        pem = make_cert(UDID, ca_key, ca_cert)
        r = c.post("/api/mdm/enroll",
                   json={"ticket": body["ticket"], "device_udid": UDID,
                         "certificate_pem": pem})
        assert r.status_code == 200, r.json()
        assert r.json()["identity_cert_status"] == "chain_unverified"

    def test_expired_cert_rejected(self, engine, tmp_path, client):
        ca_key, ca_cert, _ = make_ca(tmp_path)
        dev = mk_device(client)
        body = issue(client, dev)
        pem = make_cert(UDID, ca_key, ca_cert, expired=True)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": body["ticket"], "device_udid": UDID,
                              "certificate_pem": pem})
        assert r.status_code == 403

    def test_cert_bound_to_other_device_rejected(self, engine, tmp_path,
                                                 client):
        ca_key, ca_cert, _ = make_ca(tmp_path)
        dev = mk_device(client)
        body = issue(client, dev)
        pem = make_cert("00008030-OTHERDEVICEUDID", ca_key, ca_cert)
        r = client.post("/api/mdm/enroll",
                        json={"ticket": body["ticket"], "device_udid": UDID,
                              "certificate_pem": pem})
        assert r.status_code == 403

    def test_self_signed_cert_rejected_when_ca_configured(self, engine,
                                                          tmp_path):
        ca_key, ca_cert, ca_file = make_ca(tmp_path)
        c = make_client(engine, "ss@example.com", "fam-ss", ca_file=ca_file)
        dev = mk_device(c)
        body = issue(c, dev)
        pem = make_cert(UDID, None, None, self_signed=True)
        r = c.post("/api/mdm/enroll",
                   json={"ticket": body["ticket"], "device_udid": UDID,
                         "certificate_pem": pem})
        assert r.status_code == 403
