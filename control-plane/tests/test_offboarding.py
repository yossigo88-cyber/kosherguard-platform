"""Answer 24 tests: documented, verified offboarding.

Case lifecycle (create -> verify with fresh owner MFA -> attest manual
Apple-side steps -> complete), role gating, cross-tenant isolation,
dispute resolution notes, retention stamping, and the hard rules:
nonpayment never permanently locks a device, and nothing in the case
flow auto-erases a device, auto-releases Apple Business, or issues MDM
commands - while completion DOES perform the real local orchestration
(assignments deactivated, enrollments offboarded, device logs purged).
"""

import os
import sys

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.dirname(__file__))

from datetime import timedelta  # noqa: E402

from app import ddm_ops, security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (Device, DeviceAssignment, FilterDecision,  # noqa: E402
                        IssuedCredential, MDMCommand, MDMEnrollment,
                        OffboardingCase, Policy, Role, Tenant, User,
                        utcnow)
from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_client(engine, email="owner@example.com", tenant_name="fam-a"):
    with session_scope(engine) as s:
        tenant = Tenant(name=tenant_name)
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
    c = TestClient(create_app(Settings(env), engine=engine))
    r = mfa_login(c, json={"email": email, "password": PASSWORD}, headers=HDR)
    assert r.status_code == 200, r.text
    return c


@pytest.fixture()
def client(engine):
    return make_client(engine)


def fresh_code(client, email):
    known = getattr(client.app.state, "_fixture_mfa", {})
    return pyotp.TOTP(known[email]).now()


def mk_device(c, name="phone-1"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


def mk_case(c, kind="cancellation", device_id=None, notes=""):
    body = {"kind": kind, "notes": notes}
    if device_id is not None:
        body["device_id"] = device_id
    r = c.post("/api/offboarding/cases", json=body, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


def verify(c, case_id, email="owner@example.com"):
    return c.post(f"/api/offboarding/cases/{case_id}/verify",
                  json={"totp_code": fresh_code(c, email),
                        "confirm": "verify-offboarding"}, headers=HDR)


def attest(c, case_id, step, email="owner@example.com"):
    return c.post(f"/api/offboarding/cases/{case_id}/attest",
                  json={"step": step, "totp_code": fresh_code(c, email),
                        "confirm": f"attest-{step}"}, headers=HDR)



def complete(c, case_id, email="owner@example.com", **extra):
    """Completion requires fresh MFA + confirmation (same bar as
    verify and the Apple-side attestations)."""
    body = {"totp_code": fresh_code(c, email),
            "confirm": "complete-offboarding"}
    body.update(extra)
    return c.post(f"/api/offboarding/cases/{case_id}/complete",
                  json=body, headers=HDR)



class TestCaseLifecycle:
    def test_create_and_list(self, client):
        case = mk_case(client)
        assert case["status"] == "open"
        listing = client.get("/api/offboarding/cases").json()["cases"]
        assert [c["id"] for c in listing] == [case["id"]]

    def test_create_requires_owner(self, engine, client):
        with session_scope(engine) as s:
            tid = s.query(User).filter_by(
                email="owner@example.com").one().tenant_id
            s.add(User(tenant_id=tid, email="viewer@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.viewer))
        v = TestClient(client.app)
        r = mfa_login(v, json={"email": "viewer@example.com",
                               "password": PASSWORD}, headers=HDR)
        assert r.status_code == 200, r.text
        r = v.post("/api/offboarding/cases",
                   json={"kind": "cancellation"}, headers=HDR)
        assert r.status_code == 403

    def test_transfer_requires_device(self, client):
        r = client.post("/api/offboarding/cases",
                        json={"kind": "transfer"}, headers=HDR)
        assert r.status_code == 400

    def test_cross_tenant_isolation(self, engine, client):
        case = mk_case(client)
        other = make_client(engine, "b@example.com", "fam-b")
        r = other.post(f"/api/offboarding/cases/{case['id']}/cancel",
                       headers=HDR)
        assert r.status_code == 404
        listing = other.get("/api/offboarding/cases").json()["cases"]
        assert listing == []

    def test_verify_requires_fresh_mfa(self, client):
        case = mk_case(client)
        r = client.post(f"/api/offboarding/cases/{case['id']}/verify",
                        json={"totp_code": "000000",
                              "confirm": "verify-offboarding"}, headers=HDR)
        assert r.status_code == 403
        r = verify(client, case["id"])
        assert r.status_code == 200, r.json()
        assert r.json()["status"] == "verified"

    def test_complete_requires_verification(self, client):
        case = mk_case(client)
        r = complete(client, case['id'])
        assert r.status_code == 409

    def test_cancel_flow(self, client):
        case = mk_case(client)
        r = client.post(f"/api/offboarding/cases/{case['id']}/cancel",
                        headers=HDR)
        assert r.status_code == 200
        assert r.json()["status"] == "canceled"
        r = complete(client, case['id'])
        assert r.status_code == 409


class TestCompletion:
    def _transfer_case(self, client):
        dev = mk_device(client)
        case = mk_case(client, "transfer", dev, "sold to cousin")
        assert verify(client, case["id"]).json()["status"] == "verified"
        return case, dev

    def test_transfer_requires_attestations(self, client):
        case, _ = self._transfer_case(client)
        r = complete(client, case['id'])
        assert r.status_code == 409
        assert attest(client, case["id"], "activation_lock").status_code == 200
        r = complete(client, case['id'])
        assert r.status_code == 409
        assert attest(client, case["id"], "abm_release").status_code == 200
        r = complete(client, case['id'])
        assert r.status_code == 200, r.json()
        assert r.json()["status"] == "completed"

    def test_completion_orchestrates_local_state(self, engine, client):
        """Real environment-feasible orchestration: assignments
        deactivated, enrollments offboarded, device filter logs purged,
        retention date stamped. NOT just attestations."""
        case, dev = self._transfer_case(client)
        attest(client, case["id"], "activation_lock")
        attest(client, case["id"], "abm_release")
        with session_scope(engine) as s:
            tenant = s.query(Tenant).filter_by(name="fam-a").one()
            policy = Policy(tenant_id=tenant.id, name="p", engine_doc="{}")
            s.add(policy)
            s.flush()
            s.add(DeviceAssignment(tenant_id=tenant.id, device_id=dev,
                                   policy_id=policy.id, active=True))
            s.add(policy)
            s.flush()
            s.add(DeviceAssignment(tenant_id=tenant.id, device_id=dev,
                                   policy_id=policy.id, active=True))
            s.add(MDMEnrollment(tenant_id=tenant.id, device_id=dev,
                                enrollment_id="pending-x",
                                device_udid="UDID-X", state="enrolled"))
            s.add(FilterDecision(tenant_id=tenant.id, device_id=dev,
                                 source="proxy", domain="x.com",
                                 action="blocked"))
        r = complete(client, case['id'])
        assert r.status_code == 200
        body = r.json()
        assert body["data_retention_until"] is not None
        with session_scope(engine) as s:
            assert s.query(DeviceAssignment).filter_by(
                device_id=dev, active=True).count() == 0
            enr = s.query(MDMEnrollment).filter_by(device_id=dev).one()
            assert enr.state == "offboarded"
            assert s.query(FilterDecision).filter_by(
                device_id=dev).count() == 0
            assert s.get(Device, dev).state == "offboarded"

    def test_dispute_requires_resolution_notes(self, client):
        case = mk_case(client, "dispute")
        assert verify(client, case["id"]).status_code == 200
        r = complete(client, case['id'])
        assert r.status_code == 400
        r = complete(client, case["id"], notes="resolved: ownership confirmed")
        assert r.status_code == 200


    def test_transfer_revokes_issued_credentials(self, engine, client):
        """Runtime access stop is REAL: outstanding scoped device
        credentials are revoked at completion (edge verifiers refuse
        revoked jtis via the revocation feed)."""
        case, dev = self._transfer_case(client)
        with session_scope(engine) as s:
            tenant = s.query(Tenant).filter_by(name="fam-a").one()
            s.add(IssuedCredential(tenant_id=tenant.id, device_id=dev,
                                   jti="jti-transfer-1", scope="dataset",
                                   expires_at=utcnow() + timedelta(hours=1)))
        attest(client, case["id"], "activation_lock")
        attest(client, case["id"], "abm_release")
        r = complete(client, case['id'])
        assert r.status_code == 200
        with session_scope(engine) as s:
            cred = s.query(IssuedCredential).filter_by(
                device_id=dev).one()
            assert cred.revoked_at is not None

    def test_offboarded_enrollment_not_reactivated(self, engine, client):
        """Offboarded enrollments cannot silently reactivate: the
        authenticated DDM path refuses any state outside
        enrolled/active, and new enrollment tickets refuse an
        offboarded device (a fresh authorized enrollment requires an
        explicit guardian/owner action)."""
        case, dev = self._transfer_case(client)
        with session_scope(engine) as s:
            tenant = s.query(Tenant).filter_by(name="fam-a").one()
            s.add(MDMEnrollment(tenant_id=tenant.id, device_id=dev,
                                enrollment_id="ENR-OFF", device_udid="U-OFF",
                                state="enrolled"))
        attest(client, case["id"], "activation_lock")
        attest(client, case["id"], "abm_release")
        r = complete(client, case['id'])
        assert r.status_code == 200
        with session_scope(engine) as s:
            enr = s.query(MDMEnrollment).filter_by(
                enrollment_id="ENR-OFF").one()
            assert enr.state == "offboarded"
            with pytest.raises(ddm_ops.DDMError):
                ddm_ops.ensure_active(s, enr)
        r = client.post(f"/api/mdm/devices/{dev}/enrollment-tickets",
                        json={}, headers=HDR)
        assert r.status_code == 409

    def test_cancellation_with_device_touches_nothing(self, engine, client):
        """Nonpayment must never revoke protection: a cancellation
        naming a device completes with assignments active, enrollment
        untouched, credentials unrevoked, device state unchanged and
        zero MDM commands."""
        dev = mk_device(client)
        with session_scope(engine) as s:
            tenant = s.query(Tenant).filter_by(name="fam-a").one()
            policy = Policy(tenant_id=tenant.id, name="p2",
                            engine_doc="{}")
            s.add(policy)
            s.flush()
            s.add(DeviceAssignment(tenant_id=tenant.id, device_id=dev,
                                   policy_id=policy.id, active=True))
            s.add(MDMEnrollment(tenant_id=tenant.id, device_id=dev,
                                enrollment_id="ENR-KEEP", device_udid="U-K",
                                state="enrolled"))
            s.add(IssuedCredential(tenant_id=tenant.id, device_id=dev,
                                   jti="jti-keep-1", scope="proxy",
                                   expires_at=utcnow() + timedelta(hours=1)))
        case = mk_case(client, "cancellation", dev, "nonpayment")
        assert verify(client, case["id"]).status_code == 200
        r = complete(client, case['id'])
        assert r.status_code == 200
        assert r.json()["data_retention_until"] is not None
        with session_scope(engine) as s:
            assert s.query(DeviceAssignment).filter_by(
                device_id=dev, active=True).count() == 1
            assert s.query(MDMEnrollment).filter_by(
                device_id=dev).one().state == "enrolled"
            assert s.query(IssuedCredential).filter_by(
                device_id=dev).one().revoked_at is None
            assert s.get(Device, dev).state == "active"
            assert s.query(MDMCommand).count() == 0

    def test_cancellation_completes_without_device_effects(self, engine,
                                                           client):
        """Nonpayment cancellation: completes after verification, sets
        retention, and never locks/erases/releases the device - no MDM
        command is ever issued by the case flow."""
        case = mk_case(client, "cancellation", notes="nonpayment")
        assert verify(client, case["id"]).status_code == 200
        r = complete(client, case['id'])
        assert r.status_code == 200, r.json()
        assert r.json()["status"] == "completed"
        assert r.json()["data_retention_until"] is not None
        with session_scope(engine) as s:
            assert s.query(MDMCommand).count() == 0
            assert s.query(Device).filter_by(state="offboarded").count() == 0
