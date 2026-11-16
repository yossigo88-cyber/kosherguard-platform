"""Answer 26 tests: restore/re-enrollment readiness and the ABM
assignment attestation."""

import os
import sys
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (DeviceAssignment, IssuedCredential,  # noqa: E402
                        MDMEnrollment, Policy, Role, Tenant, User, utcnow)
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


def mk_device(c, name="phone-1"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


class TestRestore:
    def test_readiness_requires_all_checks(self, engine, client):
        dev = mk_device(client)
        body = client.get(
            f"/api/mdm/devices/{dev}/restore-readiness").json()
        assert body["setup_release_ready"] is False
        assert all(v is False for v in body["checks"].values())
        with session_scope(engine) as s:
            tenant = s.query(Tenant).filter_by(name="fam-a").one()
            policy = Policy(tenant_id=tenant.id, name="p",
                            engine_doc="{}")
            s.add(policy)
            s.flush()
            s.add(DeviceAssignment(tenant_id=tenant.id, device_id=dev,
                                   policy_id=policy.id, active=True))
            s.add(MDMEnrollment(tenant_id=tenant.id, device_id=dev,
                                enrollment_id="ENR-1", device_udid="U1",
                                state="enrolled"))
            s.add(IssuedCredential(tenant_id=tenant.id, device_id=dev,
                                   jti="jti-r1", scope="dataset",
                                   expires_at=utcnow() + timedelta(hours=1)))
        body = client.get(
            f"/api/mdm/devices/{dev}/restore-readiness").json()
        assert body["setup_release_ready"] is False
        assert body["checks"]["device_reenrolled"] is True
        assert body["checks"]["baseline_assignment_active"] is True
        assert body["checks"]["filtering_credential_issued"] is True
        assert body["checks"]["abm_assignment_attested"] is False
        # Attest the ABM assignment, then everything is green.
        r = client.post(f"/api/mdm/devices/{dev}/restore-attest",
                        json={"confirm": "attest-abm-assignment"},
                        headers=HDR)
        assert r.status_code == 200, r.json()
        body = client.get(
            f"/api/mdm/devices/{dev}/restore-readiness").json()
        assert body["setup_release_ready"] is True

    def test_attest_requires_confirmation(self, client):
        dev = mk_device(client)
        r = client.post(f"/api/mdm/devices/{dev}/restore-attest",
                        json={"confirm": "wrong"}, headers=HDR)
        assert r.status_code == 400

    def test_cross_tenant_readiness_404(self, engine, client):
        dev = mk_device(client)
        other = make_client(engine, "b@example.com", "fam-b")
        assert other.get(
            f"/api/mdm/devices/{dev}/restore-readiness").status_code == 404
