"""DDM serving endpoints (spec Part 10). Wire shapes verified against
KMFDDM ddm/items.go, ddm/token.go, ddm/declaration.go and the NanoMDM
operations guide -dm flag documentation (both fetched 2026-11-16)."""

import base64
import hashlib
import hmac
import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (DDMStatusReport, Device, MDMEnrollment,  # noqa: E402
                        Role, Tenant, User)

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


@pytest.fixture()
def client(engine, extra_env=None):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-ddm")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="ddm@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        s.add(Device(tenant_id=tenant.id, name="kid-phone"))
        s.flush()
        dev = s.query(Device).filter_by(tenant_id=tenant.id).one()
        s.add(MDMEnrollment(tenant_id=tenant.id, device_id=dev.id,
                            enrollment_id="ENR-1", state="enrolled"))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
    c = TestClient(create_app(Settings(env), engine=engine))
    r = c.post("/api/auth/login",
               json={"email": "ddm@example.com", "password": PASSWORD},
               headers=HDR)
    assert r.status_code == 200
    return c


def put_policy(c):
    r = c.get("/api/devices")
    dev = r.json()["devices"][0]["id"]
    r = c.put(f"/api/devices/{dev}/app-policy", headers=HDR,
              json={"mode": "blocklist", "bundle_ids": ["com.bad.app"]})
    assert r.status_code == 200, r.json()
    return dev


class TestDDMServing:
    def test_full_sync_flow(self, client):
        put_policy(client)
        h = {"X-Enrollment-ID": "ENR-1"}
        items = client.get("/api/ddm/declaration-items", headers=h).json()
        configs = items["Declarations"]["Configurations"]
        assert len(configs) == 1
        assert configs[0]["Identifier"].startswith("com.kosherguard.appsettings.")
        assert items["Declarations"]["Activations"] == []
        tok = client.get("/api/ddm/tokens", headers=h).json()
        assert (tok["SyncTokens"]["DeclarationsToken"]
                == items["DeclarationsToken"])
        decl = client.get(
            f"/api/ddm/declaration/configuration/{configs[0]['Identifier']}",
            headers=h).json()
        assert decl["Type"] == "com.apple.configuration.app.settings"
        assert decl["ServerToken"] == configs[0]["ServerToken"]
        assert decl["Payload"]["Allowed"]["DeniedApps"] == [
            {"AppIdentifier": "com.bad.app"}]

    def test_token_changes_when_policy_changes(self, client):
        put_policy(client)
        h = {"X-Enrollment-ID": "ENR-1"}
        first = client.get("/api/ddm/declaration-items", headers=h).json()
        dev = put_policy(client)
        r = client.put(f"/api/devices/{dev}/app-policy", headers=HDR,
                       json={"mode": "allowlist",
                             "bundle_ids": ["com.good.app"]})
        assert r.status_code == 200, r.json()
        second = client.get("/api/ddm/declaration-items", headers=h).json()
        assert (first["DeclarationsToken"] != second["DeclarationsToken"])
        assert (first["Declarations"]["Configurations"][0]["Identifier"]
                != second["Declarations"]["Configurations"][0]["Identifier"])

    def test_no_policy_empty_configurations(self, client):
        h = {"X-Enrollment-ID": "ENR-1"}
        items = client.get("/api/ddm/declaration-items", headers=h).json()
        assert items["Declarations"]["Configurations"] == []

    def test_unknown_or_missing_enrollment_rejected(self, client):
        assert client.get("/api/ddm/declaration-items").status_code == 400
        assert client.get("/api/ddm/declaration-items",
                          headers={"X-Enrollment-ID": "NOPE"}).status_code == 404

    def test_status_report_stored_and_seen(self, client, engine):
        h = {"X-Enrollment-ID": "ENR-1"}
        report = {"StatusItems": {"management.declarations": {}}}
        r = client.put("/api/ddm/status", headers=h, content=json.dumps(report))
        assert r.status_code == 200
        with session_scope(engine) as s:
            rows = s.query(DDMStatusReport).all()
            assert len(rows) == 1
            assert rows[0].enrollment_id == "ENR-1"
            enr = s.query(MDMEnrollment).filter_by(enrollment_id="ENR-1").one()
            assert enr.last_seen_at is not None
        assert client.put("/api/ddm/status", headers=h,
                          content=b"not json").status_code == 400

    def test_hmac_enforced_when_configured(self, client, engine):
        env = {"KG_DATABASE_URL": "postgresql://placeholder",
               "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test",
               "KG_DDM_HMAC_KEY": "ddm-secret"}
        c = TestClient(create_app(Settings(env), engine=engine))
        # no signature -> rejected
        assert c.get("/api/ddm/tokens",
                     headers={"X-Enrollment-ID": "ENR-1"}).status_code == 401
        body = json.dumps({"StatusItems": {}}).encode()
        sig = base64.b64encode(
            hmac.new(b"ddm-secret", body, hashlib.sha256).digest()).decode()
        r = c.put("/api/ddm/status", content=body,
                  headers={"X-Enrollment-ID": "ENR-1",
                           "X-Hmac-Signature": sig})
        assert r.status_code == 200
