"""DDM serving endpoints (spec Part 10). Wire shapes verified against
KMFDDM ddm/items.go, ddm/token.go, ddm/declaration.go, ddm/status/
status.go and the NanoMDM operations guide -dm flag documentation
(all fetched/cloned 2026-11-16)."""

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
HMAC_KEY = "ddm-secret"


def sig(body: bytes = b""):
    return base64.b64encode(
        hmac.new(HMAC_KEY.encode(), body, hashlib.sha256).digest()).decode()


def ddm_headers(body: bytes = b"", enrollment="ENR-1", key=HMAC_KEY):
    signature = base64.b64encode(
        hmac.new(key.encode(), body, hashlib.sha256).digest()).decode()
    return {"X-Enrollment-ID": enrollment, "X-Hmac-Signature": signature}


def make_client(engine, env_extra=None):
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
    env.update(env_extra or {})
    c = TestClient(create_app(Settings(env), engine=engine))
    r = c.post("/api/auth/login",
               json={"email": "ddm@example.com", "password": PASSWORD},
               headers=HDR)
    assert r.status_code == 200
    return c


@pytest.fixture()
def client(engine):
    return make_client(engine, {"KG_DDM_HMAC_KEY": HMAC_KEY})


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
        h = ddm_headers()
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
        h = ddm_headers()
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
        items = client.get("/api/ddm/declaration-items",
                           headers=ddm_headers()).json()
        assert items["Declarations"]["Configurations"] == []

    def test_unknown_or_missing_enrollment_rejected(self, client):
        # unknown enrollment id, valid HMAC -> 404
        assert client.get("/api/ddm/declaration-items",
                          headers=ddm_headers(enrollment="NOPE")
                          ).status_code == 404
        # known enrollment id, no HMAC -> 401 (id alone is not auth)
        assert client.get("/api/ddm/declaration-items",
                          headers={"X-Enrollment-ID": "ENR-1"}
                          ).status_code == 401
        # known id, wrong key -> 401
        assert client.get("/api/ddm/declaration-items",
                          headers=ddm_headers(key="wrong-key")
                          ).status_code == 401

    def test_fail_closed_without_hmac_key(self, engine):
        """Reproduction guard: before the fix, no KG_DDM_HMAC_KEY meant
        X-Enrollment-ID ALONE served declarations and accepted forged
        status reports. Now every route is 503 when unconfigured."""
        c = make_client(engine)  # no KG_DDM_HMAC_KEY
        assert c.get("/api/ddm/declaration-items",
                     headers={"X-Enrollment-ID": "ENR-1"}).status_code == 503
        assert c.get("/api/ddm/tokens",
                     headers={"X-Enrollment-ID": "ENR-1"}).status_code == 503
        assert c.put("/api/ddm/status", content=b"{}",
                     headers={"X-Enrollment-ID": "ENR-1"}).status_code == 503

    def test_status_report_stored_and_seen(self, client, engine):
        report = {"StatusItems": {"management.declarations": {}}}
        body = json.dumps(report).encode()
        r = client.put("/api/ddm/status", headers=ddm_headers(body),
                       content=body)
        assert r.status_code == 200
        with session_scope(engine) as s:
            rows = s.query(DDMStatusReport).all()
            assert len(rows) == 1
            assert rows[0].enrollment_id == "ENR-1"
            assert rows[0].declaration_states == "{}"
            enr = s.query(MDMEnrollment).filter_by(enrollment_id="ENR-1").one()
            assert enr.last_seen_at is not None
        bad = json.dumps({"x": 1}).encode()
        # unsigned status with a known enrollment id is NOT accepted
        assert client.put("/api/ddm/status", content=bad,
                          headers={"X-Enrollment-ID": "ENR-1"}
                          ).status_code == 401
        badsig = ddm_headers(b"not json")
        assert client.put("/api/ddm/status", headers=badsig,
                          content=b"not json").status_code == 400

    def test_status_declaration_states_extracted_receipt_not_application(
            self, client, engine):
        put_policy(client)
        items = client.get("/api/ddm/declaration-items",
                           headers=ddm_headers()).json()
        cfg = items["Declarations"]["Configurations"][0]
        # a report that only LISTS the declaration, invalid + inactive:
        # receipt is recorded, but nothing here evidences application
        report = {"StatusItems": {"management": {"declarations": {
            "configurations": [{"identifier": cfg["Identifier"],
                                "server-token": cfg["ServerToken"],
                                "active": False, "valid": "unknown"}]}}}}
        body = json.dumps(report).encode()
        r = client.put("/api/ddm/status", headers=ddm_headers(body),
                       content=body)
        assert r.status_code == 200
        with session_scope(engine) as s:
            row = s.query(DDMStatusReport).one()
            states = json.loads(row.declaration_states)
            st = states[cfg["Identifier"]]
            assert st["server_token"] == cfg["ServerToken"]
            assert st["active"] is False and st["valid"] == "unknown"
