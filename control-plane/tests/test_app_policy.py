"""Application management API (spec Part 10: Applications).

Covers the stored per-device allow/block policy and the app command
routing. Delivery is exercised with the simulated adapter only where
the queueing contract matters; on-device behavior of the generated
payloads is BUILT-UNVERIFIED (see mdm/app_management.py).
"""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_client(engine, email="apps@example.com",
                tenant_name="family-apps"):
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
    r = mfa_login(c, json={'email': email, 'password': PASSWORD}, headers=HDR)
    assert r.status_code == 200
    return c


@pytest.fixture()
def client(engine):
    return make_client(engine)


def mk_device(c, name="phone-apps"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


def mk_enrollment(c, device_id):
    r = c.post("/api/mdm/enrollments",
               json={"device_id": device_id,
                     "supervision_requested": True}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


class TestAppPolicy:
    def test_default_policy_when_unsaved(self, client):
        dev = mk_device(client)
        r = client.get(f"/api/devices/{dev}/app-policy")
        assert r.status_code == 200
        assert r.json() == {"mode": "blocklist", "bundle_ids": [],
                            "saved": False}

    def test_put_get_roundtrip(self, client):
        dev = mk_device(client)
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "allowlist",
                             "bundle_ids": ["com.good.one", "com.good.two"]},
                       headers=HDR)
        assert r.status_code == 200, r.json()
        got = client.get(f"/api/devices/{dev}/app-policy").json()
        assert got["mode"] == "allowlist"
        assert got["bundle_ids"] == ["com.good.one", "com.good.two"]
        assert got["saved"] is True

    def test_put_rejects_bad_mode_and_bad_bundle_id(self, client):
        dev = mk_device(client)
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "somelist", "bundle_ids": []},
                       headers=HDR)
        assert r.status_code == 400
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "blocklist",
                             "bundle_ids": ["not a bundle id"]},
                       headers=HDR)
        assert r.status_code == 400

    def test_put_rejects_unknown_device(self, client):
        r = client.put("/api/devices/99999/app-policy",
                       json={"mode": "blocklist", "bundle_ids": []},
                       headers=HDR)
        assert r.status_code == 404

    def test_policy_is_tenant_scoped(self, client, engine):
        dev = mk_device(client)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "allowlist", "bundle_ids": ["com.a.b"]},
                   headers=HDR)
        c2 = make_client(engine, email="other@example.com",
                         tenant_name="family-other-apps")
        r = c2.get(f"/api/devices/{dev}/app-policy")
        assert r.status_code == 404

    def test_update_writes_audit_event(self, client, engine):
        dev = mk_device(client)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "blocklist", "bundle_ids": ["com.bad.app"]},
                   headers=HDR)
        r = client.get("/api/audit-logs")
        actions = [e["action"] for e in r.json()["events"]]
        assert "app_policy.update" in actions


class TestAppPolicyApply:
    def test_apply_without_saved_policy_409(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 409

    def test_apply_without_enrollment_409(self, client):
        dev = mk_device(client)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "blocklist", "bundle_ids": ["com.bad.app"]},
                   headers=HDR)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 409
        assert "enroll" in r.json()["error"].lower()

    def test_apply_queues_install_profile_with_payload(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "allowlist",
                         "bundle_ids": ["com.good.one"]}, headers=HDR)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["command"] == "InstallProfile"
        assert r.json()["status"] == "queued"
        payload = r.json()["payload"]["profile"]
        assert payload["PayloadType"] == "Configuration"
        content = payload["PayloadContent"][0]
        assert content["PayloadType"] == "com.apple.applicationaccess"
        assert content["whiteListedAppBundleIDs"] == ["com.good.one"]


class TestAppCommands:
    def test_install_queues_with_store_id(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["command"] == "InstallApplication"
        assert r.json()["payload"]["ITunesStoreID"] == 284815942

    def test_install_with_managed_configuration(self, client):
        """The KosherGuard app's initial managed configuration rides the
        InstallApplication command (Apple contract: application.install.yaml
        Configuration dict). deviceID comes from the server-side device
        record; controlPlaneBaseURL is operator-supplied, never invented."""
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942,
                              "configuration": {
                                  "controlPlaneBaseURL":
                                      "https://cp.example.com"}},
                        headers=HDR)
        assert r.status_code == 200, r.json()
        cfg = r.json()["payload"]["Configuration"]
        assert cfg["controlPlaneBaseURL"] == "https://cp.example.com"
        assert cfg["deviceID"] == dev  # filled from the device record

    def test_install_without_configuration_has_no_key(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert "Configuration" not in r.json()["payload"]

    def test_install_rejects_bad_configuration(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942,
                              "configuration": "not-a-dict"}, headers=HDR)
        assert r.status_code in (400, 422)

    def test_install_requires_store_id(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "bundle_id": "com.example.app"},
                        headers=HDR)
        assert r.status_code == 400

    def test_remove_validates_bundle_id(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "remove",
                              "bundle_id": "com.example.app"},
                        headers=HDR)
        assert r.status_code == 200
        assert r.json()["command"] == "RemoveApplication"
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "remove", "bundle_id": "junk"},
                        headers=HDR)
        assert r.status_code == 400

    def test_list_and_managed_list(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "list"}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["command"] == "InstalledApplicationList"
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "managed-list"}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["command"] == "ManagedApplicationList"

    def test_unknown_action_400(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "wipe"}, headers=HDR)
        assert r.status_code == 400

    def test_commands_require_enrollment(self, client):
        dev = mk_device(client)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "list"}, headers=HDR)
        assert r.status_code == 409

    def test_signed_out_rejected(self, engine):
        env = {"KG_DATABASE_URL": "postgresql://placeholder",
               "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
        c = TestClient(create_app(Settings(env), engine=engine))
        assert c.get("/api/devices/1/app-policy").status_code == 401
        assert c.post("/api/devices/1/app-commands",
                      json={"action": "list"},
                      headers=HDR).status_code == 401

from mfa_support import mfa_login
