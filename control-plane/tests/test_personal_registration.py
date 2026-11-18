"""Personal-lane device self-registration and native-client discovery.

POST /api/devices/personal-registration is how an unsupervised iPhone
(no MDM) gets its device record after the guardian signs in. The
security contract tested here:

- Idempotency ownership: the same registration key returns the SAME
  device row (created=false) and never a duplicate, even with a
  different requested name; the server record stays authoritative.
- Tenant isolation: a key or name from another tenant is invisible;
  the same key in two tenants yields two independent rows.
- Revocation: an offboarded (inactive) device is returned in its
  inactive state and is NOT silently reactivated by re-registration.
- Registration-key secrecy: the key never appears in any response
  body, the device list or audit-log details.
- Validation: malformed keys/names are rejected before any write.

GET /api/client-config reports the deployment's supporting-service
URLs straight from server configuration, null when undeployed; URL
settings are validated at startup (https only, no credentials/query)
and the PIR pair is jointly optional.
"""

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import ConfigError, Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Device, Role, Tenant, User  # noqa: E402

from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
KEY = "kg-0123456789abcdef0123456789abcdef"


def _settings(tmp_path, **extra):
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": str(tmp_path),
           # Needed so the cross-tenant mint probe reaches the device
           # ownership check instead of the 503 issuance-not-configured.
           "KG_DEVICE_TOKEN_KEY": "test-signing-key"}
    env.update(extra)
    return Settings(env)


@pytest.fixture()
def rig(engine, tmp_path):
    """Two tenants, each with an owner; tenant A also has a viewer."""
    with session_scope(engine) as s:
        ta = Tenant(name="family-a")
        tb = Tenant(name="family-b")
        s.add_all([ta, tb])
        s.flush()
        s.add(User(tenant_id=ta.id, email="a@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        s.add(User(tenant_id=ta.id, email="viewer-a@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.viewer))
        s.add(User(tenant_id=tb.id, email="b@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        ids = (ta.id, tb.id)
    app = create_app(_settings(tmp_path), engine=engine)
    return app, ids


def login(app, email):
    c = TestClient(app)
    r = mfa_login(c, json={"email": email, "password": PASSWORD},
                  headers=HDR)
    assert r.status_code == 200
    return c


def register(c, name="Yossi iPhone", key=KEY):
    return c.post("/api/devices/personal-registration",
                  json={"name": name, "registration_key": key},
                  headers=HDR)


class TestPersonalRegistration:
    def test_register_creates_active_device(self, rig):
        app, _ = rig
        c = login(app, "a@example.com")
        r = register(c)
        assert r.status_code == 200, r.json()
        body = r.json()
        assert body["created"] is True and body["state"] == "active"
        assert body["name"] == "Yossi iPhone" and body["id"] > 0
        # Key secrecy: the registration key is never returned.
        assert "registration_key" not in body
        assert KEY not in r.text

    def test_reregistration_is_idempotent_same_row(self, rig):
        app, _ = rig
        c = login(app, "a@example.com")
        first = register(c).json()
        # A reinstall retries with the same key (and possibly a
        # different display name): same row, created=false, and the
        # server-side name stays authoritative.
        second = register(c, name="Renamed iPhone").json()
        assert second["created"] is False
        assert second["id"] == first["id"]
        assert second["name"] == "Yossi iPhone"
        # Exactly one device exists for the tenant.
        assert len(c.get("/api/devices").json()["devices"]) == 1

    def test_name_conflict_with_other_key_is_409(self, rig):
        app, _ = rig
        c = login(app, "a@example.com")
        assert register(c, name="phone-1").status_code == 200
        r = register(c, name="phone-1",
                     key="kg-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert r.status_code == 409

    def test_tenant_isolation(self, rig):
        app, _ = rig
        ca = login(app, "a@example.com")
        cb = login(app, "b@example.com")
        ra = register(ca).json()
        # Same key in another tenant is an INDEPENDENT row, never an
        # adoption of tenant A's device.
        rb = register(cb).json()
        assert rb["created"] is True and rb["id"] != ra["id"]
        # Tenant A's list shows only its own device and never leaks
        # the key.
        devices = ca.get("/api/devices").json()["devices"]
        assert [d["id"] for d in devices] == [ra["id"]]
        assert all("registration_key" not in d for d in devices)
        # Tenant B cannot mint or read rules for tenant A's device id.
        assert cb.get(
            f"/api/devices/{ra['id']}/filter-rules").status_code == 404
        assert cb.post(f"/api/devices/{ra['id']}/dataset-credential",
                       json={"scope": "dataset"},
                       headers=HDR).status_code == 404

    def test_inactive_device_not_reactivated(self, rig, engine):
        app, _ = rig
        c = login(app, "a@example.com")
        device_id = register(c).json()["id"]
        with session_scope(engine) as s:
            row = s.get(Device, device_id)
            row.state = "offboarded"
            s.commit()
        r = register(c)
        assert r.status_code == 200
        assert r.json()["created"] is False
        assert r.json()["state"] == "offboarded"
        with session_scope(engine) as s:
            assert s.get(Device, device_id).state == "offboarded"

    @pytest.mark.parametrize("key", ["", "short", "kg has spaces",
                                     "kg/slash", "kg_underscore",
                                     "x" * 65])
    def test_bad_registration_keys_rejected(self, rig, key):
        app, _ = rig
        c = login(app, "a@example.com")
        r = register(c, key=key)
        assert r.status_code == 422

    def test_empty_name_rejected(self, rig):
        app, _ = rig
        c = login(app, "a@example.com")
        assert register(c, name="").status_code == 422

    def test_auth_and_csrf_required(self, rig):
        app, _ = rig
        c = TestClient(app)
        # No session at all.
        assert c.post("/api/devices/personal-registration",
                      json={"name": "x", "registration_key": KEY},
                      headers=HDR).status_code == 401
        # Session but no CSRF marker header.
        c2 = login(app, "a@example.com")
        assert c2.post("/api/devices/personal-registration",
                       json={"name": "x",
                             "registration_key": KEY}).status_code == 403

    def test_viewer_cannot_register(self, rig):
        app, _ = rig
        c = login(app, "viewer-a@example.com")
        assert register(c).status_code == 403

    def test_audit_record_carries_no_key(self, rig):
        app, _ = rig
        c = login(app, "a@example.com")
        register(c)
        events = c.get("/api/audit-logs").json()["events"]
        register_events = [e for e in events
                           if e["action"] == "device.personal_register"]
        assert len(register_events) == 1
        assert KEY not in register_events[0]["detail"]




class TestRegistrationConcurrency:
    """PostgreSQL-backed races against the registration endpoint.

    The suite runs on pgserver, so lock_tenant is a real SELECT FOR
    UPDATE here - these tests would deadlock or duplicate on a broken
    serialization, not pass vacuously. Sessions are created serially
    (MFA enrolment is a single-user flow); the race under test is the
    registration endpoint itself.
    """

    def test_concurrent_same_key_yields_one_row(self, rig, engine):
        app, (ta, _) = rig
        clients = [login(app, "a@example.com") for _ in range(4)]
        barrier = threading.Barrier(4)

        def go(c):
            barrier.wait(timeout=10)
            return register(c)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(go, clients))
        assert all(r.status_code == 200 for r in results)
        bodies = [r.json() for r in results]
        assert len({b["id"] for b in bodies}) == 1
        assert sum(1 for b in bodies if b["created"]) == 1
        with session_scope(engine) as s:
            rows = s.scalars(
                select(Device).where(Device.tenant_id == ta)).all()
            assert len(rows) == 1

    def test_concurrent_same_name_one_wins_one_409(self, rig, engine):
        app, (ta, _) = rig
        clients = [login(app, "a@example.com") for _ in range(2)]
        barrier = threading.Barrier(2)
        keys = ["kg-" + "b" * 32, "kg-" + "c" * 32]

        def go(pair):
            c, key = pair
            barrier.wait(timeout=10)
            return register(c, name="same-name", key=key)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(go, zip(clients, keys)))
        assert sorted(r.status_code for r in results) == [200, 409]
        with session_scope(engine) as s:
            rows = s.scalars(
                select(Device).where(Device.tenant_id == ta)).all()
            assert len(rows) == 1

class TestClientConfig:
    def test_defaults_are_null(self, rig):
        app, _ = rig
        c = login(app, "a@example.com")
        body = c.get("/api/client-config").json()
        assert body == {"dataset_base_url": None,
                        "doh_server_url": None,
                        "pir_server_url": None,
                        "pir_privacy_pass_issuer_url": None}

    def test_configured_values_reported(self, engine, tmp_path):
        with session_scope(engine) as s:
            t = Tenant(name="family-cc")
            s.add(t)
            s.flush()
            s.add(User(tenant_id=t.id, email="cc@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        settings = _settings(
            tmp_path,
            KG_DATASET_BASE_URL="https://dataset.example.org",
            KG_DOH_SERVER_URL="https://dns.example.org/dns-query",
            KG_PIR_SERVER_URL="https://pir.example.org",
            KG_PIR_ISSUER_URL="https://issuer.example.org")
        c = TestClient(create_app(settings, engine=engine))
        r = mfa_login(c, json={"email": "cc@example.com",
                               "password": PASSWORD}, headers=HDR)
        assert r.status_code == 200
        body = c.get("/api/client-config").json()
        assert body["dataset_base_url"] == "https://dataset.example.org"
        assert body["doh_server_url"] == \
            "https://dns.example.org/dns-query"
        assert body["pir_server_url"] == "https://pir.example.org"
        assert body["pir_privacy_pass_issuer_url"] == \
            "https://issuer.example.org"

    def test_requires_authentication(self, rig):
        app, _ = rig
        assert TestClient(app).get("/api/client-config").status_code == 401

    @pytest.mark.parametrize("value", ["http://insecure.example.org",
                                       "https://user:pw@x.example.org",
                                       "https://x.example.org/?q=1",
                                       "not-a-url"])
    def test_invalid_service_url_is_startup_error(self, tmp_path, value):
        with pytest.raises(ConfigError):
            _settings(tmp_path, KG_DATASET_BASE_URL=value)

    def test_lone_pir_url_is_startup_error(self, tmp_path):
        with pytest.raises(ConfigError):
            _settings(tmp_path,
                      KG_PIR_SERVER_URL="https://pir.example.org")
