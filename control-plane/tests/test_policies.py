"""Milestone 2 policy API tests, including the tighten-only invariant."""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}

BASE = {"default_policy": "allow", "blocklist": ["bad.example"],
        "allowlist": [], "category_allow": [], "category_block": []}
TIGHTER = dict(BASE, category_block=["adult"])
LOOSER = {"default_policy": "allow", "blocklist": [], "allowlist": [],
          "category_allow": [], "category_block": []}


@pytest.fixture()
def client(engine):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-p")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="g@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
              "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    c = TestClient(create_app(settings, engine=engine))
    r = c.post("/api/auth/login",
               json={"email": "g@example.com", "password": PASSWORD},
               headers=HDR)
    assert r.status_code == 200
    return c


def mkpolicy(c, name, **doc):
    body = {"name": name, **doc}
    return c.post("/api/policies", json=body, headers=HDR)


class TestPolicies:
    def test_create_and_list(self, client):
        r = mkpolicy(client, "base", **BASE)
        assert r.status_code == 200, r.json()
        assert r.json()["versions"] == 1
        listing = client.get("/api/policies").json()["policies"]
        assert [p["name"] for p in listing] == ["base"]
        assert listing[0]["blocklist"] == ["bad.example"]

    def test_duplicate_name_rejected(self, client):
        assert mkpolicy(client, "base", **BASE).status_code == 200
        assert mkpolicy(client, "base", **BASE).status_code == 409

    def test_invalid_rules_rejected(self, client):
        r = mkpolicy(client, "bad", default_policy="sideways")
        assert r.status_code == 400

    def test_update_creates_version(self, client):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        r = client.put(f"/api/policies/{pid}",
                       json={"name": "base", **TIGHTER}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["versions"] == 2

    def test_assignment_tighten_only(self, client):
        default = mkpolicy(client, "default", **TIGHTER).json()["id"]
        client.post(f"/api/policies/{default}/select", headers=HDR)
        looser = mkpolicy(client, "looser", **LOOSER).json()["id"]
        device = client.post("/api/devices", json={"name": "phone-1"},
                             headers=HDR).json()["id"]
        r = client.post(f"/api/devices/{device}/assignment",
                        json={"policy_id": looser}, headers=HDR)
        assert r.status_code == 409
        tighter = mkpolicy(client, "tighter", **dict(
            TIGHTER, blocklist=["bad.example", "worse.example"])
        ).json()["id"]
        r = client.post(f"/api/devices/{device}/assignment",
                        json={"policy_id": tighter}, headers=HDR)
        assert r.status_code == 200, r.json()

    def test_default_reselection_recHECKS_assignments(self, client):
        default = mkpolicy(client, "default", **LOOSER).json()["id"]
        client.post(f"/api/policies/{default}/select", headers=HDR)
        mid = mkpolicy(client, "mid", **BASE).json()["id"]
        device = client.post("/api/devices", json={"name": "phone-2"},
                             headers=HDR).json()["id"]
        assert client.post(f"/api/devices/{device}/assignment",
                           json={"policy_id": mid},
                           headers=HDR).status_code == 200
        # Selecting a stricter default would loosen the existing
        # assignment relative to the default: refused.
        strict = mkpolicy(client, "strict", **TIGHTER).json()["id"]
        r = client.post(f"/api/policies/{strict}/select", headers=HDR)
        assert r.status_code == 409

    def test_cross_tenant_policy_invisible(self, client, engine):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        with session_scope(engine) as s:
            other = Tenant(name="other-family")
            s.add(other)
            s.flush()
            s.add(User(tenant_id=other.id, email="o@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        c2 = TestClient(client.app)
        c2.post("/api/auth/login",
                json={"email": "o@example.com", "password": PASSWORD},
                headers=HDR)
        assert c2.get("/api/policies").json()["policies"] == []
        r = c2.put(f"/api/policies/{pid}",
                   json={"name": "stolen", **BASE}, headers=HDR)
        assert r.status_code == 404
