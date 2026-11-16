"""Milestone 2 publication trigger tests, against bundled PostgreSQL."""

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
from app.models import Role, Tenant, User  # noqa: E402
from app.publisher import Publisher  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
BASE = {"default_policy": "allow", "blocklist": ["bad.example"],
        "allowlist": [], "category_allow": [], "category_block": []}


@pytest.fixture()
def pub_root(tmp_path):
    return str(tmp_path / "pub")


@pytest.fixture()
def client(engine, pub_root):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-pub")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="g@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        s.add(User(tenant_id=tenant.id, email="v@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.viewer))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": pub_root})
    return TestClient(create_app(settings, engine=engine))


def login(c, email="g@example.com"):
    r = c.post("/api/auth/login",
               json={"email": email, "password": PASSWORD}, headers=HDR)
    assert r.status_code == 200


def make_default_policy(c):
    r = c.post("/api/policies", json=dict(BASE, name="fam"), headers=HDR)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]
    r = c.post(f"/api/policies/{pid}/select", headers=HDR)
    assert r.status_code == 200, r.text
    return pid


class TestPublications:
    def test_publish_without_default_is_409(self, client):
        login(client)
        r = client.post("/api/publications", headers=HDR)
        assert r.status_code == 409

    def test_viewer_cannot_publish(self, client):
        login(client)
        make_default_policy(client)
        login(client, email="v@example.com")
        r = client.post("/api/publications", headers=HDR)
        assert r.status_code == 403

    def test_publish_and_republish_increments_revision(self, client, pub_root):
        login(client)
        make_default_policy(client)
        r1 = client.post("/api/publications", headers=HDR)
        assert r1.status_code == 200, r1.text
        assert r1.json()["revision"] == 1
        r2 = client.post("/api/publications", headers=HDR)
        assert r2.json()["revision"] == 2

        manifest = Publisher(pub_root).current()
        assert manifest["revision"] == 2
        assert manifest["generation"] == "2"
        assert manifest["tenant_id"] is not None

        policy = json.loads((open(os.path.join(
            pub_root, "generations", "2", "policy.json")).read()))
        assert policy["blocklist"] == ["bad.example"]
        # File permissions enforced by the publishing discipline.
        import stat as _stat
        mode = _stat.S_IMODE(os.stat(os.path.join(
            pub_root, "generations", "2", "policy.json")).st_mode)
        assert mode == 0o600

    def test_current_endpoint(self, client):
        login(client)
        r = client.get("/api/publications/current")
        assert r.json() == {"published": False}
        make_default_policy(client)
        client.post("/api/publications", headers=HDR)
        r = client.get("/api/publications/current")
        body = r.json()
        assert body["published"] is True
        assert body["manifest"]["revision"] == 1

    def test_published_generation_loads_in_the_engine(self, client, pub_root):
        """End to end: control-plane publication -> engine decision."""
        import engine_set  # engine src is on sys.path via app.policy_ops
        login(client)
        make_default_policy(client)
        r = client.post("/api/publications", headers=HDR)
        assert r.status_code == 200, r.text
        gen = os.path.join(pub_root, "current")
        engine, _info = engine_set.load_validated_engine(
            os.path.join(gen, "policy.json"),
            os.path.join(gen, "categories.json"))
        assert engine.decide("bad.example").action == "block"
        assert engine.decide("good.example").action == "allow"
