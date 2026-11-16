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

        import glob
        roots = glob.glob(os.path.join(pub_root, "tenant-*"))
        assert len(roots) == 1
        manifest = Publisher(roots[0]).current()
        assert manifest["revision"] == 2
        assert manifest["generation"] == "2"
        assert manifest["tenant_id"] is not None

        policy = json.loads((open(os.path.join(
            roots[0], "generations", "2", "policy.json")).read()))
        assert policy["blocklist"] == ["bad.example"]
        # File permissions enforced by the publishing discipline.
        import stat as _stat
        mode = _stat.S_IMODE(os.stat(os.path.join(
            roots[0], "generations", "2", "policy.json")).st_mode)
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
        import glob
        roots = glob.glob(os.path.join(pub_root, "tenant-*"))
        assert len(roots) == 1
        gen = os.path.join(roots[0], "current")
        engine, _info = engine_set.load_validated_engine(
            os.path.join(gen, "policy.json"),
            os.path.join(gen, "categories.json"))
        assert engine.decide("bad.example").action == "block"
        assert engine.decide("good.example").action == "allow"


class TestCrossTenantIsolation:
    """Negative tests: no cross-tenant read, overwrite, or deletion."""

    def _tenant_client(self, engine, pub_root, name, email):
        with session_scope(engine) as s:
            tenant = Tenant(name=name)
            s.add(tenant)
            s.flush()
            s.add(User(tenant_id=tenant.id, email=email,
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                             "KG_PUBLICATIONS_ROOT": pub_root})
        c = TestClient(create_app(settings, engine=engine))
        login(c, email)
        return c

    def test_second_tenant_publish_never_touches_first(self, engine, pub_root):
        ca = self._tenant_client(engine, pub_root, "family-a", "a@x.com")
        cb = self._tenant_client(engine, pub_root, "family-b", "b@x.com")

        r = ca.post("/api/policies", json=dict(BASE, name="pa"), headers=HDR)
        pid = r.json()["id"]
        ca.post(f"/api/policies/{pid}/select", headers=HDR)
        r = ca.post("/api/publications", headers=HDR)
        assert r.status_code == 200, r.text

        r = cb.post("/api/policies", json=dict(BASE, name="pb"), headers=HDR)
        pid = r.json()["id"]
        cb.post(f"/api/policies/{pid}/select", headers=HDR)
        r = cb.post("/api/publications", headers=HDR)
        assert r.status_code == 200, r.text  # no collision

        # Both tenants have their own generation 1, intact.
        import glob
        gens = sorted(glob.glob(os.path.join(
            pub_root, "tenant-*", "generations", "1", "policy.json")))
        assert len(gens) == 2

        # Each tenant's current shows only its own policy.
        ma = ca.get("/api/publications/current").json()["manifest"]
        mb = cb.get("/api/publications/current").json()["manifest"]
        assert ma["policy"] == "pa"
        assert mb["policy"] == "pb"
        assert ma["tenant_id"] != mb["tenant_id"]

        # Tenant A's published policy still decides correctly (not deleted).
        import engine_set
        gen = os.path.join(pub_root, f"tenant-{ma['tenant_id']}", "current")
        engine_obj, _ = engine_set.load_validated_engine(
            os.path.join(gen, "policy.json"),
            os.path.join(gen, "categories.json"))
        assert engine_obj.decide("bad.example").action == "block"

    def test_failed_publish_leaves_other_tenant_bytes_unchanged(self,
                                                                 engine,
                                                                 pub_root):
        """Fix 1 negative case: a FAILED publish for tenant B (replayed
        revision inside B's own root) must not change a single byte of
        tenant A's active generation, and must not clean up B's own
        existing generation either (cleanup is self-created-only)."""
        import hashlib
        ca = self._tenant_client(engine, pub_root, "family-a", "a@x.com")
        cb = self._tenant_client(engine, pub_root, "family-b", "b@x.com")
        ra = ca.post("/api/policies", json=dict(BASE, name="pa"), headers=HDR)
        ca.post(f"/api/policies/{ra.json()['id']}/select", headers=HDR)
        assert ca.post("/api/publications", headers=HDR).status_code == 200
        rb = cb.post("/api/policies", json=dict(BASE, name="pb"), headers=HDR)
        cb.post(f"/api/policies/{rb.json()['id']}/select", headers=HDR)
        assert cb.post("/api/publications", headers=HDR).status_code == 200

        def tree_hashes(root):
            out = {}
            for dirpath, _dirs, files in os.walk(root):
                for f in files:
                    full = os.path.join(dirpath, f)
                    out[os.path.relpath(full, root)] = hashlib.sha256(
                        open(full, "rb").read()).hexdigest()
            return out

        ma = ca.get("/api/publications/current").json()["manifest"]
        mb = cb.get("/api/publications/current").json()["manifest"]
        root_a = os.path.join(pub_root, f"tenant-{ma['tenant_id']}")
        root_b = os.path.join(pub_root, f"tenant-{mb['tenant_id']}")
        before_a, before_b = tree_hashes(root_a), tree_hashes(root_b)

        # Tenant B replays its own revision directly at the publisher:
        # must be refused and must delete nothing anywhere.
        from app.publisher import Publisher
        from app.publication_ops import export_policy_documents
        p_bytes, c_bytes = b"{}", b"{}"
        with Publisher(root_b).locked():
            try:
                Publisher(root_b).publish(
                    mb["revision"], p_bytes, c_bytes, {"k": "replay"})
                assert False, "replay must be refused"
            except Exception:
                pass

        assert tree_hashes(root_a) == before_a, "tenant A bytes changed"
        assert tree_hashes(root_b) == before_b, "tenant B bytes changed"
        assert Publisher(root_b).current()["revision"] == mb["revision"]

    def test_mid_publish_failure_cleans_only_own_generation(self, engine,
                                                            pub_root):
        """Fix 1 negative case, DISTINCT from replay-before-writes: the
        generation directory is CREATED and a write fails mid-publish.
        Cleanup must remove only the partial generation it created -
        tenant A's active generation bytes and tenant B's pre-existing
        current pointer stay exactly as they were."""
        import hashlib
        ca = self._tenant_client(engine, pub_root, "family-a", "a@x.com")
        cb = self._tenant_client(engine, pub_root, "family-b", "b@x.com")
        ra = ca.post("/api/policies", json=dict(BASE, name="pa"), headers=HDR)
        ca.post(f"/api/policies/{ra.json()['id']}/select", headers=HDR)
        assert ca.post("/api/publications", headers=HDR).status_code == 200
        rb = cb.post("/api/policies", json=dict(BASE, name="pb"), headers=HDR)
        cb.post(f"/api/policies/{rb.json()['id']}/select", headers=HDR)
        assert cb.post("/api/publications", headers=HDR).status_code == 200

        def tree_hashes(root):
            out = {}
            for dirpath, _dirs, files in os.walk(root):
                for f in files:
                    full = os.path.join(dirpath, f)
                    out[os.path.relpath(full, root)] = hashlib.sha256(
                        open(full, "rb").read()).hexdigest()
            return out

        ma = ca.get("/api/publications/current").json()["manifest"]
        mb = cb.get("/api/publications/current").json()["manifest"]
        root_a = os.path.join(pub_root, f"tenant-{ma['tenant_id']}")
        root_b = os.path.join(pub_root, f"tenant-{mb['tenant_id']}")
        before_a, before_b = tree_hashes(root_a), tree_hashes(root_b)

        # Fail tenant B's NEXT publish mid-write: valid documents, but
        # the categories write raises after policy.json has landed.
        from app.publication_ops import export_policy_documents
        from app.models import PolicyVersion as _PV
        from sqlalchemy import select as _select
        import json as _json
        with session_scope(engine) as s2:
            ver = s2.scalar(_select(_PV).where(
                _PV.policy_id == rb.json()["id"]).order_by(
                    _PV.version.desc()).limit(1))
            pol_bytes, cat_bytes = export_policy_documents(ver)
        import app.publisher as pub_mod
        real_write = pub_mod._write_file_atomic
        calls = {"n": 0}

        def failing_write(path, content, token):
            calls["n"] += 1
            if calls["n"] == 2:  # categories.json: policy.json landed
                raise OSError("simulated mid-publish write failure")
            return real_write(path, content, token)

        pub_mod._write_file_atomic = failing_write
        try:
            with Publisher(root_b).locked():
                try:
                    Publisher(root_b).publish(
                        mb["revision"] + 1, pol_bytes, cat_bytes,
                        {"k": "bad"})
                    assert False, "publish must fail"
                except OSError:
                    pass
        finally:
            pub_mod._write_file_atomic = real_write

        # Tenant A untouched, byte for byte; tenant B's partial
        # generation was cleaned up, its prior current intact.
        assert tree_hashes(root_a) == before_a, "tenant A bytes changed"
        assert tree_hashes(root_b) == before_b, \
            "tenant B partial generation not cleaned or bytes changed"
        assert Publisher(root_b).current()["revision"] == mb["revision"]

    def test_replay_same_revision_is_refused_and_preserves_data(self,
                                                                pub_root):
        """A direct second publish with the same revision never deletes
        the existing generation, even inside one tenant's root."""
        from app.publisher import Publisher, PublicationError
        from app.publication_ops import export_policy_documents
        p, c = b'{"default_policy": "allow", "allowlist": [], "blocklist": [], "category_rules": {"allow": [], "block": []}}', b'{"domains": {}, "_meta": {}}'
        pub = Publisher(pub_root)
        with pub.locked():
            pub.publish(1, p, c, {"k": "first"})
        with pub.locked():
            try:
                pub.publish(1, p, c, {"k": "second"})
                assert False, "replay must be refused"
            except Exception:
                pass
        # Original generation untouched.
        import json as _json
        manifest = _json.loads(open(os.path.join(
            pub_root, "generations", "1", "manifest.json")).read())
        assert manifest["k"] == "first"
        assert pub.current()["revision"] == 1

    def test_publish_with_categories_file(self, engine, tmp_path):
        """A built categories.json reaches the published generation."""
        import subprocess
        cat_out = str(tmp_path / "categories.json")
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        subprocess.run(
            [sys.executable, os.path.join(repo, "category-pipeline", "build.py"),
             "--out", cat_out], check=True, capture_output=True)
        pub_root = str(tmp_path / "pub")
        with session_scope(engine) as s:
            tenant = Tenant(name="family-cat")
            s.add(tenant)
            s.flush()
            s.add(User(tenant_id=tenant.id, email="c@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                             "KG_PUBLICATIONS_ROOT": pub_root,
                             "KG_CATEGORIES_FILE": cat_out})
        c = TestClient(create_app(settings, engine=engine))
        login(c, email="c@example.com")
        r = c.post("/api/policies",
                   json={"name": "pc", "default_policy": "allow",
                         "blocklist": [], "allowlist": [],
                         "category_allow": [], "category_block": ["gambling"]},
                   headers=HDR)
        assert r.status_code == 200, r.text
        pid = r.json()["id"]
        c.post(f"/api/policies/{pid}/select", headers=HDR)
        r = c.post("/api/publications", headers=HDR)
        assert r.status_code == 200, r.text

        import engine_set
        import glob
        gen = os.path.join(glob.glob(os.path.join(
            pub_root, "tenant-*", "current"))[0])
        engine_obj, _ = engine_set.load_validated_engine(
            os.path.join(gen, "policy.json"),
            os.path.join(gen, "categories.json"))
        assert engine_obj.decide("bet365.com").action == "block"
        assert engine_obj.decide("wikipedia.org").action == "allow"
