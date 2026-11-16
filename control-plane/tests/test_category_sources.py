"""Answer 22 tests: category source registry - provenance, versioned
imports with hashes, manual review activation, rollback, history.
"""

import hashlib
import os
import sys

import pyotp
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402
from app.publisher import canonical_json  # noqa: E402
from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
HASH1 = "a" * 64
HASH2 = "b" * 64


def _normalized(rules):
    """Mirror the registry's row normalization so the digest binds the
    exact canonical bytes the import validates."""
    return [{"domain": str(r.get("domain", "")).strip().lower().rstrip("."),
             "category": str(r.get("category", "")).strip(),
             "verdict": str(r.get("verdict", "block")).strip()}
            for r in rules]


def rules_digest(rules):
    """The digest the registry binds imports to: sha256 over the
    canonical JSON of the validated rules."""
    return hashlib.sha256(canonical_json(_normalized(rules))).hexdigest()


def make_client(engine, staff=True, email="admin@example.com",
                categories_file=None, raise_server_exceptions=True):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-x")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner,
                   staff_role="owner" if staff else None))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
    if categories_file:
        env["KG_CATEGORIES_FILE"] = categories_file
    c = TestClient(create_app(Settings(env), engine=engine),
                   raise_server_exceptions=raise_server_exceptions)
    r = mfa_login(c, json={"email": email, "password": PASSWORD},
                  headers=HDR)
    assert r.status_code == 200, r.text
    return c


def fresh_code(client, email="admin@example.com"):
    known = getattr(client.app.state, "_fixture_mfa", {})
    return pyotp.TOTP(known[email]).now()


def mk_source(client, name="ut1"):
    r = client.post("/api/admin/category-sources",
                    json={"name": name, "license_name": "CC-BY-4.0",
                          "attribution": "UT1, univ-toulouse.fr"},
                    headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


def mk_import(client, source_id, version="2024-01", sha=None,
              rules=None):
    if rules is None:
        rules = [{"domain": "bet365.com", "category": "gambling",
                  "verdict": "block"}]
    if sha is None:
        sha = rules_digest(rules)
    r = client.post(f"/api/admin/category-sources/{source_id}/imports",
                    json={"version": version, "sha256": sha,
                          "category_mapping": {"gambling": "gambling"},
                          "rules": rules},
                    headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


def activate(client, source_id, update_id, email="admin@example.com"):
    return client.post(
        f"/api/admin/category-sources/{source_id}/activate",
        json={"update_id": update_id,
              "totp_code": fresh_code(client, email),
              "confirm": "activate-category-update"}, headers=HDR)


class TestSources:
    def test_create_and_list(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        assert source["license_name"] == "CC-BY-4.0"
        listing = c.get("/api/admin/category-sources").json()["sources"]
        assert [s["name"] for s in listing] == ["ut1"]

    def test_staff_gate(self, engine):
        c = make_client(engine, staff=False)
        r = c.post("/api/admin/category-sources",
                   json={"name": "x", "license_name": "MIT",
                         "attribution": "a"}, headers=HDR)
        assert r.status_code == 403
        assert c.get("/api/admin/category-sources").status_code == 403

    def test_license_and_attribution_required(self, engine):
        c = make_client(engine)
        r = c.post("/api/admin/category-sources",
                   json={"name": "x", "license_name": "",
                         "attribution": "a"}, headers=HDR)
        assert r.status_code == 422

    def test_duplicate_name_rejected(self, engine):
        c = make_client(engine)
        mk_source(c)
        r = c.post("/api/admin/category-sources",
                   json={"name": "ut1", "license_name": "MIT",
                         "attribution": "a"}, headers=HDR)
        assert r.status_code == 409


class TestImportsAndReview:
    def test_import_starts_pending_review(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        update = mk_import(c, source["id"])
        assert update["status"] == "pending_review"
        assert update["sha256"] == rules_digest(update and [{"domain": "bet365.com", "category": "gambling", "verdict": "block"}])
        assert update["rules_count"] == 1
        # Pending data is never effective before review.
        rules = c.get("/api/admin/categories").json()["rules"]
        assert rules == []

    def test_import_validates_sha256(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        r = c.post(f"/api/admin/category-sources/{source['id']}/imports",
                   json={"version": "1", "sha256": "not-a-hash"},
                   headers=HDR)
        assert r.status_code == 400

    def test_import_rejects_malformed_rules(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        r = c.post(f"/api/admin/category-sources/{source['id']}/imports",
                   json={"version": "1", "sha256": HASH1,
                         "rules": [{"domain": "not a domain!!",
                                    "category": "gambling"}]},
                   headers=HDR)
        assert r.status_code == 400
        r = c.post(f"/api/admin/category-sources/{source['id']}/imports",
                   json={"version": "1", "sha256": HASH1,
                         "rules": [{"domain": "x.com"}]},
                   headers=HDR)
        assert r.status_code == 400

    def test_activation_applies_rules_with_provenance(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        update = mk_import(c, source["id"])
        assert activate(c, source["id"], update["id"]).status_code == 200
        rules = c.get("/api/admin/categories").json()["rules"]
        assert len(rules) == 1
        assert rules[0]["domain"] == "bet365.com"
        assert rules[0]["category"] == "gambling"
        assert rules[0]["source"] == "ut1@2024-01"
        assert rules[0]["active"] is True

    def test_activation_replaces_and_rollback_restores(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        u1 = mk_import(c, source["id"], version="2024-01",
                       rules=[{"domain": "old.com", "category": "ads"}])
        u2 = mk_import(c, source["id"], version="2024-02",
                       rules=[{"domain": "new.com", "category": "ads"}])
        assert activate(c, source["id"], u1["id"]).status_code == 200
        assert activate(c, source["id"], u2["id"]).status_code == 200
        rules = {r["domain"]: r for r in
                 c.get("/api/admin/categories").json()["rules"]}
        assert rules["old.com"]["active"] is False
        assert rules["new.com"]["active"] is True
        # Rollback: real data rollback, not just status.
        r = c.post(f"/api/admin/category-sources/{source['id']}/rollback",
                   json={"update_id": u1["id"],
                         "totp_code": fresh_code(c),
                         "confirm": "rollback-category-update"},
                   headers=HDR)
        assert r.status_code == 200
        rules = {r["domain"]: r for r in
                 c.get("/api/admin/categories").json()["rules"]}
        assert rules["old.com"]["active"] is True
        assert rules["new.com"]["active"] is False

    def test_rules_less_update_cannot_activate(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        update = mk_import(c, source["id"], rules=[])
        r = activate(c, source["id"], update["id"])
        assert r.status_code == 400

    def test_activate_requires_fresh_mfa(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        update = mk_import(c, source["id"])
        r = c.post(f"/api/admin/category-sources/{source['id']}/activate",
                   json={"update_id": update["id"], "totp_code": "000000",
                         "confirm": "activate-category-update"},
                   headers=HDR)
        assert r.status_code == 403
        r = activate(c, source["id"], update["id"])
        assert r.status_code == 200, r.json()
        assert r.json()["status"] == "active"

    def test_only_one_active_and_rollback(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        u1 = mk_import(c, source["id"], version="2024-01")
        u2 = mk_import(c, source["id"], version="2024-02")
        assert activate(c, source["id"], u1["id"]).json()["status"] == "active"
        assert activate(c, source["id"], u2["id"]).json()["status"] == "active"
        history = c.get(
            f"/api/admin/category-sources/{source['id']}/history").json()
        by_id = {u["id"]: u for u in history["updates"]}
        assert by_id[u1["id"]]["status"] == "superseded"
        assert by_id[u2["id"]]["status"] == "active"
        # Roll back to the superseded update with fresh MFA.
        r = c.post(f"/api/admin/category-sources/{source['id']}/rollback",
                   json={"update_id": u1["id"],
                         "totp_code": fresh_code(c),
                         "confirm": "rollback-category-update"},
                   headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["status"] == "active"
        history = c.get(
            f"/api/admin/category-sources/{source['id']}/history").json()
        by_id = {u["id"]: u for u in history["updates"]}
        assert by_id[u2["id"]]["status"] == "rolled_back"
        assert by_id[u1["id"]]["status"] == "active"

    def test_activate_rejects_non_pending(self, engine):
        c = make_client(engine)
        source = mk_source(c)
        u1 = mk_import(c, source["id"], version="2024-01")
        assert activate(c, source["id"], u1["id"]).status_code == 200
        r = activate(c, source["id"], u1["id"])
        assert r.status_code == 409


class TestImportHashBinding:
    def test_hash_must_match_canonical_dataset(self, engine):
        """A format-valid hash that does not match the canonical
        dataset bytes is not payload integrity: reject it. The binding
        is sha256 over the canonical JSON of the validated rules."""
        c = make_client(engine)
        source = mk_source(c)
        rules = [{"domain": "bet365.com", "category": "gambling",
                  "verdict": "block"}]
        r = c.post(f"/api/admin/category-sources/{source['id']}/imports",
                   json={"version": "1", "sha256": HASH1,
                         "rules": rules}, headers=HDR)
        assert r.status_code == 400
        # Tampered rows under the correct hash are rejected too.
        r = c.post(f"/api/admin/category-sources/{source['id']}/imports",
                   json={"version": "1", "sha256": rules_digest(rules),
                         "rules": [{"domain": "bet365.com",
                                    "category": "gambling",
                                    "verdict": "allow"}]},
                   headers=HDR)
        assert r.status_code == 400
        # The exact canonical digest imports cleanly.
        ok = mk_import(c, source["id"], rules=rules)
        assert ok["sha256"] == rules_digest(rules)


class TestFileSyncIntegrity:
    @staticmethod
    def _mk(engine, tmp_path, **kw):
        path = str(tmp_path / "categories.json")
        return make_client(engine, categories_file=path, **kw), path

    def test_commit_failure_leaves_file_untouched(self, engine,
                                                  tmp_path, monkeypatch):
        """If the database commit fails, the categories file must not
        be written at all (file sync runs strictly after the commit)."""
        import sqlalchemy.orm
        c, path = self._mk(engine, tmp_path,
                           raise_server_exceptions=False)
        with open(path, "wb") as fh:
            fh.write(b"sentinel")
        source = mk_source(c)
        update = mk_import(c, source["id"])
        def boom(self):
            raise RuntimeError("simulated commit failure")
        monkeypatch.setattr(sqlalchemy.orm.Session, "commit", boom)
        r = activate(c, source["id"], update["id"])
        assert r.status_code == 500
        monkeypatch.undo()
        with open(path, "rb") as fh:
            assert fh.read() == b"sentinel"
        history = c.get(
            f"/api/admin/category-sources/{source['id']}/history").json()
        assert history["updates"][0]["status"] == "pending_review"

    def test_sync_failure_keeps_lkg_audits_and_resync_repairs(
            self, engine, tmp_path, monkeypatch):
        """A failed post-commit file sync leaves the last-known-good
        file untouched, is audited, the committed rules stay
        effective, and the resync endpoint repairs the file."""
        import app.category_source_routes as routes_mod
        c, path = self._mk(engine, tmp_path)
        source = mk_source(c)
        update = mk_import(c, source["id"])
        def boom(*a, **kw):
            raise OSError("simulated filesystem failure")
        monkeypatch.setattr(routes_mod.os, "replace", boom)
        r = activate(c, source["id"], update["id"])
        assert r.status_code == 500
        assert "last-known-good" in r.json()["error"]
        monkeypatch.undo()
        # Rules committed and effective; no file materialized.
        rules = c.get("/api/admin/categories").json()["rules"]
        assert rules[0]["active"] is True
        assert not os.path.exists(path)
        with session_scope(engine) as s:
            from app.models import AuditEvent
            actions = [a.action for a in s.scalars(
                __import__("sqlalchemy").select(AuditEvent)).all()]
        assert "category_source.file_sync_failed" in actions
        # Repair path.
        r = c.post("/api/admin/category-sources/resync", headers=HDR)
        assert r.status_code == 200
        assert r.json()["synced"] is True
        import json as _json
        with open(path, "rb") as fh:
            doc = _json.loads(fh.read())
        assert doc["domains"] == {"bet365.com": ["gambling"]}

    def test_activation_writes_engine_valid_file(self, engine, tmp_path):
        c, path = self._mk(engine, tmp_path)
        source = mk_source(c)
        update = mk_import(c, source["id"])
        assert activate(c, source["id"], update["id"]).status_code == 200
        import json as _json
        with open(path, "rb") as fh:
            doc = _json.loads(fh.read())
        assert doc["domains"] == {"bet365.com": ["gambling"]}
        # The engine's own loader accepts what was written.
        eng = os.path.join(os.path.dirname(__file__), "..", "..",
                           "filtering-engine", "src")
        sys.path.insert(0, os.path.abspath(eng))
        import category_db
        assert category_db.CategoryDB(
            doc["domains"], meta=doc["_meta"]).categories_for(
                "bet365.com") == {"gambling"}


class TestPublishDivergenceGuard:
    def test_publish_refuses_diverged_categories_file(self, engine,
                                                      tmp_path):
        """The publish flow verifies the categories file against the
        committed registry-managed rules and refuses to ship a
        diverged file; an operator-provided file with no
        registry-managed rules is left alone."""
        from app.models import (CategoryRule, CategorySource,
                                CategorySourceUpdate)
        from app.policy_ops import PolicyError
        from app.publication_ops import (
            _assert_categories_file_matches_db, build_categories_doc)
        path = str(tmp_path / "categories.json")
        with session_scope(engine) as s:
            src = CategorySource(name="t", license_name="CC0",
                                 attribution="t", created_by_user_id=None)
            s.add(src)
            s.flush()
            upd = CategorySourceUpdate(
                source_id=src.id, version="1", sha256="a" * 64,
                category_mapping="{}", validation_results="{}",
                rules_json="[]", imported_by_user_id=None,
                status="active")
            s.add(upd)
            s.flush()
            s.add(CategoryRule(domain="bet365.com", category="gambling",
                               verdict="block", source="t@1",
                               source_update_id=upd.id, active=True))
        with open(path, "wb") as fh:
            fh.write(canonical_json({"_meta": {}, "domains":
                                     {"evil.example": ["adult"]}}))
        with session_scope(engine) as s:
            try:
                _assert_categories_file_matches_db(s, path)
                raise AssertionError("divergence not detected")
            except PolicyError as exc:
                assert "diverged" in str(exc)
        with session_scope(engine) as s:
            with open(path, "wb") as fh:
                fh.write(canonical_json(build_categories_doc(s)))
        with session_scope(engine) as s:
            _assert_categories_file_matches_db(s, path)  # no raise

    def test_zero_active_registry_rules_still_enforced(self, engine,
                                                       tmp_path):
        """Provenance, not row count: after a registry update was
        activated and its rules are later all deactivated, a stale
        registry file on disk must NOT silently fall back to the
        operator-file carve-out - publish still refuses until resync
        materializes the empty committed state."""
        from app.models import CategoryRule
        from app.policy_ops import PolicyError
        from app.publication_ops import (
            _assert_categories_file_matches_db, build_categories_doc)
        c, path = TestFileSyncIntegrity._mk(engine, tmp_path)
        source = mk_source(c)
        update = mk_import(c, source["id"])
        assert activate(c, source["id"], update["id"]).status_code == 200
        # Deactivate the only registry rule directly (removal path).
        with session_scope(engine) as s:
            rule = s.scalars(__import__("sqlalchemy").select(
                CategoryRule)).first()
            rule.active = False
        with session_scope(engine) as s:
            try:
                _assert_categories_file_matches_db(s, path)
                raise AssertionError("stale registry file accepted")
            except PolicyError as exc:
                assert "diverged" in str(exc)
        # Resync materializes the empty committed state; then publish
        # verification passes again.
        assert c.post("/api/admin/category-sources/resync",
                      headers=HDR).status_code == 200
        with session_scope(engine) as s:
            _assert_categories_file_matches_db(s, path)  # no raise

    def test_guard_skips_operator_provided_dataset(self, engine,
                                                   tmp_path):
        """With no registry-managed active rules the categories file is
        operator-provided (pipeline build); nothing committed to
        diverge from, so the guard does not apply."""
        from app.models import CategoryRule
        from app.publication_ops import _assert_categories_file_matches_db
        path = str(tmp_path / "categories.json")
        with session_scope(engine) as s:
            s.add(CategoryRule(domain="manual.example", category="misc",
                               verdict="block", source="manual",
                               source_update_id=None, active=True))
        with open(path, "wb") as fh:
            fh.write(canonical_json({"_meta": {}, "domains":
                                     {"pipeline.example": ["ads"]}}))
        with session_scope(engine) as s:
            _assert_categories_file_matches_db(s, path)  # no raise


class TestConcurrentActivation:
    def test_concurrent_activations_serialize(self, engine):
        """Two staff activations racing on the SAME source: the source
        row lock serializes them; exactly one update ends active and
        the active rules match it exactly (no interleaving)."""
        import threading
        c = make_client(engine)
        source = mk_source(c)
        u1 = mk_import(c, source["id"], version="2024-01",
                       rules=[{"domain": "a.com", "category": "ads"}])
        u2 = mk_import(c, source["id"], version="2024-02",
                       rules=[{"domain": "b.com", "category": "ads"}])
        c2 = make_client(engine, email="second@example.com")
        barrier = threading.Barrier(2)
        results = {}

        def go(client, uid, key, email):
            barrier.wait(timeout=10)
            results[key] = activate(client, source["id"], uid, email
                                    ).status_code

        threads = [threading.Thread(
                       target=go, args=(c, u1["id"], "u1",
                                        "admin@example.com")),
                   threading.Thread(
                       target=go, args=(c2, u2["id"], "u2",
                                        "second@example.com"))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert sorted(results.values()) == [200, 200], results
        history = c.get(
            f"/api/admin/category-sources/{source['id']}/history").json()
        active = [u for u in history["updates"]
                  if u["status"] == "active"]
        assert len(active) == 1
        expected = {"u1": "a.com", "u2": "b.com"}
        winner = "u1" if active[0]["id"] == u1["id"] else "u2"
        rules = {r["domain"]: r["active"] for r in
                 c.get("/api/admin/categories").json()["rules"]}
        assert rules[expected[winner]] is True
        loser = "u2" if winner == "u1" else "u1"
        assert rules[expected[loser]] is False


class TestCrossSourceSync:
    def test_concurrent_cross_source_syncs_converge(self, engine,
                                                    tmp_path):
        """Two activations on DIFFERENT sources race; the shared
        categories file must end up matching the union of committed
        rules regardless of interleaving (global sync lock + advisory
        lock), never a stale subset written after a newer commit."""
        import json as _json
        import threading
        c, path = TestFileSyncIntegrity._mk(engine, tmp_path)
        s1 = mk_source(c, name="src-a")
        s2 = mk_source(c, name="src-b")
        c2 = make_client(engine, email="second@example.com")
        s1u = mk_import(c, s1["id"], version="1",
                        rules=[{"domain": "a.com", "category": "ads"}])
        s2u = mk_import(c, s2["id"], version="1",
                        rules=[{"domain": "b.com", "category": "ads"}])
        barrier = threading.Barrier(2)
        results = {}

        def go(client, sid, uid, key, email):
            barrier.wait(timeout=10)
            results[key] = activate(client, sid, uid, email).status_code

        t1 = threading.Thread(target=go, args=(c, s1["id"], s1u["id"],
                                               "u1", "admin@example.com"))
        t2 = threading.Thread(target=go, args=(c2, s2["id"], s2u["id"],
                                               "u2", "second@example.com"))
        for t in (t1, t2):
            t.start()
        for t in (t1, t2):
            t.join(timeout=30)
        assert sorted(results.values()) == [200, 200], results
        with open(path, "rb") as fh:
            doc = _json.loads(fh.read())
        assert doc["domains"] == {"a.com": ["ads"], "b.com": ["ads"]}
