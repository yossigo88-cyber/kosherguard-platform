"""Answer 22 tests: category source registry - provenance, versioned
imports with hashes, manual review activation, rollback, history.
"""

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
from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
HASH1 = "a" * 64
HASH2 = "b" * 64


def make_client(engine, staff=True, email="admin@example.com"):
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
    c = TestClient(create_app(Settings(env), engine=engine))
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


def mk_import(client, source_id, version="2024-01", sha=HASH1,
              rules=None):
    if rules is None:
        rules = [{"domain": "bet365.com", "category": "gambling",
                  "verdict": "block"}]
    r = client.post(f"/api/admin/category-sources/{source_id}/imports",
                    json={"version": version, "sha256": sha,
                          "category_mapping": {"gambling": "gambling"},
                          "rules": rules},
                    headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


def activate(client, source_id, update_id):
    return client.post(
        f"/api/admin/category-sources/{source_id}/activate",
        json={"update_id": update_id,
              "totp_code": fresh_code(client),
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
        assert update["sha256"] == HASH1
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
        u1 = mk_import(c, source["id"], version="2024-01", sha=HASH1,
                       rules=[{"domain": "old.com", "category": "ads"}])
        u2 = mk_import(c, source["id"], version="2024-02", sha=HASH2,
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
        u1 = mk_import(c, source["id"], version="2024-01", sha=HASH1)
        u2 = mk_import(c, source["id"], version="2024-02", sha=HASH2)
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
        u1 = mk_import(c, source["id"], version="2024-01", sha=HASH1)
        assert activate(c, source["id"], u1["id"]).status_code == 200
        r = activate(c, source["id"], u1["id"])
        assert r.status_code == 409
