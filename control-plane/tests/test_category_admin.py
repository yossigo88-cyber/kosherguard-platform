"""Platform category-dataset administration tests (M6).

Approved fallback for the commercial category feed: a human-reviewed
seed dataset with provenance, managed by platform admins only.
"""

import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_app(engine, is_admin):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-x")
        s.add(tenant)
        s.flush()
        user = User(tenant_id=tenant.id, email="guardian@example.com",
                    password_hash=security.hash_password(PASSWORD),
                    role=Role.owner, is_platform_admin=is_admin,
                    staff_role="owner" if is_admin else None)
        s.add(user)
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    return create_app(settings, engine=engine)


def login(client):
    return mfa_login(client, json={'email': 'guardian@example.com', 'password': PASSWORD}, headers=HDR)


class TestCategoryAdmin:
    def test_non_admin_forbidden(self, engine):
        c = TestClient(make_app(engine, is_admin=False))
        login(c)
        assert c.get("/api/admin/categories").status_code == 403
        r = c.post("/api/admin/categories", json={
            "domain": "bet365.com", "category": "gambling"}, headers=HDR)
        assert r.status_code == 403

    def test_unauthenticated_rejected(self, engine):
        c = TestClient(make_app(engine, is_admin=True))
        assert c.get("/api/admin/categories").status_code in (401, 403)

    def test_add_list_export(self, engine):
        c = TestClient(make_app(engine, is_admin=True))
        login(c)
        r = c.post("/api/admin/categories", json={
            "domain": "Bet365.COM.", "category": "gambling",
            "source": "manual-review-2026-11"}, headers=HDR)
        assert r.status_code == 200
        body = r.json()
        assert body["domain"] == "bet365.com"  # normalized
        assert body["source"] == "manual-review-2026-11"
        assert body["active"] is True

        listing = c.get("/api/admin/categories").json()["rules"]
        assert [r_["domain"] for r_ in listing] == ["bet365.com"]

        exported = c.get("/api/admin/categories/export").json()
        assert exported["version"] == 1
        assert exported["rules"] == [{
            "domain": "bet365.com", "category": "gambling",
            "verdict": "block", "source": "manual-review-2026-11"}]

    def test_duplicate_active_rule_conflict(self, engine):
        c = TestClient(make_app(engine, is_admin=True))
        login(c)
        payload = {"domain": "x.example", "category": "adult"}
        assert c.post("/api/admin/categories", json=payload,
                      headers=HDR).status_code == 200
        assert c.post("/api/admin/categories", json=payload,
                      headers=HDR).status_code == 409

    def test_deactivate_then_reactivate_preserves_history(self, engine):
        c = TestClient(make_app(engine, is_admin=True))
        login(c)
        r = c.post("/api/admin/categories", json={
            "domain": "y.example", "category": "adult"}, headers=HDR)
        rule_id = r.json()["id"]
        d = c.delete(f"/api/admin/categories/{rule_id}", headers=HDR)
        assert d.status_code == 200
        assert d.json()["active"] is False
        assert d.json()["deactivated_at"] is not None
        # Export excludes inactive.
        assert c.get("/api/admin/categories/export").json()["rules"] == []
        # Reactivation updates the assignment in place.
        r2 = c.post("/api/admin/categories", json={
            "domain": "y.example", "category": "gambling",
            "verdict": "allow"}, headers=HDR)
        assert r2.status_code == 200
        assert r2.json()["category"] == "gambling"
        assert r2.json()["verdict"] == "allow"

    def test_invalid_inputs_rejected(self, engine):
        c = TestClient(make_app(engine, is_admin=True))
        login(c)
        for bad in ({"domain": "", "category": "x"},
                    {"domain": "has space.com", "category": "x"},
                    {"domain": "a.com/path", "category": "x"},
                    {"domain": "ok.com", "category": "x",
                     "verdict": "maybe"}):
            assert c.post("/api/admin/categories", json=bad,
                          headers=HDR).status_code == 400

    def test_audit_trail_recorded(self, engine):
        c = TestClient(make_app(engine, is_admin=True))
        login(c)
        c.post("/api/admin/categories", json={
            "domain": "audit.example", "category": "adult"}, headers=HDR)
        with session_scope(engine) as s:
            from app.models import AuditEvent
            from sqlalchemy import select
            actions = [a.action for a in s.execute(
                select(AuditEvent)).scalars().all()]
        assert "admin.category.upsert" in actions

from mfa_support import mfa_login
