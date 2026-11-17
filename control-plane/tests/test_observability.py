"""M6 observability: deep health, JSON request logging, staff-only metrics."""

import json
import logging
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
from app.models import Role, StaffRole, Tenant, User  # noqa: E402
from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_client(engine, email="staff@example.com", role=Role.viewer,
                staff_role=StaffRole.support_admin):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-o")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=role, staff_role=staff_role))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
    c = TestClient(create_app(Settings(env), engine=engine))
    r = mfa_login(c, json={"email": email, "password": PASSWORD},
                  headers=HDR)
    assert r.status_code == 200, r.text
    return c


def test_health_depth_ok(engine):
    c = make_client(engine)
    r = c.get("/health/depth")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["checks"]["database"] == "ok"
    # Liveness stays cheap and unauthenticated.
    assert c.get("/health").json() == {"status": "ok"}


def test_health_depth_degraded_when_db_down(engine, monkeypatch):
    c = make_client(engine)
    from sqlalchemy.orm import Session as _S
    monkeypatch.setattr(_S, "execute",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("db down")))
    r = c.get("/health/depth")
    assert r.status_code == 503
    assert r.json()["status"] == "degraded"
    assert r.json()["checks"]["database"] == "fail"


def test_request_log_json_line_without_secrets(engine, caplog):
    c = make_client(engine)
    with caplog.at_level(logging.INFO, logger="kosherguard.requests"):
        c.get("/api/auth/me")
    lines = [rec.getMessage() for rec in caplog.records
             if rec.name == "kosherguard.requests"]
    assert lines, "expected a structured request log line"
    entry = json.loads(lines[-1])
    assert entry["method"] == "GET"
    assert entry["route"] == "/api/auth/me"
    assert entry["status"] == 200
    assert "duration_ms" in entry and "ts" in entry
    blob = " ".join(lines).lower()
    for forbidden in ("password", "authorization", "cookie",
                      "staff@example.com", "totp"):
        assert forbidden not in blob


def test_metrics_require_auth_and_staff(engine):
    c = make_client(engine)
    # Unauthenticated: no metrics.
    anon = TestClient(c.app)
    r = anon.get("/metrics")
    assert r.status_code in (401, 403)
    # Authenticated non-staff family user: no metrics.
    with session_scope(engine) as s:
        t = s.query(Tenant).first()
        s.add(User(tenant_id=t.id, email="parent@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    r = mfa_login(c, json={"email": "parent@example.com",
                           "password": PASSWORD}, headers=HDR)
    assert r.status_code == 200
    assert c.get("/metrics").status_code == 403


def test_metrics_render_prometheus_counters(engine):
    c = make_client(engine)
    # Log back in as staff (previous test's login may have switched the
    # session): create a fresh staff session on a second client.
    staff = make_client(engine, email="ops@example.com")
    staff.get("/api/auth/me")
    r = staff.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert "http_requests_total{" in body
    assert 'route="/api/auth/me"' in body
    assert 'status="200"' in body
    # Concrete IDs never become label values (cardinality + privacy).
    assert "parent@example.com" not in body
