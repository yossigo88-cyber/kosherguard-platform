"""API tests for the Milestone 1 auth slice, against bundled PostgreSQL."""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pyotp  # noqa: E402

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


@pytest.fixture()
def app_and_user(engine):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-x")
        s.add(tenant)
        s.flush()
        user = User(tenant_id=tenant.id, email="guardian@example.com",
                    password_hash=security.hash_password(PASSWORD),
                    role=Role.owner)
        s.add(user)
        s.flush()
        uid = user.id
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
              "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    return create_app(settings, engine=engine), uid


def login(client, **kw):
    body = {"email": "guardian@example.com", "password": PASSWORD}
    body.update(kw)
    return client.post("/api/auth/login", json=body, headers=HDR)


class TestAuthAPI:
    def test_health(self, app_and_user):
        app, _ = app_and_user
        assert TestClient(app).get("/health").json() == {"status": "ok"}

    def test_login_logout_me(self, app_and_user):
        app, _ = app_and_user
        c = TestClient(app)
        assert login(c).status_code == 200
        me = c.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["email"] == "guardian@example.com"
        assert me.json()["mfa_enabled"] is False
        cookie = c.cookies.get("kg_session")
        assert cookie
        assert c.post("/api/auth/logout", headers=HDR).status_code == 200
        assert c.get("/api/auth/me").status_code == 401

    def test_cookie_flags(self, app_and_user):
        app, _ = app_and_user
        c = TestClient(app)
        r = login(c)
        header = r.headers["set-cookie"]
        assert "httponly" in header.lower() and "samesite=strict" in header.lower()

    def test_wrong_password_rejected(self, app_and_user):
        app, _ = app_and_user
        c = TestClient(app)
        assert login(c, password="wrong password here").status_code == 401
        assert c.get("/api/auth/me").status_code == 401

    def test_csrf_header_required(self, app_and_user):
        app, _ = app_and_user
        c = TestClient(app)
        r = c.post("/api/auth/login",
                   json={"email": "guardian@example.com",
                         "password": PASSWORD})
        assert r.status_code == 403

    def test_lockout_after_repeated_failures(self, app_and_user):
        app, _ = app_and_user
        c = TestClient(app)
        for _ in range(5):
            login(c, password="wrong password here")
        # Sixth attempt is refused even with the right password.
        assert login(c).status_code == 429

    def test_mfa_required_when_enrolled(self, app_and_user, engine):
        app, uid = app_and_user
        secret = security.new_totp_secret()
        with session_scope(engine) as s:
            s.get(User, uid).totp_secret = secret
        c = TestClient(app)
        assert login(c).status_code == 401  # no code
        assert login(c, totp_code="0000000").status_code == 401  # bad code
        good = pyotp.TOTP(secret).now()
        assert login(c, totp_code=good).status_code == 200
        assert c.get("/api/auth/me").json()["mfa_enabled"] is True

    def test_session_token_not_stored_plain(self, app_and_user, engine):
        app, _ = app_and_user
        c = TestClient(app)
        assert login(c).status_code == 200
        token = c.cookies.get("kg_session")
        with session_scope(engine) as s:
            from sqlalchemy import text
            rows = s.execute(text("SELECT token_hash FROM auth_sessions"))
            hashes = [r[0] for r in rows]
        assert token not in hashes
        assert security.hash_session_token(token) in hashes


class TestFrontEnds:
    def test_website_portal_admin_served(self, app_and_user):
        app, _ = app_and_user
        c = TestClient(app)
        r = c.get("/")
        assert r.status_code == 200 and "KosherGuard" in r.text
        r = c.get("/portal/")
        assert r.status_code == 200 and "Family Portal" in r.text
        r = c.get("/portal/app.js")
        assert r.status_code == 200 and "esc(" in r.text
        r = c.get("/web/")
        assert r.status_code == 200 and "KosherGuard Admin" in r.text
        r = c.get("/web/app.js")
        assert r.status_code == 200 and "esc(" in r.text

    def test_static_traversal_rejected(self, app_and_user):
        app, _ = app_and_user
        c = TestClient(app)
        assert c.get("/portal/../app/main.py").status_code in (400, 404)
        assert c.get("/web/..%2F..%2Fapp%2Fmain.py").status_code in (400, 404)
