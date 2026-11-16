"""Account self-service tests: password change + MFA enrollment.

Both flows require fresh authentication (the current password), so an
unattended session alone cannot take over or lock out an account. The
MFA pending secret is never persisted before confirmation.
"""

import os
import sys

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

PASSWORD = "a long enough password"
NEW_PASSWORD = "an even longer new password"
HDR = {"X-KosherGuard-Request": "1"}


@pytest.fixture()
def client(engine):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-ss")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="o@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    c = TestClient(create_app(settings, engine=engine))
    r = c.post("/api/auth/login",
               json={"email": "o@example.com", "password": PASSWORD},
               headers=HDR)
    assert r.status_code == 200
    return c


class TestPasswordChange:
    def test_change_roundtrip(self, client, engine):
        r = client.post("/api/auth/password-change",
                        json={"current_password": PASSWORD,
                              "new_password": NEW_PASSWORD},
                        headers=HDR)
        assert r.status_code == 200
        assert r.json()["changed"] is True
        # old password no longer logs in; new one does
        c2 = TestClient(client.app)
        assert c2.post("/api/auth/login",
                       json={"email": "o@example.com",
                             "password": PASSWORD},
                       headers=HDR).status_code != 200
        assert c2.post("/api/auth/login",
                       json={"email": "o@example.com",
                             "password": NEW_PASSWORD},
                       headers=HDR).status_code == 200

    def test_wrong_current_password_403(self, client):
        r = client.post("/api/auth/password-change",
                        json={"current_password": "wrong wrong wrong",
                              "new_password": NEW_PASSWORD},
                        headers=HDR)
        assert r.status_code == 403

    def test_short_new_password_400(self, client):
        r = client.post("/api/auth/password-change",
                        json={"current_password": PASSWORD,
                              "new_password": "short"},
                        headers=HDR)
        assert r.status_code == 400

    def test_audit_written(self, client, engine):
        client.post("/api/auth/password-change",
                    json={"current_password": PASSWORD,
                          "new_password": NEW_PASSWORD},
                    headers=HDR)
        from app.models import AuditEvent
        with session_scope(engine) as s:
            from sqlalchemy import select
            rows = s.execute(select(AuditEvent).where(
                AuditEvent.action == "auth.password_change")).scalars().all()
            assert len(rows) == 1


class TestMfaEnrollment:
    def _start(self, client):
        r = client.post("/api/auth/mfa/enroll-start", headers=HDR)
        assert r.status_code == 200
        return r.json()

    def test_start_returns_secret_and_uri(self, client):
        body = self._start(client)
        assert body["secret"]
        assert body["provisioning_uri"].startswith("otpauth://totp/")
        assert "KosherGuard" in body["provisioning_uri"]

    def test_confirm_requires_fresh_password(self, client):
        secret = self._start(client)["secret"]
        code = pyotp.TOTP(secret).now()
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"secret": secret, "code": code,
                              "password": "wrong wrong wrong"},
                        headers=HDR)
        assert r.status_code == 403

    def test_confirm_rejects_bad_code(self, client):
        secret = self._start(client)["secret"]
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"secret": secret, "code": "000000",
                              "password": PASSWORD},
                        headers=HDR)
        assert r.status_code in (400, 403)  # 000000 may rarely be valid

    def test_full_enrollment_then_login_requires_totp(self, client):
        secret = self._start(client)["secret"]
        code = pyotp.TOTP(secret).now()
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"secret": secret, "code": code,
                              "password": PASSWORD},
                        headers=HDR)
        assert r.status_code == 200
        assert r.json()["mfa_enabled"] is True
        c2 = TestClient(client.app)
        # password alone no longer suffices
        assert c2.post("/api/auth/login",
                       json={"email": "o@example.com",
                             "password": PASSWORD},
                       headers=HDR).status_code != 200
        # password + code works
        r2 = c2.post("/api/auth/login",
                     json={"email": "o@example.com", "password": PASSWORD,
                           "totp_code": pyotp.TOTP(secret).now()},
                     headers=HDR)
        assert r2.status_code == 200
        # double enrollment refused
        assert client.post("/api/auth/mfa/enroll-start",
                           headers=HDR).status_code == 409

    def test_pending_secret_not_persisted_before_confirm(self, client,
                                                         engine):
        self._start(client)
        with session_scope(engine) as s:
            from sqlalchemy import select
            u = s.execute(select(User).where(
                User.email == "o@example.com")).scalar_one()
            assert u.totp_secret is None
