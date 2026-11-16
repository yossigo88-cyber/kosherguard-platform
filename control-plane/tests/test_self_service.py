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

    def test_other_sessions_invalidated_on_change(self, client):
        c2 = TestClient(client.app)
        assert c2.post("/api/auth/login",
                       json={"email": "o@example.com", "password": PASSWORD},
                       headers=HDR).status_code == 200
        r = client.post("/api/auth/password-change",
                        json={"current_password": PASSWORD,
                              "new_password": NEW_PASSWORD},
                        headers=HDR)
        assert r.status_code == 200
        assert r.json()["other_sessions_invalidated"] == 1
        # the other session is dead; the changing session survives
        assert c2.get("/api/auth/me").status_code == 401
        assert client.get("/api/auth/me").status_code == 200

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
            assert "other_sessions_invalidated=" in rows[0].detail


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
                        json={"code": code, "password": "wrong wrong wrong"},
                        headers=HDR)
        assert r.status_code == 403

    def test_confirm_rejects_bad_code(self, client):
        self._start(client)
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"code": "000000", "password": PASSWORD},
                        headers=HDR)
        assert r.status_code in (400, 403)  # 000000 may rarely be valid

    def test_confirm_without_start_400(self, client):
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"code": "123456", "password": PASSWORD},
                        headers=HDR)
        assert r.status_code == 400

    def test_client_cannot_substitute_secret(self, client, engine):
        """The confirm route takes no secret: the server-stored pending
        secret is used. A code valid for an attacker-chosen secret but
        not for the pending one is rejected."""
        self._start(client)  # real pending secret stored server-side
        attacker_secret = pyotp.random_base32()
        attacker_code = pyotp.TOTP(attacker_secret).now()
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"code": attacker_code, "password": PASSWORD},
                        headers=HDR)
        assert r.status_code == 400

    def test_expired_pending_rejected_and_cleared(self, client, engine):
        from datetime import timedelta
        from app.models import PendingMfaEnrollment, utcnow
        self._start(client)
        with session_scope(engine) as s:
            from sqlalchemy import select
            row = s.execute(select(PendingMfaEnrollment)).scalar_one()
            row.expires_at = utcnow() - timedelta(minutes=1)
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"code": "123456", "password": PASSWORD},
                        headers=HDR)
        assert r.status_code == 400
        assert "expired" in r.json()["error"]
        with session_scope(engine) as s:
            from sqlalchemy import select
            assert s.execute(
                select(PendingMfaEnrollment)).scalar_one_or_none() is None

    def test_restart_replaces_pending(self, client):
        first = self._start(client)["secret"]
        second = self._start(client)["secret"]
        assert first != second
        # old code no longer works; new one does
        assert client.post("/api/auth/mfa/enroll-confirm",
                           json={"code": pyotp.TOTP(first).now(),
                                 "password": PASSWORD},
                           headers=HDR).status_code == 400
        assert client.post("/api/auth/mfa/enroll-confirm",
                           json={"code": pyotp.TOTP(second).now(),
                                 "password": PASSWORD},
                           headers=HDR).status_code == 200

    def test_pending_bound_to_user(self, client, engine):
        """Another user's pending row cannot satisfy this user's
        confirm: confirm consumes only the caller's own pending row."""
        from app.models import PendingMfaEnrollment
        other_secret = pyotp.random_base32()
        with session_scope(engine) as s:
            from sqlalchemy import select
            tenant = s.execute(select(Tenant)).scalar_one()
            other = User(tenant_id=tenant.id, email="x@example.com",
                         password_hash=security.hash_password(PASSWORD),
                         role=Role.viewer)
            s.add(other)
            s.flush()
            from app.models import utcnow
            from datetime import timedelta
            s.add(PendingMfaEnrollment(
                user_id=other.id, secret=other_secret,
                expires_at=utcnow() + timedelta(minutes=10)))
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"code": pyotp.TOTP(other_secret).now(),
                              "password": PASSWORD},
                        headers=HDR)
        assert r.status_code == 400  # caller has no pending row

    def test_full_enrollment_then_login_requires_totp(self, client):
        secret = self._start(client)["secret"]
        code = pyotp.TOTP(secret).now()
        r = client.post("/api/auth/mfa/enroll-confirm",
                        json={"code": code, "password": PASSWORD},
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

    def test_pending_secret_not_promoted_before_confirm(self, client,
                                                        engine):
        self._start(client)
        with session_scope(engine) as s:
            from sqlalchemy import select
            u = s.execute(select(User).where(
                User.email == "o@example.com")).scalar_one()
            assert u.totp_secret is None  # pending row only, not promoted


class TestAuditLogViewer:
    def test_events_visible_newest_first(self, client):
        client.post("/api/auth/password-change",
                    json={"current_password": PASSWORD,
                          "new_password": NEW_PASSWORD},
                    headers=HDR)
        r = client.get("/api/audit-logs")
        assert r.status_code == 200
        events = r.json()["events"]
        assert len(events) >= 1
        assert events[0]["action"] == "auth.password_change"
        assert events[0]["actor"] == "o@example.com"
        ids = [e["id"] for e in events]
        assert ids == sorted(ids, reverse=True)

    def test_tenant_isolation(self, client, engine):
        client.post("/api/auth/password-change",
                    json={"current_password": PASSWORD,
                          "new_password": NEW_PASSWORD},
                    headers=HDR)
        # a second tenant with its own user sees none of tenant one's events
        with session_scope(engine) as s:
            t2 = Tenant(name="family-other")
            s.add(t2)
            s.flush()
            s.add(User(tenant_id=t2.id, email="p@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        c2 = TestClient(client.app)
        assert c2.post("/api/auth/login",
                       json={"email": "p@example.com",
                             "password": PASSWORD},
                       headers=HDR).status_code == 200
        r = c2.get("/api/audit-logs")
        assert r.status_code == 200
        assert all(e["action"] != "auth.password_change"
                   for e in r.json()["events"])

    def test_viewer_can_read(self, client, engine):
        with session_scope(engine) as s:
            from sqlalchemy import select
            tenant = s.execute(select(Tenant).where(
                Tenant.name == "family-ss")).scalar_one()
            s.add(User(tenant_id=tenant.id, email="v@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.viewer))
        c2 = TestClient(client.app)
        assert c2.post("/api/auth/login",
                       json={"email": "v@example.com",
                             "password": PASSWORD},
                       headers=HDR).status_code == 200
        assert c2.get("/api/audit-logs").status_code == 200

    def test_signed_out_401(self, engine):
        settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                             "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
        c = TestClient(create_app(settings, engine=engine))
        assert c.get("/api/audit-logs").status_code == 401
