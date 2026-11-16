"""Milestone 1 control-plane foundation tests, run against a real
bundled PostgreSQL so SQL behavior matches production."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import db as db_module  # noqa: E402
from app import security  # noqa: E402
from app.config import ConfigError, Settings  # noqa: E402
from app.models import Role, Tenant  # noqa: E402


def make_tenant(engine, name):
    with db_module.session_scope(engine) as s:
        t = Tenant(name=name)
        s.add(t)
        s.flush()
        return t.id


class TestSecurity:
    def test_password_roundtrip(self):
        stored = security.hash_password("correct horse battery")
        assert security.verify_password("correct horse battery", stored)
        assert not security.verify_password("wrong", stored)

    def test_password_rejects_garbage(self):
        assert not security.verify_password("x", "not-a-hash")
        assert not security.verify_password("x", "md5$1$aa$bb")

    def test_password_never_stored_plain(self):
        stored = security.hash_password("a long secret value")
        assert "a long secret value" not in stored

    def test_session_tokens_hashed(self):
        token = security.new_session_token()
        digest = security.hash_session_token(token)
        assert token != digest and len(digest) == 64

    def test_totp_roundtrip(self):
        import pyotp
        secret = security.new_totp_secret()
        code = pyotp.TOTP(secret).now()
        assert security.verify_totp(secret, code)
        assert not security.verify_totp(secret, "0000000")


class TestConfig:
    def test_database_url_required(self):
        with pytest.raises(ConfigError):
            Settings({})

    def test_ambiguous_flag_rejected(self):
        with pytest.raises(ConfigError):
            Settings({"KG_DATABASE_URL": "postgresql://x",
                      "KG_SECURE_COOKIES": "maybe"})


class TestTenantIsolation:
    def test_scoped_reads_are_pinned(self, engine):
        a = make_tenant(engine, "family-a")
        b = make_tenant(engine, "family-b")
        with db_module.session_scope(engine) as s:
            db_module.ScopedSession(s, a).add_user(
                "a@example.com", security.hash_password("password-a-long"),
                Role.owner)
        with db_module.session_scope(engine) as s:
            scoped_b = db_module.ScopedSession(s, b)
            assert scoped_b.users() == []

    def test_cross_tenant_get_refused(self, engine):
        a = make_tenant(engine, "family-a2")
        b = make_tenant(engine, "family-b2")
        with db_module.session_scope(engine) as s:
            user = db_module.ScopedSession(s, a).add_user(
                "a2@example.com", security.hash_password("password-a-long"),
                Role.owner)
            uid = user.id
        with db_module.session_scope(engine) as s:
            with pytest.raises(db_module.TenantIsolationError):
                db_module.ScopedSession(s, b).get_user(uid)

    def test_audit_events_scoped(self, engine):
        a = make_tenant(engine, "family-a3")
        b = make_tenant(engine, "family-b3")
        with db_module.session_scope(engine) as s:
            db_module.ScopedSession(s, a).audit("user.create", "made a")
        with db_module.session_scope(engine) as s:
            assert len(db_module.ScopedSession(s, a).audit_events()) == 1
            assert db_module.ScopedSession(s, b).audit_events() == []
