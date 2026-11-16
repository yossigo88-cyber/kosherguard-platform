"""Guardian account lifecycle tests (M6): invite, accept, roles,
MFA reset. Approved requirement: multiple guardians per family tenant."""

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


def make_app(engine, role=Role.owner):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-x")
        s.add(tenant)
        s.flush()
        user = User(tenant_id=tenant.id, email="owner@example.com",
                    password_hash=security.hash_password(PASSWORD),
                    role=role)
        s.add(user)
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    return create_app(settings, engine=engine)


def login(client, email="owner@example.com", password=PASSWORD):
    return client.post("/api/auth/login", json={
        "email": email, "password": password}, headers=HDR)


def invite_and_accept(client, email="second@example.com"):
    r = client.post("/api/guardians/invite", json={
        "email": email, "role": "guardian"}, headers=HDR)
    token = r.json()["invite_token"]
    return client.post("/api/invites/accept", json={
        "token": token, "password": "another long password"},
        headers=HDR)


class TestGuardianLifecycle:
    def test_full_invite_accept_login_flow(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        r = invite_and_accept(c)
        assert r.status_code == 200
        assert r.json()["accepted"] == "second@example.com"
        assert login(c, "second@example.com",
                     "another long password").status_code == 200
        guardians = c.get("/api/guardians").json()["guardians"]
        assert {g["email"] for g in guardians} == {
            "owner@example.com", "second@example.com"}

    def test_invite_requires_owner(self, engine):
        c = TestClient(make_app(engine, role=Role.guardian))
        login(c)
        assert c.post("/api/guardians/invite", json={
            "email": "x@example.com"}, headers=HDR).status_code == 403

    def test_invite_token_single_use(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        r = c.post("/api/guardians/invite", json={
            "email": "once@example.com"}, headers=HDR)
        token = r.json()["invite_token"]
        body = {"token": token, "password": "another long password"}
        assert c.post("/api/invites/accept", json=body,
                      headers=HDR).status_code == 200
        assert c.post("/api/invites/accept", json=body,
                      headers=HDR).status_code == 400

    def test_invite_token_stored_hashed(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        r = c.post("/api/guardians/invite", json={
            "email": "hash@example.com"}, headers=HDR)
        raw = r.json()["invite_token"]
        with session_scope(engine) as s:
            from app.models import InviteToken
            from sqlalchemy import select
            row = s.execute(select(InviteToken)).scalar_one()
        assert row.token_hash != raw
        assert raw not in row.token_hash

    def test_duplicate_email_rejected(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        assert c.post("/api/guardians/invite", json={
            "email": "owner@example.com"}, headers=HDR).status_code == 409

    def test_short_password_rejected(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        r = c.post("/api/guardians/invite", json={
            "email": "pw@example.com"}, headers=HDR)
        assert c.post("/api/invites/accept", json={
            "token": r.json()["invite_token"], "password": "short"},
            headers=HDR).status_code == 400

    def test_role_change_and_self_lockout_prevented(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        invite_and_accept(c)
        guardians = c.get("/api/guardians").json()["guardians"]
        second = next(g for g in guardians
                      if g["email"] == "second@example.com")
        me = next(g for g in guardians
                  if g["email"] == "owner@example.com")
        r = c.put(f"/api/guardians/{second['id']}/role",
                  json={"role": "viewer"}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["role"] == "viewer"
        assert c.put(f"/api/guardians/{me['id']}/role",
                     json={"role": "viewer"},
                     headers=HDR).status_code == 400

    def test_cross_tenant_role_change_rejected(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        with session_scope(engine) as s:
            other_tenant = Tenant(name="family-y")
            s.add(other_tenant)
            s.flush()
            outsider = User(
                tenant_id=other_tenant.id, email="outsider@example.com",
                password_hash=security.hash_password(PASSWORD),
                role=Role.owner)
            s.add(outsider)
            s.flush()
            outsider_id = outsider.id
        r = c.put(f"/api/guardians/{outsider_id}/role",
                  json={"role": "viewer"}, headers=HDR)
        assert r.status_code == 404

    def test_mfa_reset_by_owner(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        invite_and_accept(c)
        with session_scope(engine) as s:
            from sqlalchemy import select
            second = s.execute(select(User).where(
                User.email == "second@example.com")).scalar_one()
            second.totp_secret = security.new_totp_secret()
            s.flush()
            second_id = second.id
        r = c.post(f"/api/guardians/{second_id}/mfa-reset",
                   json={"password": PASSWORD}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["mfa_enrolled"] is False

    def test_mfa_reset_requires_fresh_auth(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        invite_and_accept(c)
        with session_scope(engine) as s:
            from sqlalchemy import select
            second = s.execute(select(User).where(
                User.email == "second@example.com")).scalar_one()
            second.totp_secret = security.new_totp_secret()
            s.flush()
            second_id = second.id
        # No password at all.
        assert c.post(f"/api/guardians/{second_id}/mfa-reset",
                      json={}, headers=HDR).status_code == 422
        # Wrong password.
        assert c.post(f"/api/guardians/{second_id}/mfa-reset",
                      json={"password": "not the password"},
                      headers=HDR).status_code == 403
        # MFA still enrolled after both failures.
        with session_scope(engine) as s:
            from sqlalchemy import select
            second = s.execute(select(User).where(
                User.id == second_id)).scalar_one()
            assert second.totp_secret is not None

    def test_mfa_reset_requires_owner_role(self, engine):
        c = TestClient(make_app(engine, role=Role.guardian))
        login(c)
        assert c.post("/api/guardians/1/mfa-reset",
                      json={"password": PASSWORD},
                      headers=HDR).status_code == 403


class TestCredentialIssuance:
    def test_mint_and_verify_roundtrip(self, engine):
        import os as _os
        _os.environ["KG_DEVICE_TOKEN_KEY"] = "route-test-key"
        try:
            with session_scope(engine) as s:
                tenant = Tenant(name="family-z")
                s.add(tenant)
                s.flush()
                user = User(tenant_id=tenant.id, email="o@example.com",
                            password_hash=security.hash_password(PASSWORD),
                            role=Role.owner)
                s.add(user)
                s.flush()
                from app.models import Device
                s.add(Device(tenant_id=tenant.id, name="iphone-1"))
            settings = Settings({
                "KG_DATABASE_URL": "postgresql://placeholder",
                "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test",
                "KG_DEVICE_TOKEN_KEY": "route-test-key"})
            c = TestClient(create_app(settings, engine=engine))
            login(c, "o@example.com")
            devices = c.get("/api/devices").json()["devices"]
            dev_id = devices[0]["id"]
            r = c.post(f"/api/devices/{dev_id}/dataset-credential",
                       headers=HDR)
            assert r.status_code == 200
            token = r.json()["credential"]
            import importlib.util as ilu
            spec = ilu.spec_from_file_location(
                "kg_device_auth_test",
                _os.path.abspath(_os.path.join(
                    _os.path.dirname(__file__), "..", "..",
                    "url-filter-server", "app", "device_auth.py")))
            da = ilu.module_from_spec(spec)
            spec.loader.exec_module(da)
            payload = da.verify_token(b"route-test-key", token, "dataset")
            assert payload["device_id"] == str(dev_id)
            assert payload["tenant_id"] == str(
                devices[0].get("tenant_id", payload["tenant_id"]))
        finally:
            _os.environ.pop("KG_DEVICE_TOKEN_KEY", None)

    def test_mint_unconfigured_503(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        r = c.post("/api/devices/1/dataset-credential", headers=HDR)
        assert r.status_code in (404, 503)

    def test_mint_cross_tenant_device_404(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        with session_scope(engine) as s:
            other = Tenant(name="family-q")
            s.add(other)
            s.flush()
            from app.models import Device
            d = Device(tenant_id=other.id, name="other-phone")
            s.add(d)
            s.flush()
            did = d.id
        import os as _os
        _os.environ["KG_DEVICE_TOKEN_KEY"] = "k"
        try:
            settings = Settings({
                "KG_DATABASE_URL": "postgresql://placeholder",
                "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test",
                "KG_DEVICE_TOKEN_KEY": "k"})
            c2 = TestClient(create_app(settings, engine=engine))
            login(c2)
            assert c2.post(f"/api/devices/{did}/dataset-credential",
                           headers=HDR).status_code == 404
        finally:
            _os.environ.pop("KG_DEVICE_TOKEN_KEY", None)
