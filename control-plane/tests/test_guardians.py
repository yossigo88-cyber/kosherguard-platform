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


class TestOverviewAndTenants:
    def test_overview_own_tenant_only(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        invite_and_accept(c)
        body = c.get("/api/overview").json()
        assert body["guardians"] == 2
        assert body["devices"] == 0
        actions = [a["action"] for a in body["recent_activity"]]
        assert "guardian.invite" in actions

    def test_overview_excludes_other_tenants(self, engine):
        c = TestClient(make_app(engine))
        login(c)
        with session_scope(engine) as s:
            other = Tenant(name="family-y")
            s.add(other)
            s.flush()
            s.add(User(tenant_id=other.id, email="o@y.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
            from app.models import Device
            s.add(Device(tenant_id=other.id, name="other-phone"))
        body = c.get("/api/overview").json()
        assert body["devices"] == 0
        assert body["guardians"] == 1

    def test_admin_tenants_platform_admin_only(self, engine):
        c = TestClient(make_app(engine))  # not platform admin
        login(c)
        assert c.get("/api/admin/tenants").status_code == 403

    def test_admin_tenants_lists_counts(self, engine):
        with session_scope(engine) as s:
            t = Tenant(name="fam-a")
            s.add(t); s.flush()
            s.add(User(tenant_id=t.id, email="admin@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner, is_platform_admin=True))
            t2 = Tenant(name="fam-b")
            s.add(t2); s.flush()
            s.add(User(tenant_id=t2.id, email="b@b.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
            from app.models import Device
            s.add(Device(tenant_id=t2.id, name="b-phone"))
        settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                             "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
        c = TestClient(create_app(settings, engine=engine))
        login(c, "admin@example.com")
        body = c.get("/api/admin/tenants").json()["tenants"]
        by_name = {t["name"]: t for t in body}
        assert by_name["fam-b"]["devices"] == 1
        assert by_name["fam-a"]["guardians"] == 1


class TestProxyScopeMinting:
    """8B issuance: proxy-scoped tokens are bound to the device's
    effective policy (active assignment, else tenant default)."""

    def _app_with_device(self, engine, with_policy=False, assigned=False):
        with session_scope(engine) as s:
            tenant = Tenant(name="family-proxy")
            s.add(tenant)
            s.flush()
            s.add(User(tenant_id=tenant.id, email="p@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
            from app.models import Device, Policy, DeviceAssignment, PublicationState
            dev = Device(tenant_id=tenant.id, name="kid-phone")
            s.add(dev)
            s.flush()
            pid = None
            if with_policy:
                import json as _json
                pol = Policy(tenant_id=tenant.id, name="base",
                             engine_doc=_json.dumps({
                                 "default_policy": "allow",
                                 "blocklist": ["bad.example"],
                                 "allowlist": [], "category_allow": [],
                                 "category_block": []}))
                s.add(pol)
                s.flush()
                pid = pol.id
                if assigned:
                    s.add(DeviceAssignment(tenant_id=tenant.id,
                                           device_id=dev.id,
                                           policy_id=pid, active=True))
                else:
                    s.add(PublicationState(tenant_id=tenant.id,
                                           selected_policy_id=pid))
            s.flush()
            did = dev.id
        settings = Settings({
            "KG_DATABASE_URL": "postgresql://placeholder",
            "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test",
            "KG_DEVICE_TOKEN_KEY": "proxy-mint-key"})
        c = TestClient(create_app(settings, engine=engine))
        login(c, "p@example.com")
        return c, did, pid

    def _verify(self, token, scope, policy_id=None):
        import importlib.util as ilu
        spec = ilu.spec_from_file_location(
            "kg_device_auth_test2",
            os.path.abspath(os.path.join(
                os.path.dirname(__file__), "..", "..",
                "url-filter-server", "app", "device_auth.py")))
        da = ilu.module_from_spec(spec)
        spec.loader.exec_module(da)
        return da.verify_token(b"proxy-mint-key", token, scope,
                               required_policy_id=policy_id)

    def test_proxy_scope_binds_assigned_policy(self, engine):
        c, did, pid = self._app_with_device(
            engine, with_policy=True, assigned=True)
        r = c.post(f"/api/devices/{did}/dataset-credential",
                   json={"scope": "proxy"}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["scope"] == "proxy"
        assert r.json()["policy_id"] == pid
        payload = self._verify(r.json()["credential"], "proxy", pid)
        assert payload["policy_id"] == pid

    def test_proxy_scope_binds_tenant_default(self, engine):
        c, did, pid = self._app_with_device(
            engine, with_policy=True, assigned=False)
        r = c.post(f"/api/devices/{did}/dataset-credential",
                   json={"scope": "proxy"}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["policy_id"] == pid
        self._verify(r.json()["credential"], "proxy", pid)

    def test_proxy_scope_without_policy_409(self, engine):
        c, did, _ = self._app_with_device(engine, with_policy=False)
        r = c.post(f"/api/devices/{did}/dataset-credential",
                   json={"scope": "proxy"}, headers=HDR)
        assert r.status_code == 409

    def test_dataset_scope_unchanged_default(self, engine):
        c, did, _ = self._app_with_device(engine, with_policy=True,
                                          assigned=True)
        r = c.post(f"/api/devices/{did}/dataset-credential", headers=HDR)
        assert r.status_code == 200
        assert r.json()["scope"] == "dataset"
        assert r.json()["policy_id"] is None
        payload = self._verify(r.json()["credential"], "dataset")
        assert "policy_id" not in payload

    def test_bad_scope_400(self, engine):
        c, did, _ = self._app_with_device(engine)
        r = c.post(f"/api/devices/{did}/dataset-credential",
                   json={"scope": "admin"}, headers=HDR)
        assert r.status_code == 400
