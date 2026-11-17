"""Answers 31/33/34 tests: inventory minimization, invitation-only
registration, and support channels.
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


def make_client(engine, email="owner@example.com", role=Role.owner,
                staff_role=None):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-s")
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


def fresh_code(client, email):
    known = getattr(client.app.state, "_fixture_mfa", {})
    return pyotp.TOTP(known[email]).now()


def mk_request(client, kind="general", subject="help", channel="in_product"):
    r = client.post("/api/support/requests",
                    json={"kind": kind, "subject": subject,
                          "body": "details here", "channel": channel},
                    headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


class TestSupportRequests:
    def test_create_and_list_kinds(self, engine):
        c = make_client(engine)
        for kind in ("account_recovery", "enrollment_assistance",
                     "connectivity_troubleshooting", "policy_change",
                     "general"):
            got = mk_request(c, kind=kind)
            assert got["kind"] == kind
            assert got["status"] == "open"
        listing = c.get("/api/support/requests").json()["requests"]
        assert len(listing) == 5

    def test_invalid_kind_rejected(self, engine):
        c = make_client(engine)
        r = client_post = c.post("/api/support/requests",
                                 json={"kind": "delete_protection",
                                       "subject": "x", "body": "y"},
                                 headers=HDR)
        assert r.status_code == 400

    def test_email_channel_is_metadata_only(self, engine):
        """The verified-email support channel is recorded as metadata;
        no outbound delivery is claimed."""
        c = make_client(engine)
        got = mk_request(c, channel="email")
        assert got["channel"] == "email"
        r = c.post("/api/support/requests",
                   json={"kind": "general", "subject": "x", "body": "y",
                         "channel": "sms"}, headers=HDR)
        assert r.status_code == 400

    def test_viewer_sees_only_own(self, engine):
        owner = make_client(engine)
        mk_request(owner, subject="owner ticket")
        viewer = make_client(engine, email="v@example.com",
                             role=Role.viewer)
        with session_scope(engine) as s:
            t = s.scalars(__import__("sqlalchemy").select(Tenant)).first()
            u = s.scalars(__import__("sqlalchemy").select(User).where(
                User.email == "v@example.com")).first()
            u.tenant_id = t.id
        listing = viewer.get("/api/support/requests").json()["requests"]
        assert listing == []
        mk_request(viewer, subject="viewer ticket")
        listing = viewer.get("/api/support/requests").json()["requests"]
        assert [r["subject"] for r in listing] == ["viewer ticket"]

    def test_staff_advance_and_escalate(self, engine):
        owner = make_client(engine)
        ticket = mk_request(owner, kind="policy_change",
                            subject="allow example.com")
        staff = make_client(engine, email="s@example.com",
                            staff_role="support_admin")
        listing = staff.get("/api/admin/support/requests").json()[
            "requests"]
        assert len(listing) == 1
        rid = ticket["id"]
        r = staff.post(f"/api/admin/support/requests/{rid}/advance",
                       json={}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["status"] == "in_progress"
        # Resolving requires notes.
        r = staff.post(f"/api/admin/support/requests/{rid}/advance",
                       json={}, headers=HDR)
        assert r.status_code == 400
        r = staff.post(f"/api/admin/support/requests/{rid}/advance",
                       json={"notes": "forwarded to guardian"},
                       headers=HDR)
        assert r.json()["status"] == "resolved"
        r = staff.post(f"/api/admin/support/requests/{rid}/escalate",
                       json={"notes": "needs owner review"}, headers=HDR)
        assert r.json()["escalated"] is True
        r = staff.post(f"/api/admin/support/requests/{rid}/advance",
                       json={}, headers=HDR)
        assert r.json()["status"] == "closed"
        r = staff.post(f"/api/admin/support/requests/{rid}/advance",
                       json={}, headers=HDR)
        assert r.status_code == 409

    def test_non_staff_cannot_admin(self, engine):
        c = make_client(engine)
        ticket = mk_request(c)
        assert c.get("/api/admin/support/requests").status_code == 403
        r = c.post(f"/api/admin/support/requests/{ticket['id']}/advance",
                   json={}, headers=HDR)
        assert r.status_code == 403

    def test_support_never_touches_protection(self, engine):
        """A policy_change request end-to-end (create, advance,
        escalate, resolve) changes no policy rows and issues no MDM
        commands."""
        from sqlalchemy import func, select as sa_select
        from app.models import MDMCommand, Policy, PolicyVersion
        c = make_client(engine)
        staff = make_client(engine, email="s@example.com",
                            staff_role="support_admin")
        ticket = mk_request(c, kind="policy_change",
                            subject="weaken the baseline")
        rid = ticket["id"]
        staff.post(f"/api/admin/support/requests/{rid}/advance",
                   json={}, headers=HDR)
        staff.post(f"/api/admin/support/requests/{rid}/escalate",
                   json={"notes": "x"}, headers=HDR)
        staff.post(f"/api/admin/support/requests/{rid}/advance",
                   json={"notes": "done"}, headers=HDR)
        with session_scope(engine) as s:
            assert s.scalar(sa_select(func.count()).select_from(
                Policy)) == 0
            assert s.scalar(sa_select(func.count()).select_from(
                PolicyVersion)) == 0
            assert s.scalar(sa_select(func.count()).select_from(
                MDMCommand)) == 0


class TestInventoryMinimization:
    def test_inventory_models_collect_only_necessary_fields(self):
        """Answer 31: no device location or expanded personal app
        inventory is stored anywhere in the inventory models."""
        from app.models import (DDMStatusReport, Device,
                                DeviceAppPolicy, MDMEnrollment)
        forbidden = {"location", "latitude", "longitude", "altitude",
                     "gps", "installed_apps", "app_inventory",
                     "personal_apps"}
        for model in (Device, MDMEnrollment, DDMStatusReport,
                      DeviceAppPolicy):
            cols = {c.name for c in model.__table__.columns}
            assert not (cols & forbidden), (
                f"{model.__tablename__} collects {cols & forbidden}")

    def test_status_report_drops_unsolicited_sensitive_keys(
            self, engine):
        """A device (or impersonator) sending location or personal-app
        content in a status report must not get it persisted or
        logged: only the minimized declaration receipt is stored."""
        import json
        from app import ddm_ops
        from app.models import (DDMStatusReport, Device, MDMEnrollment)
        with session_scope(engine) as s:
            tenant = Tenant(name="fam-min")
            s.add(tenant)
            s.flush()
            dev = Device(tenant_id=tenant.id, name="iphone-2")
            s.add(dev)
            s.flush()
            enr = MDMEnrollment(tenant_id=tenant.id, device_id=dev.id,
                                enrollment_id="UDID-2",
                                device_udid="UDID-2", state="enrolled")
            s.add(enr)
            s.flush()
            report = {
                "StatusItems": {"management": {"declarations": {
                    "configurations": [
                        {"identifier": "cfg-1",
                         "server-token": "tok-1", "active": True,
                         "valid": "valid"}]}}},
                "DeviceLocation": {"latitude": 40.1,
                                   "longitude": -74.1},
                "InstalledAppList": [{"name": "personal-app"}],
                "StatusResponses": {"anything": "unexpected"},
            }
            ddm_ops.record_status(s, enr, json.dumps(report).encode())
            stored = s.scalars(__import__("sqlalchemy").select(
                DDMStatusReport)).first()
        blob = stored.body.lower()
        assert "latitude" not in blob
        assert "personal-app" not in blob
        assert "unexpected" not in blob
        # The declaration receipt survives intact.
        states = json.loads(stored.declaration_states)
        assert states == {"cfg-1": {"server_token": "tok-1",
                                    "active": True, "valid": "valid",
                                    "reasons": None}}

    def test_served_declarations_request_no_location_or_app_list(
            self, engine):
        """The DDM declarations served to devices never request
        location or an installed-app list."""
        import json
        from app import ddm_ops
        from app.models import Device, MDMEnrollment
        with session_scope(engine) as s:
            tenant = Tenant(name="fam-inv")
            s.add(tenant)
            s.flush()
            dev = Device(tenant_id=tenant.id, name="iphone-1")
            s.add(dev)
            s.flush()
            enr = MDMEnrollment(tenant_id=tenant.id, device_id=dev.id,
                                enrollment_id="UDID-1",
                                device_udid="UDID-1", state="enrolled")
            s.add(enr)
            s.flush()
            decls = ddm_ops.configurations(s, enr)
        blob = json.dumps(decls).lower()
        assert "location" not in blob
        assert "installedapplist" not in blob


class TestInvitationOnly:
    def test_no_public_signup_route(self, engine):
        """Answer 33: registration is invitation-only; there is no
        open public customer signup endpoint."""
        c = TestClient(create_app(Settings(
            {"KG_DATABASE_URL": "postgresql://placeholder",
             "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}),
            engine=engine))
        for path in ("/api/signup", "/api/register", "/api/tenants"):
            r = c.post(path, json={"name": "x", "email": "y@z.com"},
                       headers=HDR)
            assert r.status_code in (404, 405), (path, r.status_code)

    def test_invite_accept_requires_valid_token(self, engine):
        c = make_client(engine)
        r = c.post("/api/invites/accept",
                   json={"token": "bogus-token", "password": PASSWORD},
                   headers=HDR)
        assert r.status_code in (400, 401, 403, 404)
