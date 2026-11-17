"""Structured exception requests (spec Part 2A customer portal:
"request exceptions or policy changes"; Answer 20: scoped,
time-limited exceptions with reason, approver, audit; parents may
approve delegated limited exceptions).

A pending request is inert. Approving creates a real PolicyException
through the same validation as direct creation, with the approver
recorded; guardian approvers stay within their delegated limits.
"""

import json
import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (Device, DeviceGroup, ExceptionRequest,  # noqa: E402
                        PolicyException, Role, Tenant, User)

from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_app(engine):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-x")
        s.add(tenant)
        s.flush()
        owner = User(tenant_id=tenant.id, email="owner@example.com",
                     password_hash=security.hash_password(PASSWORD),
                     role=Role.owner)
        guardian = User(tenant_id=tenant.id,
                        email="guardian@example.com",
                        password_hash=security.hash_password(PASSWORD),
                        role=Role.guardian,
                        delegated_settings='["exceptions"]')
        viewer = User(tenant_id=tenant.id, email="viewer@example.com",
                      password_hash=security.hash_password(PASSWORD),
                      role=Role.viewer)
        device = Device(tenant_id=tenant.id, name="iphone-1")
        group = DeviceGroup(tenant_id=tenant.id, name="kids")
        s.add_all([owner, guardian, viewer, device, group])
        s.flush()
        ids = (device.id, group.id)
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    app = create_app(settings, engine=engine)
    app.state.test_device_id, app.state.test_group_id = ids
    return app


def login(client, email):
    return mfa_login(client, json={"email": email, "password": PASSWORD},
                     headers=HDR)


def make_request(client, device_id, **over):
    body = {"kind": "allow_domains", "scope_type": "device",
            "device_id": device_id, "domains": ["example.com"],
            "reason": "homework site needed", "duration_minutes": 120}
    body.update(over)
    return client.post("/api/exception-requests", json=body, headers=HDR)


class TestExceptionRequests:
    def test_request_approve_creates_real_exception(self, engine):
        c = TestClient(make_app(engine))
        login(c, "guardian@example.com")
        device_id = c.app.state.test_device_id
        r = make_request(c, device_id)
        assert r.status_code == 200, r.text
        rid = r.json()["id"]
        assert r.json()["status"] == "pending"
        # pending request creates no exception yet
        with session_scope(engine) as s:
            assert s.query(PolicyException).count() == 0
        # guardian without the exceptions delegation cannot approve
        login(c, "viewer@example.com")
        assert c.post(f"/api/exception-requests/{rid}/approve",
                      json={}, headers=HDR).status_code == 403
        # owner approves: real exception created, approver recorded
        login(c, "owner@example.com")
        r = c.post(f"/api/exception-requests/{rid}/approve",
                   json={}, headers=HDR)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "approved"
        assert r.json()["decided_by_email"] == "owner@example.com"
        ex_id = r.json()["exception_id"]
        with session_scope(engine) as s:
            ex = s.get(PolicyException, ex_id)
            assert ex is not None
            assert ex.kind == "allow_domains"
            assert ex.device_id == device_id
            assert json.loads(ex.domains) == ["example.com"]
            assert ex.reason == "homework site needed"
            assert ex.approver_user_id is not None
            assert ex.expires_at > ex.starts_at
        # decided requests cannot be decided again
        assert c.post(f"/api/exception-requests/{rid}/reject",
                      json={}, headers=HDR).status_code == 409

    def test_reject_records_decision_without_exception(self, engine):
        c = TestClient(make_app(engine))
        login(c, "guardian@example.com")
        rid = make_request(c, c.app.state.test_device_id).json()["id"]
        login(c, "owner@example.com")
        r = c.post(f"/api/exception-requests/{rid}/reject",
                   json={}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"
        assert r.json()["exception_id"] is None
        with session_scope(engine) as s:
            assert s.query(PolicyException).count() == 0

    def test_guardian_with_delegation_can_approve_limited(self, engine):
        c = TestClient(make_app(engine))
        login(c, "guardian@example.com")
        rid = make_request(
            c, c.app.state.test_device_id,
            duration_minutes=60).json()["id"]
        r = c.post(f"/api/exception-requests/{rid}/approve",
                   json={}, headers=HDR)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "approved"

    def test_guardian_delegated_limits_hold_on_approve(self, engine):
        c = TestClient(make_app(engine))
        # An owner files a 48h request; a guardian whose delegation is
        # limited to 24h must not be able to approve it into a real
        # exception, even though they hold the exceptions delegation.
        login(c, "owner@example.com")
        rid = make_request(
            c, c.app.state.test_device_id,
            duration_minutes=48 * 60).json()["id"]
        login(c, "guardian@example.com")
        r = c.post(f"/api/exception-requests/{rid}/approve",
                   json={}, headers=HDR)
        assert r.status_code == 403
        with session_scope(engine) as s:
            row = s.get(ExceptionRequest, rid)
            assert row.status == "pending"
            assert s.query(PolicyException).count() == 0
        # the owner can still approve their own request
        login(c, "owner@example.com")
        assert c.post(f"/api/exception-requests/{rid}/approve",
                      json={}, headers=HDR).status_code == 200

    def test_guardian_requests_stay_within_delegation(self, engine):
        c = TestClient(make_app(engine))
        login(c, "guardian@example.com")
        # a guardian cannot even file a request beyond their 24h cap:
        # the same shared validation guards creation
        assert make_request(c, c.app.state.test_device_id,
                            duration_minutes=48 * 60).status_code == 403

    def test_viewers_cannot_request_and_validation(self, engine):
        c = TestClient(make_app(engine))
        login(c, "viewer@example.com")
        assert make_request(
            c, c.app.state.test_device_id).status_code == 403
        login(c, "owner@example.com")
        # unbounded or absurd durations refused
        assert make_request(c, c.app.state.test_device_id,
                            duration_minutes=0).status_code == 400
        assert make_request(c, c.app.state.test_device_id,
                            duration_minutes=999999).status_code == 400
        # invalid domain refused by shared validation
        assert make_request(c, c.app.state.test_device_id,
                            domains=["bad domain!"]).status_code == 400
        # unknown kind refused
        assert make_request(c, c.app.state.test_device_id,
                            kind="everything").status_code == 400
        # foreign device refused
        assert make_request(c, 424242).status_code == 404

    def test_list_requests(self, engine):
        c = TestClient(make_app(engine))
        login(c, "guardian@example.com")
        make_request(c, c.app.state.test_device_id)
        make_request(c, None, scope_type="group",
                     group_id=c.app.state.test_group_id)
        rows = c.get("/api/exception-requests").json()["requests"]
        assert len(rows) == 2
        assert rows[0]["requested_by_email"] == "guardian@example.com"
        assert rows[0]["duration_minutes"] == 120
