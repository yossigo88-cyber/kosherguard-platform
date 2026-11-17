"""Five-role staff model (Answer 29) and two-person approval of
especially destructive operations (Answer 25).

Roles: Owner / Security administrator / Support administrator /
Customer-parent administrator (tenant Role.owner/guardian) /
Read-only operator. Staff accounts require MFA. Destructive device
commands and platform-level sensitive operations need fresh
verification, explicit confirmation, and approval by a DIFFERENT
privileged user before anything executes.
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
from app.models import (AuditEvent, Device, MDMEnrollment, Role,  # noqa: E402
                        Tenant, User)

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}

USERS = {
    "owner@example.com": "owner",
    "sec@example.com": "security_admin",
    "support@example.com": "support_admin",
    "ro@example.com": "read_only",
    "parent@example.com": None,  # customer/parent administrator (tenant)
}


def make_app(engine):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-x")
        s.add(tenant)
        s.flush()
        for email, staff in USERS.items():
            s.add(User(tenant_id=tenant.id, email=email,
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner, staff_role=staff))
        device = Device(tenant_id=tenant.id, name="iphone-1")
        s.add(device)
        s.flush()
        enr = MDMEnrollment(tenant_id=tenant.id, device_id=device.id,
                            enrollment_id="enr-1")
        s.add(enr)
        s.flush()
        ids = (tenant.id, enr.id)
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    app = create_app(settings, engine=engine)
    app.state.test_tenant_id, app.state.test_enrollment_pk = ids
    return app


def login(client, email):
    return mfa_login(client, json={"email": email, "password": PASSWORD},
                     headers=HDR)


def fresh_code(client, email):
    return pyotp.TOTP(client.app.state._fixture_mfa[email]).now()


class TestStaffMatrix:
    def test_support_cannot_change_categories(self, engine):
        c = TestClient(make_app(engine))
        login(c, "support@example.com")
        assert c.get("/api/admin/categories").status_code == 403
        assert c.post("/api/admin/categories", json={
            "domain": "x.example", "category": "adult"}, headers=HDR
        ).status_code == 403

    def test_security_admin_can_change_categories(self, engine):
        c = TestClient(make_app(engine))
        login(c, "sec@example.com")
        assert c.post("/api/admin/categories", json={
            "domain": "x.example", "category": "adult",
            "source": "t"}, headers=HDR).status_code == 200

    def test_authorized_staff_can_read_limited_tenant_roster(self, engine):
        """Preserve Answer 29's limited support/read-only overview."""
        c = TestClient(make_app(engine))
        login(c, "sec@example.com")
        assert c.get("/api/admin/tenants").status_code == 200
        login(c, "ro@example.com")
        assert c.get("/api/admin/tenants").status_code == 200
        login(c, "support@example.com")
        assert c.get("/api/admin/tenants").status_code == 200
        c2 = TestClient(c.app)
        # plain tenant user without staff role: 403
        login(c2, "parent@example.com")
        assert c2.get("/api/admin/tenants").status_code == 403

    def test_staff_management_owner_only_and_last_owner(self, engine):
        c = TestClient(make_app(engine))
        login(c, "sec@example.com")
        assert c.get("/api/staff").status_code == 403
        c2 = TestClient(c.app)
        login(c2, "owner@example.com")
        staff = c2.get("/api/staff").json()["staff"]
        assert {u["email"] for u in staff} == {
            "owner@example.com", "sec@example.com",
            "support@example.com", "ro@example.com"}
        owner_id = [u["id"] for u in staff
                    if u["email"] == "owner@example.com"][0]
        parent_id = None
        with session_scope(engine) as s:
            from sqlalchemy import select
            parent_id = s.scalar(select(User).where(
                User.email == "parent@example.com")).id
        # promote the parent admin to read-only staff: allowed
        r = c2.post(f"/api/staff/{parent_id}/role",
                    json={"staff_role": "read_only"}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["staff_role"] == "read_only"
        # demoting the only remaining owner is refused
        assert c2.post(f"/api/staff/{owner_id}/role",
                       json={"staff_role": "support_admin"},
                       headers=HDR).status_code == 409
        # unknown role rejected
        assert c2.post(f"/api/staff/{parent_id}/role",
                       json={"staff_role": "superuser"},
                       headers=HDR).status_code == 400

    def test_staff_mfa_enforced(self, engine):
        c = TestClient(make_app(engine))
        # password-only login for a staff account is a restricted
        # enrollment session: everything except enrollment is blocked
        r = c.post("/api/auth/login", json={
            "email": "ro@example.com", "password": PASSWORD}, headers=HDR)
        assert r.status_code == 200 and r.json()["mfa_required"]
        assert c.get("/api/admin/tenants").status_code == 403

    def test_support_query_limited_to_read_only_commands(self, engine):
        c = TestClient(make_app(engine))
        login(c, "support@example.com")
        tid, pk = c.app.state.test_tenant_id, c.app.state.test_enrollment_pk
        r = c.post(f"/api/staff/tenants/{tid}/enrollments/{pk}/query",
                   json={"command": "DeviceInformation"}, headers=HDR)
        assert r.status_code == 200
        assert c.post(f"/api/staff/tenants/{tid}/enrollments/{pk}/query",
                      json={"command": "InstallProfile"},
                      headers=HDR).status_code == 403
        # read-only operator cannot issue even query commands
        login(c, "ro@example.com")
        assert c.post(f"/api/staff/tenants/{tid}/enrollments/{pk}/query",
                       json={"command": "DeviceInformation"},
                       headers=HDR).status_code == 403


class TestTwoPersonApproval:
    def _request_erase(self, client, email, operation="EraseDevice"):
        login(client, email)
        pk = client.app.state.test_enrollment_pk
        return client.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": operation,
            "totp_code": fresh_code(client, email),
            "confirm": operation,
            "reason": "device lost"}, headers=HDR)

    def test_full_flow_two_distinct_users(self, engine):
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        assert r.status_code == 202, r.text
        aid = r.json()["approval_id"]
        assert r.json()["status"] == "pending"
        # nothing queued to the device yet
        pk = req.app.state.test_enrollment_pk
        assert req.get(f"/api/mdm/enrollments/{pk}/commands").json()[
            "commands"] == []
        # requester cannot approve their own request
        r = req.post(f"/api/mdm/sensitive-approvals/{aid}/approve", json={
            "totp_code": fresh_code(req, "parent@example.com"),
            "confirm": "EraseDevice"}, headers=HDR)
        assert r.status_code == 403
        # a second privileged user with fresh verification approves
        appr = TestClient(req.app)
        login(appr, "sec@example.com")
        r = appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve", json={
            "totp_code": fresh_code(appr, "sec@example.com"),
            "confirm": "EraseDevice"}, headers=HDR)
        assert r.status_code == 200, r.text
        # Honest lifecycle: approval records the command in the server
        # queue; it is never called "executed" before the device
        # acknowledges it.
        assert r.json()["status"] == "approved_command_queued"
        # now the device command exists exactly once, in the queue
        cmds = appr.get(f"/api/mdm/enrollments/{pk}/commands").json()["commands"]
        assert [c["command"] for c in cmds] == ["EraseDevice"]
        assert cmds[0]["status"] == "queued"
        # decided approvals cannot be re-decided
        assert appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve",
                         json={"totp_code": fresh_code(appr, "sec@example.com"),
                               "confirm": "EraseDevice"},
                         headers=HDR).status_code == 409

    def test_fresh_verification_and_confirmation_required(self, engine):
        c = TestClient(make_app(engine))
        login(c, "parent@example.com")
        pk = c.app.state.test_enrollment_pk
        # a request against a nonexistent enrollment is refused before
        # any approval is recorded
        assert c.post("/api/mdm/enrollments/999999/commands", json={
            "command": "EraseDevice", "confirm": "EraseDevice",
            "reason": "x"}, headers=HDR).status_code == 404
        # no TOTP code
        assert c.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": "EraseDevice", "confirm": "EraseDevice",
            "reason": "x"}, headers=HDR).status_code == 403
        # wrong confirmation string
        assert c.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": "EraseDevice",
            "totp_code": fresh_code(c, "parent@example.com"),
            "confirm": "yes", "reason": "x"}, headers=HDR).status_code == 400
        # no reason
        assert c.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": "EraseDevice",
            "totp_code": fresh_code(c, "parent@example.com"),
            "confirm": "EraseDevice"}, headers=HDR).status_code == 400

    def test_support_and_readonly_cannot_request_or_approve(self, engine):
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        aid = r.json()["approval_id"]
        sup = TestClient(req.app)
        login(sup, "support@example.com")
        pk = req.app.state.test_enrollment_pk
        assert sup.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": "EraseDevice",
            "totp_code": fresh_code(sup, "support@example.com"),
            "confirm": "EraseDevice", "reason": "x"},
            headers=HDR).status_code == 403
        assert sup.post(f"/api/mdm/sensitive-approvals/{aid}/approve",
                        json={"totp_code": fresh_code(sup, "support@example.com"),
                              "confirm": "EraseDevice"},
                        headers=HDR).status_code == 403

    def test_platform_level_operation_approval_records_runbook(self, engine):
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        # reuse the flow shape for a platform-level operation
        login(req, "owner@example.com")
        pk = req.app.state.test_enrollment_pk
        r = req.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": "ABMRelease",
            "totp_code": fresh_code(req, "owner@example.com"),
            "confirm": "ABMRelease",
            "reason": "device retired"}, headers=HDR)
        assert r.status_code == 202, r.text
        aid = r.json()["approval_id"]
        appr = TestClient(req.app)
        login(appr, "sec@example.com")
        r = appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve", json={
            "totp_code": fresh_code(appr, "sec@example.com"),
            "confirm": "ABMRelease"}, headers=HDR)
        assert r.status_code == 200
        # No live ABM integration: approval is the authorization
        # record only, and says a manual runbook step is still required
        # - never "executed".
        assert r.json()["status"] == "approved_manual_action_required"
        assert "runbook" in r.json()["decision_detail"]
        assert "NOT" in r.json()["decision_detail"]

    def test_binding_operation_and_target(self, engine):
        """Approval executes exactly what was requested: confirm must
        name the recorded operation, and the queued command carries the
        recorded enrollment and payload - the approval body cannot
        redirect it."""
        req = TestClient(make_app(engine))
        pk = req.app.state.test_enrollment_pk
        login(req, "parent@example.com")
        r = req.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": "EraseDevice", "payload": {"pin": "123456"},
            "totp_code": fresh_code(req, "parent@example.com"),
            "confirm": "EraseDevice", "reason": "lost"}, headers=HDR)
        aid = r.json()["approval_id"]
        appr = TestClient(req.app)
        login(appr, "sec@example.com")
        # confirmation naming a DIFFERENT operation is refused
        assert appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve",
                         json={"totp_code": fresh_code(appr, "sec@example.com"),
                               "confirm": "ABMRelease"},
                         headers=HDR).status_code == 400
        r = appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve", json={
            "totp_code": fresh_code(appr, "sec@example.com"),
            "confirm": "EraseDevice"}, headers=HDR)
        assert r.status_code == 200
        cmds = appr.get(f"/api/mdm/enrollments/{pk}/commands").json()["commands"]
        assert cmds[0]["command"] == "EraseDevice"
        # The stored payload is bound and intact (verifiable in the
        # ledger), but API responses redact secretish keys like PINs.
        assert cmds[0]["payload"] == {"pin": "[redacted]"}
        from app.models import MDMCommand
        with session_scope(engine) as s:
            stored = s.query(MDMCommand).filter_by(
                command="EraseDevice").one()
            import json as _json
            assert _json.loads(stored.payload) == {"pin": "123456"}

    def test_requester_demoted_while_pending_voids_approval(self, engine):
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        aid = r.json()["approval_id"]
        # requester loses privileged role while the request is pending
        with session_scope(engine) as s:
            from sqlalchemy import select
            u = s.scalar(select(User).where(User.email == "parent@example.com"))
            u.role = Role.viewer
        appr = TestClient(req.app)
        login(appr, "sec@example.com")
        r = appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve", json={
            "totp_code": fresh_code(appr, "sec@example.com"),
            "confirm": "EraseDevice"}, headers=HDR)
        assert r.status_code == 409
        from app.models import SensitiveCommandApproval
        with session_scope(engine) as s:
            assert s.get(SensitiveCommandApproval, aid).status == "void"

    def test_approver_demoted_cannot_approve(self, engine):
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        aid = r.json()["approval_id"]
        with session_scope(engine) as s:
            from sqlalchemy import select
            u = s.scalar(select(User).where(User.email == "sec@example.com"))
            u.staff_role = "support_admin"
            u.role = Role.viewer
        appr = TestClient(req.app)
        login(appr, "sec@example.com")
        assert appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve",
                         json={"totp_code": fresh_code(appr, "sec@example.com"),
                               "confirm": "EraseDevice"},
                         headers=HDR).status_code == 403

    def test_cross_tenant_isolation(self, engine):
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        aid = r.json()["approval_id"]
        # a privileged owner of ANOTHER tenant cannot see or approve it
        with session_scope(engine) as s:
            other = Tenant(name="family-y")
            s.add(other)
            s.flush()
            s.add(User(tenant_id=other.id, email="other@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        c2 = TestClient(req.app)
        login(c2, "other@example.com")
        assert c2.post(f"/api/mdm/sensitive-approvals/{aid}/approve",
                       json={"totp_code": fresh_code(c2, "other@example.com"),
                             "confirm": "EraseDevice"},
                       headers=HDR).status_code == 404
        ids = [a["id"] for a in c2.get("/api/mdm/sensitive-approvals").json()["approvals"]]
        assert aid not in ids

    def test_concurrent_double_approval_single_use(self, engine):
        """Real disposable-PostgreSQL concurrency: two privileged users
        approve the SAME pending request simultaneously. The FOR UPDATE
        row lock + status guard must let exactly one execute; the other
        gets 409. Exactly one device command may be queued."""
        import threading
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        aid = r.json()["approval_id"]
        pk = req.app.state.test_enrollment_pk
        clients = {}
        for email in ("sec@example.com", "owner@example.com"):
            c = TestClient(req.app)
            login(c, email)
            clients[email] = c
        barrier = threading.Barrier(2)
        results = {}

        def approve(email):
            c = clients[email]
            barrier.wait(timeout=10)
            resp = c.post(f"/api/mdm/sensitive-approvals/{aid}/approve",
                          json={"totp_code": fresh_code(c, email),
                                "confirm": "EraseDevice"}, headers=HDR)
            results[email] = resp.status_code

        threads = [threading.Thread(target=approve, args=(e,))
                   for e in clients]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert sorted(results.values()) == [200, 409], results
        cmds = req.get(f"/api/mdm/enrollments/{pk}/commands").json()["commands"]
        assert [c["command"] for c in cmds] == ["EraseDevice"]
        from app.models import SensitiveCommandApproval
        with session_scope(engine) as s:
            assert s.get(SensitiveCommandApproval, aid).status == (
                "approved_command_queued")

    def test_expired_approval_cannot_be_approved(self, engine):
        from datetime import timedelta
        from app.models import SensitiveCommandApproval, utcnow
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        aid = r.json()["approval_id"]
        with session_scope(engine) as s:
            row = s.get(SensitiveCommandApproval, aid)
            row.expires_at = utcnow() - timedelta(minutes=1)
        appr = TestClient(req.app)
        login(appr, "sec@example.com")
        r = appr.post(f"/api/mdm/sensitive-approvals/{aid}/approve", json={
            "totp_code": fresh_code(appr, "sec@example.com"),
            "confirm": "EraseDevice"}, headers=HDR)
        assert r.status_code == 410
        with session_scope(engine) as s:
            assert s.get(SensitiveCommandApproval, aid).status == "expired"

    def test_approval_list_shows_requester_and_device(self, engine):
        """An approver must see WHO requested and WHICH device is
        targeted before approving - not only a request id."""
        req = TestClient(make_app(engine))
        r = self._request_erase(req, "parent@example.com")
        assert r.status_code == 202
        rows = req.get("/api/mdm/sensitive-approvals").json()["approvals"]
        a = rows[0]
        assert a["requested_by_email"] == "parent@example.com"
        assert a["device"] is not None
        assert "iphone-1" in a["device"] and "enr-1" in a["device"]


import mfa_support  # noqa: E402
from mfa_support import mfa_login  # noqa: E402


class TestReadOnlyStaffViewingOnly:
    def test_read_only_staff_cannot_mutate_even_as_tenant_owner(self, engine):
        """Answer 29: read_only staff may view authorized information
        only. The account in this fixture also holds the tenant owner
        role; the read-only staff limit still wins (same precedence as
        the destructive-command limit), while reads and account
        self-service stay open."""
        c = TestClient(make_app(engine))
        login(c, "ro@example.com")
        me = c.get("/api/auth/me").json()
        assert me["staff_role"] == "read_only"
        # Limited tenant-overview reads are explicitly authorized.
        assert c.get("/api/admin/tenants").status_code == 200
        assert c.get("/api/policies").status_code == 200
        # Tenant configuration mutation is rejected before validation.
        r = c.post("/api/policies", json={}, headers=HDR)
        assert r.status_code == 403
        assert "read-only staff role" in r.json()["detail"]
        # Category administration is mutation too.
        assert c.post("/api/admin/categories", json={
            "domain": "x.example", "category": "adult"}, headers=HDR
        ).status_code == 403
        # Sweep of representative mutation routes across methods and
        # surfaces, including the privilege-changing ones.
        for method, path in [
                ("put", "/api/policies/1"),
                ("delete", "/api/exceptions/1"),
                ("put", "/api/privacy/retention"),
                ("post", "/api/guardians/invite"),
                ("put", "/api/guardians/1/role"),
                ("post", "/api/guardians/1/mfa-reset"),
                ("post", "/api/staff/1/role"),
                ("post", "/api/publications"),
                ("delete", "/api/groups/1/devices/1"),
                ("post", "/api/mdm/enrollments/1/commands"),
                ("post", "/api/admin/support/requests/1/advance")]:
            kw = {} if method == "delete" else {"json": {}}
            r = getattr(c, method)(path, headers=HDR, **kw)
            assert r.status_code == 403, (method, path, r.status_code)
            assert "read-only staff role" in r.json()["detail"], (method, path)
        # Account self-service stays available and cannot change
        # privilege: password change works, the account stays read-only.
        r = c.post("/api/auth/password-change", json={
            "current_password": PASSWORD,
            "new_password": "a new long enough password"}, headers=HDR)
        assert r.status_code == 200
        me = c.get("/api/auth/me").json()
        assert me["staff_role"] == "read_only"
        assert c.post("/api/policies", json={}, headers=HDR).status_code == 403
        assert c.post("/api/auth/logout", headers=HDR).status_code in (200, 204)


class TestTenantOnboarding:
    """Customer-tenant onboarding (B1; Answers 28/33: invitation-only
    pilot, staff-assisted). The ONLY way a tenant comes into existence
    is a staff owner creating it plus an owner invitation."""

    def test_onboard_owner_only(self, engine):
        c = TestClient(make_app(engine))
        login(c, "sec@example.com")
        assert c.post("/api/staff/tenants", json={
            "tenant_name": "family-y",
            "owner_email": "dad@family-y.example"},
            headers=HDR).status_code == 403
        login(c, "support@example.com")
        assert c.post("/api/staff/tenants", json={
            "tenant_name": "family-y",
            "owner_email": "dad@family-y.example"},
            headers=HDR).status_code == 403
        login(c, "parent@example.com")
        assert c.post("/api/staff/tenants", json={
            "tenant_name": "family-y",
            "owner_email": "dad@family-y.example"},
            headers=HDR).status_code == 403

    def test_onboard_full_flow_and_isolation(self, engine):
        c = TestClient(make_app(engine))
        login(c, "owner@example.com")
        r = c.post("/api/staff/tenants", json={
            "tenant_name": "family-y",
            "owner_email": "dad@family-y.example"}, headers=HDR)
        assert r.status_code == 200, r.text
        token = r.json()["invite_token"]
        new_tenant_id = r.json()["tenant_id"]
        assert new_tenant_id != c.app.state.test_tenant_id
        # invite token stored hashed, usable once via the existing
        # accept flow; the new owner then logs in
        r = c.post("/api/invites/accept", json={
            "token": token, "password": "brand new password1"},
            headers=HDR)
        assert r.status_code == 200
        assert r.json()["role"] == "owner"
        assert c.post("/api/invites/accept", json={
            "token": token, "password": "brand new password1"},
            headers=HDR).status_code == 400
        c2 = TestClient(c.app)
        mfa_login(c2, json={"email": "dad@family-y.example",
                            "password": "brand new password1"},
                  headers=HDR)
        # tenant isolation: the new customer sees none of family-x's
        # devices, and family-x staff-cookie user can't see theirs
        assert c2.get("/api/devices").json()["devices"] == []
        assert c.get("/api/devices").json()["devices"] != []
        with session_scope(engine) as s:
            from sqlalchemy import select
            t = s.scalar(select(Tenant).where(Tenant.name == "family-y"))
            assert t is not None
            audits = s.execute(select(AuditEvent).where(
                AuditEvent.tenant_id == t.id)).scalars().all()
            assert any(a.action == "staff.tenant_onboard"
                       for a in audits)

    def test_onboard_validation(self, engine):
        c = TestClient(make_app(engine))
        login(c, "owner@example.com")
        assert c.post("/api/staff/tenants", json={
            "tenant_name": "", "owner_email": "a@b.example"},
            headers=HDR).status_code == 400
        assert c.post("/api/staff/tenants", json={
            "tenant_name": "ok-name", "owner_email": "not-an-email"},
            headers=HDR).status_code == 400
