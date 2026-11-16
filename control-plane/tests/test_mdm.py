"""Milestone 4 MDM tests: enrollment records, command lifecycle,
tenant isolation, and the honesty rule that nothing reports success
from a successful send alone.
"""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402
from mdm.adapter import CommandResult, SimulatedMDMAdapter  # noqa: E402
from app import mdm_ops  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_client(engine, email="g@example.com", tenant_name="family-m",
                nanomdm_url=None):
    with session_scope(engine) as s:
        tenant = Tenant(name=tenant_name)
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
    if nanomdm_url:
        env["KG_NANOMDM_URL"] = nanomdm_url
    c = TestClient(create_app(Settings(env), engine=engine))
    r = mfa_login(c, json={'email': email, 'password': PASSWORD}, headers=HDR)
    assert r.status_code == 200
    return c


@pytest.fixture()
def client(engine):
    return make_client(engine)



def tenant_id_of(engine, email="g@example.com"):
    with session_scope(engine) as s:
        return s.query(User).filter_by(email=email).one().tenant_id

def mk_device(c, name="phone-1"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


def mk_enrollment(c, device_id):
    r = c.post("/api/mdm/enrollments",
               json={"device_id": device_id,
                     "supervision_requested": True},
               headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


class TestEnrollments:
    def test_create_and_list(self, client):
        dev = mk_device(client)
        enr = mk_enrollment(client, dev)
        assert enr["state"] == "pending"
        assert enr["supervision_requested"] is True
        listing = client.get("/api/mdm/enrollments").json()["enrollments"]
        assert len(listing) == 1
        assert listing[0]["device_id"] == dev

    def test_requested_supervision_is_never_verified(self, client):
        """A guardian's checkbox is a request, not a device fact. A
        pending, never-contacted enrollment must never report verified
        supervision, whatever the API caller asked for."""
        dev = mk_device(client)
        enr = mk_enrollment(client, dev)
        assert enr["supervision_requested"] is True
        assert enr["supervision_verified"] is False
        listed = client.get("/api/mdm/enrollments").json()["enrollments"][0]
        assert listed["supervision_verified"] is False

    def test_verify_pending_enrollment_refused(self, engine, client):
        """The device-reported path refuses to verify supervision on a
        pending enrollment: the device has never checked in."""
        enr = mk_enrollment(client, mk_device(client))
        tid = tenant_id_of(engine)
        with session_scope(engine) as s:
            with pytest.raises(mdm_ops.MDMError) as exc:
                mdm_ops.mark_supervision_verified(s, tid, enr["id"], True)
            assert exc.value.status == 409
            row = s.get(__import__("app.models", fromlist=["MDMEnrollment"])
                        .MDMEnrollment, enr["id"])
            assert row.supervision_verified is False

    def test_verify_after_activation_works(self, engine, client):
        """Once a device is active (has checked in), device-reported
        supervision can be recorded through the check-in path."""
        enr = mk_enrollment(client, mk_device(client))
        tid = tenant_id_of(engine)
        with session_scope(engine) as s:
            from app.models import MDMEnrollment
            row = s.get(MDMEnrollment, enr["id"])
            row.state = "active"
            s.flush()
            mdm_ops.mark_supervision_verified(s, tid, enr["id"], True)
            assert s.get(MDMEnrollment, enr["id"]).supervision_verified \
                is True

    def test_enroll_other_tenants_device_rejected(self, engine):
        c1 = make_client(engine, "a@example.com", "tenant-a")
        c2 = make_client(engine, "b@example.com", "tenant-b")
        dev_b = mk_device(c2, "phone-b")
        r = c1.post("/api/mdm/enrollments",
                    json={"device_id": dev_b}, headers=HDR)
        assert r.status_code == 404

    def test_csrf_required(self, client):
        dev = mk_device(client)
        r = client.post("/api/mdm/enrollments", json={"device_id": dev})
        assert r.status_code == 403


class TestCommands:
    def test_unsupported_command_rejected(self, client):
        enr = mk_enrollment(client, mk_device(client))
        r = client.post(f"/api/mdm/enrollments/{enr['id']}/commands",
                        json={"command": "EraseDevice"}, headers=HDR)
        assert r.status_code == 400

    def test_no_adapter_stays_queued(self, client):
        """Without an MDM server the honest state is queued: nothing
        was delivered, and the command is certainly not applied."""
        enr = mk_enrollment(client, mk_device(client))
        r = client.post(f"/api/mdm/enrollments/{enr['id']}/commands",
                        json={"command": "DeviceLock"}, headers=HDR)
        assert r.status_code == 200, r.json()
        body = r.json()
        assert body["status"] == "queued"
        assert body["applied"] is False

    def test_queued_never_applied_via_ops(self, engine, client):
        """Direct ops call without adapter: queued, not applied."""
        enr = mk_enrollment(client, mk_device(client))
        tid = tenant_id_of(engine)
        with session_scope(engine) as s:
            row = mdm_ops.issue_command(
                s, tid, enr["id"], "DeviceInformation", {}, None,
                adapter=None)
            assert row.status == "queued"
            assert row.applied is False

    def test_acknowledged_marks_applied(self, engine, client):
        enr = mk_enrollment(client, mk_device(client))
        adapter = SimulatedMDMAdapter()
        tid = tenant_id_of(engine)
        with session_scope(engine) as s:
            row = mdm_ops.issue_command(
                s, tid, enr["id"], "DeviceLock", {}, None, adapter=adapter)
            assert row.status == "acknowledged"
            assert row.applied is True
        assert adapter.calls[0][1] == "DeviceLock"

    def test_error_and_not_now_never_applied(self, engine, client):
        enr = mk_enrollment(client, mk_device(client))
        tid = tenant_id_of(engine)
        for status in ("error", "not_now"):
            adapter = SimulatedMDMAdapter(
                {"DeviceLock": CommandResult(status, "device said so")})
            with session_scope(engine) as s:
                row = mdm_ops.issue_command(
                    s, tid, enr["id"], "DeviceLock", {}, None,
                    adapter=adapter)
                assert row.status == status
                assert row.applied is False

    def test_adapter_failure_returns_to_queued(self, engine, client):
        class DeadAdapter:
            def deliver_command(self, *a):
                raise RuntimeError("mdm server unreachable")
        enr = mk_enrollment(client, mk_device(client))
        with session_scope(engine) as s:
            row = mdm_ops.issue_command(
                s, tenant_id_of(engine), enr["id"], "RestartDevice", {},
                None, adapter=DeadAdapter())
            assert row.status == "queued"
            assert row.applied is False
            assert "unreachable" in row.result_detail

    def test_cross_tenant_command_read_denied(self, engine):
        c1 = make_client(engine, "a@example.com", "tenant-a")
        c2 = make_client(engine, "b@example.com", "tenant-b")
        enr = mk_enrollment(c1, mk_device(c1))
        r = c1.post(f"/api/mdm/enrollments/{enr['id']}/commands",
                    json={"command": "DeviceInformation"}, headers=HDR)
        cmd_id = r.json()["id"]
        # Tenant B cannot read tenant A's command, list its commands,
        # or issue against its enrollment.
        assert c2.get(f"/api/mdm/commands/{cmd_id}").status_code == 404
        assert c2.get(
            f"/api/mdm/enrollments/{enr['id']}/commands").status_code == 404
        r = c2.post(f"/api/mdm/enrollments/{enr['id']}/commands",
                    json={"command": "DeviceLock"}, headers=HDR)
        assert r.status_code == 404

    def test_command_history_listed(self, client):
        enr = mk_enrollment(client, mk_device(client))
        for cmd in ("DeviceInformation", "ProfileList"):
            client.post(f"/api/mdm/enrollments/{enr['id']}/commands",
                        json={"command": cmd}, headers=HDR)
        listing = client.get(
            f"/api/mdm/enrollments/{enr['id']}/commands").json()["commands"]
        assert [c["command"] for c in listing] == [
            "DeviceInformation", "ProfileList"]


class TestReconciler:
    """mdm.reconciler: NanoMDM device statuses advance our ledger;
    cross-tenant rows and terminal-status re-opening are refused."""

    def _seed_command(self, engine, tenant_id=1, status="delivered"):
        with session_scope(engine) as s:
            from app.models import Device, MDMCommand, MDMEnrollment, Tenant
            t = s.get(Tenant, tenant_id) or Tenant(name=f"t{tenant_id}")
            if t.id is None:
                s.add(t)
                s.flush()
            d = Device(tenant_id=t.id, name=f"dev-{tenant_id}")
            s.add(d)
            s.flush()
            e = MDMEnrollment(tenant_id=t.id, device_id=d.id,
                              enrollment_id=f"enr-{tenant_id}",
                              state="active")
            s.add(e)
            s.flush()
            c = MDMCommand(tenant_id=t.id, enrollment_pk=e.id,
                           command="DeviceLock", status=status)
            s.add(c)
            s.flush()
            return t.id, c.id

    def test_acknowledged_advances_and_applies(self, engine):
        from mdm.reconciler import reconcile
        tid, cid = self._seed_command(engine)
        with session_scope(engine) as s:
            from app.models import MDMCommand
            r = reconcile(s, tid, [{"command_id": cid,
                                    "status": "Acknowledged"}])
            assert (r.advanced, r.applied) == (1, 1)
            row = s.get(MDMCommand, cid)
            assert row.status == "acknowledged" and row.applied is True

    def test_error_advances_without_applied(self, engine):
        from mdm.reconciler import reconcile
        tid, cid = self._seed_command(engine)
        with session_scope(engine) as s:
            from app.models import MDMCommand
            reconcile(s, tid, [{"command_id": cid, "status": "Error",
                                "detail": "device refused"}])
            row = s.get(MDMCommand, cid)
            assert row.status == "error" and row.applied is False

    def test_terminal_not_reopened_by_idle(self, engine):
        from mdm.reconciler import reconcile
        tid, cid = self._seed_command(engine, status="acknowledged")
        with session_scope(engine) as s:
            from app.models import MDMCommand
            r = reconcile(s, tid, [{"command_id": cid, "status": "Idle"}])
            assert r.advanced == 0 and r.skipped == 1
            assert s.get(MDMCommand, cid).status == "acknowledged"

    def test_cross_tenant_row_ignored(self, engine):
        from mdm.reconciler import reconcile
        tid, cid = self._seed_command(engine, tenant_id=1)
        with session_scope(engine) as s:
            from app.models import MDMCommand
            r = reconcile(s, 999, [{"command_id": cid,
                                    "status": "Acknowledged"}])
            assert r.advanced == 0 and r.skipped == 1
            assert s.get(MDMCommand, cid).status == "delivered"

    def test_unknown_command_id_ignored(self, engine):
        from mdm.reconciler import reconcile
        tid, _ = self._seed_command(engine)
        with session_scope(engine) as s:
            r = reconcile(s, tid, [{"command_id": 424242,
                                    "status": "Acknowledged"}])
            assert r.advanced == 0 and r.skipped == 1

from mfa_support import mfa_login
