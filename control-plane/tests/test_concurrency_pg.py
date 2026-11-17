"""Real disposable-PostgreSQL concurrency races for the 2026-11-17
security corrections.

Every test drives the real API from two threads against the bundled
PostgreSQL fixture and asserts the serialized outcome: exactly one
winner, a consistent final state, and no duplicated side effects.
"""

import os
import sys
import tempfile
import threading
import traceback

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (Device, ExceptionRequest, InviteToken,  # noqa: E402
                        LoginAttempt, MDMCommand, MDMEnrollment, PolicyException,
                        Role, SensitiveCommandApproval, Tenant, User, utcnow)
from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_app(engine, tenant_name="race-t"):
    with session_scope(engine) as s:
        tenant = Tenant(name=tenant_name)
        s.add(tenant)
        s.flush()
        for email in ("a@example.com", "b@example.com"):
            s.add(User(tenant_id=tenant.id, email=email,
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        device = Device(tenant_id=tenant.id, name="race-phone")
        s.add(device)
        s.flush()
        enr = MDMEnrollment(tenant_id=tenant.id, device_id=device.id,
                            enrollment_id=f"enr-{tenant_name}",
                            state="enrolled")
        s.add(enr)
        s.flush()
        ids = (tenant.id, device.id, enr.id)
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": tempfile.mkdtemp(prefix="kg-pub-")})
    app = create_app(settings, engine=engine)
    app.state.test_settings = settings
    app.state.test_ids = ids
    return app


def login(c, email):
    r = mfa_login(c, json={"email": email, "password": PASSWORD},
                  headers=HDR)
    assert r.status_code == 200, r.text


def fresh_code(c, email):
    return pyotp.TOTP(c.app.state._fixture_mfa[email]).now()


def race(fn_a, fn_b):
    """Run two functions with a staggered start; return their results
    in call order. Each gets its own thread."""
    results = {}
    barrier = threading.Barrier(2)

    def wrap(key, fn):
        try:
            barrier.wait(timeout=10)
            results[key] = fn()
        except Exception:  # surface the real failure
            results[key] = traceback.format_exc()

    threads = [threading.Thread(target=wrap, args=("a", fn_a)),
               threading.Thread(target=wrap, args=("b", fn_b))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    for key, val in results.items():
        if not isinstance(val, int):
            raise AssertionError(f"race thread {key} raised:\n{val}")
    return results


def _request_erase(app):
    req = TestClient(app)
    login(req, "a@example.com")
    _, _, pk = app.state.test_ids
    r = req.post(f"/api/mdm/enrollments/{pk}/commands", json={
        "command": "EraseDevice",
        "totp_code": fresh_code(req, "a@example.com"),
        "confirm": "EraseDevice", "reason": "race"}, headers=HDR)
    assert r.status_code == 202, r.text
    return r.json()["approval_id"]


class TestApprovalRaces:
    def test_approve_reject_race_single_decision(self, engine):
        """Approve and reject race on the SAME pending approval: the
        row lock admits exactly one decision; the loser gets 409 and
        the recorded status matches the winner."""
        app = make_app(engine, "race-ar")
        aid = _request_erase(app)
        appr = TestClient(app)
        login(appr, "b@example.com")

        def approve():
            return appr.post(
                f"/api/mdm/sensitive-approvals/{aid}/approve",
                json={"totp_code": fresh_code(appr, "b@example.com"),
                      "confirm": "EraseDevice"}, headers=HDR).status_code

        def reject():
            return appr.post(
                f"/api/mdm/sensitive-approvals/{aid}/reject",
                json={"totp_code": fresh_code(appr, "b@example.com"),
                      "confirm": "EraseDevice",
                      "reason": "no"}, headers=HDR).status_code

        results = race(approve, reject)
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            row = s.get(SensitiveCommandApproval, aid)
            if results["a"] == 200:
                assert row.status == "approved_command_queued"
            else:
                assert row.status == "rejected"

    def test_double_approve_executes_once(self, engine):
        """Two different privileged approvers race to approve the SAME
        pending destructive command: exactly one wins, the approval
        executes once, and exactly one MDM command is queued."""
        app = make_app(engine, "race-da")
        tid, _, _ = app.state.test_ids
        with session_scope(engine) as s:
            s.add(User(tenant_id=tid, email="c@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        aid = _request_erase(app)
        c1, c2 = TestClient(app), TestClient(app)
        login(c1, "b@example.com")
        login(c2, "c@example.com")

        def approve(c, email):
            return c.post(
                f"/api/mdm/sensitive-approvals/{aid}/approve",
                json={"totp_code": fresh_code(c, email),
                      "confirm": "EraseDevice"}, headers=HDR).status_code

        results = race(lambda: approve(c1, "b@example.com"),
                       lambda: approve(c2, "c@example.com"))
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            row = s.get(SensitiveCommandApproval, aid)
            assert row.status == "approved_command_queued"
            assert s.query(MDMCommand).filter_by(
                tenant_id=tid, command="EraseDevice").count() == 1

    def test_exception_request_double_approve(self, engine):
        """Two approvers race on the SAME exception request: one
        decision, one created exception."""
        app = make_app(engine, "race-er")
        tid, dev, _ = app.state.test_ids
        req = TestClient(app)
        login(req, "a@example.com")
        r = req.post("/api/exception-requests", json={
            "kind": "allow_domains", "scope_type": "device",
            "device_id": dev, "domains": ["race.example"],
            "reason": "race", "duration_minutes": 60}, headers=HDR)
        assert r.status_code == 200, r.text
        rid = r.json()["id"]
        c1, c2 = TestClient(app), TestClient(app)
        login(c1, "a@example.com")
        login(c2, "b@example.com")

        def approve(c, email):
            return c.post(f"/api/exception-requests/{rid}/approve",
                          json={}, headers=HDR).status_code

        results = race(lambda: approve(c1, "a@example.com"),
                       lambda: approve(c2, "b@example.com"))
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            row = s.get(ExceptionRequest, rid)
            assert row.status == "approved"
            assert s.query(PolicyException).filter_by(
                tenant_id=tid).count() == 1


class TestTicketAndInviteRaces:
    def test_redeem_revoke_race_single_outcome(self, engine):
        """A redeem racing a revoke on the SAME ticket: exactly one
        wins. A ticket is never redeemed after a winning revoke nor
        revoked as-unused after a winning redeem."""
        app = make_app(engine, "race-tk")
        _, dev, _ = app.state.test_ids
        c = TestClient(app)
        login(c, "a@example.com")
        r = c.post(f"/api/mdm/devices/{dev}/enrollment-tickets",
                   json={}, headers=HDR)
        assert r.status_code == 200, r.text
        ticket = r.json()["ticket"]
        tid = r.json()["id"]
        anon = TestClient(app)

        def redeem():
            return anon.post("/api/mdm/enroll", json={
                "ticket": ticket,
                "device_udid": "UDID-RACE-TK"}).status_code

        def revoke():
            return c.delete(f"/api/mdm/enrollment-tickets/{tid}",
                            headers=HDR).status_code

        results = race(redeem, revoke)
        codes = sorted(results.values())
        # winner takes all: redeem 200 + revoke 409, or revoke 200 +
        # redeem 410 (revoked) - never both 200.
        assert codes in ([200, 409], [200, 410]), results
        if results["a"] == 200:
            with session_scope(engine) as s:
                assert s.query(MDMEnrollment).filter_by(
                    device_udid="UDID-RACE-TK").count() == 1

    def test_invite_double_accept_single_user(self, engine):
        """Two accepts of the SAME invite token: exactly one account
        is created."""
        app = make_app(engine, "race-inv")
        c = TestClient(app)
        login(c, "a@example.com")
        r = c.post("/api/guardians/invite", json={
            "email": "racer@example.com", "role": "viewer"}, headers=HDR)
        assert r.status_code == 200, r.text
        token = r.json()["invite_token"]
        a1, a2 = TestClient(app), TestClient(app)

        def accept(c):
            return c.post("/api/invites/accept", json={
                "token": token, "password": "another long password"},
                headers=HDR).status_code

        results = race(lambda: accept(a1), lambda: accept(a2))
        assert sorted(results.values()) == [200, 400], results
        with session_scope(engine) as s:
            assert s.query(User).filter_by(
                email="racer@example.com").count() == 1
            invite = s.query(InviteToken).filter_by(
                email="racer@example.com").one()
            assert invite.used_at is not None


class TestApprovalExpiryAndOrder:
    def test_expired_approval_double_approve(self, engine):
        """An EXPIRED approval raced by two approvers: both get 410,
        the status flips to expired exactly once, and no command is
        ever queued."""
        from datetime import timedelta as _td
        from app.models import utcnow as _utcnow
        app = make_app(engine, "race-exp")
        aid = _request_erase(app)
        with session_scope(engine) as s:
            row = s.get(SensitiveCommandApproval, aid)
            row.expires_at = _utcnow() - _td(minutes=1)
        c1, c2 = TestClient(app), TestClient(app)
        login(c1, "b@example.com")
        login(c2, "b@example.com")

        def approve(c):
            return c.post(
                f"/api/mdm/sensitive-approvals/{aid}/approve",
                json={"totp_code": fresh_code(c, "b@example.com"),
                      "confirm": "EraseDevice"}, headers=HDR).status_code

        results = race(lambda: approve(c1), lambda: approve(c2))
        assert sorted(results.values()) == [410, 410], results
        with session_scope(engine) as s:
            assert s.get(SensitiveCommandApproval, aid).status == "expired"
        _, _, pk = app.state.test_ids
        cmds = c1.get(f"/api/mdm/enrollments/{pk}/commands").json()[
            "commands"]
        assert cmds == []


class TestDistinctTicketsSameDevice:
    def test_two_tickets_conflicting_udids(self, engine):
        """Two DIFFERENT tickets for the same device redeemed
        concurrently with different device UDIDs: the device row lock
        serializes them; the second is a 409 identity conflict and the
        device keeps exactly ONE current enrollment."""
        app = make_app(engine, "race-tt")
        _, dev, _ = app.state.test_ids
        c = TestClient(app)
        login(c, "a@example.com")
        with session_scope(engine) as s:
            # The fixture enrollment binds no UDID; remove it so both
            # tickets start from a clean device.
            s.query(MDMEnrollment).filter_by(device_id=dev).delete()
        t1 = c.post(f"/api/mdm/devices/{dev}/enrollment-tickets",
                    json={}, headers=HDR).json()
        t2 = c.post(f"/api/mdm/devices/{dev}/enrollment-tickets",
                    json={}, headers=HDR).json()
        anon = TestClient(app)

        def redeem(ticket, udid):
            return anon.post("/api/mdm/enroll", json={
                "ticket": ticket, "device_udid": udid}).status_code

        results = race(lambda: redeem(t1["ticket"], "UDID-AAA-0001"),
                       lambda: redeem(t2["ticket"], "UDID-BBB-0002"))
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            current = s.query(MDMEnrollment).filter_by(
                device_id=dev).filter(MDMEnrollment.state.in_(
                    ["pending", "enrolled"])).all()
            assert len(current) == 1


class TestOffboardingRaces:
    def _verified_case(self, app, engine, name):
        _, dev, _ = app.state.test_ids
        c = TestClient(app)
        login(c, "a@example.com")
        r = c.post("/api/offboarding/cases", json={
            "kind": "cancellation", "notes": "race"}, headers=HDR)
        assert r.status_code == 200, r.text
        case_id = r.json()["id"]
        r = c.post(f"/api/offboarding/cases/{case_id}/verify", json={
            "totp_code": fresh_code(c, "a@example.com"),
            "confirm": "verify-offboarding"}, headers=HDR)
        assert r.status_code == 200, r.text
        return c, case_id

    def test_complete_complete_race(self, engine):
        """Two completions of the SAME case: exactly one completes;
        the other sees the committed status."""
        app = make_app(engine, "race-oc")
        c, case_id = self._verified_case(app, engine, "race-oc")
        c2 = TestClient(app)
        login(c2, "a@example.com")

        def complete(cl):
            return cl.post(
                f"/api/offboarding/cases/{case_id}/complete",
                json={"totp_code": fresh_code(cl, "a@example.com"),
                      "confirm": "complete-offboarding"},
                headers=HDR).status_code

        results = race(lambda: complete(c), lambda: complete(c2))
        assert sorted(results.values()) == [200, 409], results

    def test_complete_cancel_race(self, engine):
        """Complete racing cancel: exactly one wins; the final status
        is exactly the winner's."""
        from app.models import OffboardingCase
        app = make_app(engine, "race-ox")
        c, case_id = self._verified_case(app, engine, "race-ox")
        c2 = TestClient(app)
        login(c2, "a@example.com")

        def complete():
            return c.post(
                f"/api/offboarding/cases/{case_id}/complete",
                json={"totp_code": fresh_code(c, "a@example.com"),
                      "confirm": "complete-offboarding"},
                headers=HDR).status_code

        def cancel():
            return c2.post(f"/api/offboarding/cases/{case_id}/cancel",
                           headers=HDR).status_code

        results = race(complete, cancel)
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            status = s.get(OffboardingCase, case_id).status
        if results["a"] == 200:
            assert status == "completed"
        else:
            assert status == "canceled"


class TestLastStaffOwnerRace:
    def test_two_owners_demote_each_other(self, engine):
        """The last-owner invariant under concurrency: two staff
        owners demote each other simultaneously. Exactly one succeeds;
        at least one staff owner always remains."""
        with session_scope(engine) as s:
            tenant = Tenant(name="race-so")
            s.add(tenant)
            s.flush()
            for email in ("sa@example.com", "sb@example.com"):
                s.add(User(tenant_id=tenant.id, email=email,
                           password_hash=security.hash_password(PASSWORD),
                           role=Role.owner, staff_role="owner"))
        settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                             "KG_PUBLICATIONS_ROOT": tempfile.mkdtemp(prefix="kg-pub-")})
        app = create_app(settings, engine=engine)
        ca, cb = TestClient(app), TestClient(app)
        login(ca, "sa@example.com")
        login(cb, "sb@example.com")
        with session_scope(engine) as s:
            ids = {u.email: u.id for u in s.query(User).all()}

        def demote(c, target):
            return c.post(f"/api/staff/{target}/role", json={
                "staff_role": "support_admin"}, headers=HDR).status_code

        results = race(lambda: demote(ca, ids["sb@example.com"]),
                       lambda: demote(cb, ids["sa@example.com"]))
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            owners = s.query(User).filter_by(staff_role="owner").count()
            assert owners == 1


class TestInviteUniquenessRace:
    def test_concurrent_invites_same_email(self, engine):
        """Two concurrent invites for the same email: the partial
        unique index admits exactly one active invite."""
        app = make_app(engine, "race-ii")
        c1, c2 = TestClient(app), TestClient(app)
        login(c1, "a@example.com")
        login(c2, "a@example.com")
        body = {"email": "dup@example.com", "role": "viewer"}

        def invite(c):
            return c.post("/api/guardians/invite", json=body,
                          headers=HDR).status_code

        results = race(lambda: invite(c1), lambda: invite(c2))
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            active = s.query(InviteToken).filter_by(
                email="dup@example.com", used_at=None).all()
            assert len(active) == 1


class TestPublicationVsExceptionRace:
    def _setup(self, app):
        c = TestClient(app)
        login(c, "a@example.com")
        body = {"name": "p", "default_policy": "allow",
                "blocklist": ["bad.example"], "allowlist": [],
                "category_allow": [], "category_block": []}
        r = c.post("/api/policies", json=body, headers=HDR)
        pid = r.json()["id"]
        assert c.post(f"/api/policies/{pid}/select",
                      headers=HDR).status_code == 200
        return c

    def test_publish_racing_exception_create(self, engine):
        """A publish racing an exception create: the tenant write lock
        serializes them - both succeed, no 5xx, no deadlock, and the
        tenant stays consistent (a later publish succeeds too)."""
        app = make_app(engine, "race-pe")
        c = self._setup(app)
        _, dev, _ = app.state.test_ids
        future = "2026-12-10T00:00:00+00:00"

        def publish():
            return c.post("/api/publications", headers=HDR).status_code

        def create_exc():
            return c.post("/api/exceptions", json={
                "kind": "allow_domains", "scope_type": "device",
                "device_id": dev, "domains": ["race.example"],
                "reason": "race", "expires_at": future},
                headers=HDR).status_code

        results = race(publish, create_exc)
        assert sorted(results.values()) == [200, 200], results
        # The snapshot must match the actual transaction order, not just
        # return two 200s. Both audits are flushed under the tenant lock,
        # so their IDs establish which transaction committed first.
        from app.models import AuditEvent
        with session_scope(engine) as session:
            tid = app.state.test_ids[0]
            events = session.query(AuditEvent).filter_by(tenant_id=tid).all()
            created = next(e.id for e in events if e.action == "exception.create")
            published = next(e.id for e in events if e.action == "publication.publish")
            eid = session.query(PolicyException).filter_by(tenant_id=tid).one().id
        overlay = TestWorkerPublicationMatrix()._overlay(app)
        ids = {e["exception_id"] for entries in overlay.values() for e in entries}
        assert (eid in ids) == (created < published), (created, published, overlay)
        # A later publication MUST include the committed create, no matter
        # which of the original racing transactions won the lock first.
        assert c.post("/api/publications", headers=HDR).status_code == 200
        assert {e["exception_id"] for entries in
                TestWorkerPublicationMatrix()._overlay(app).values()
                for e in entries} == {eid}

    def test_publish_racing_exception_revoke(self, engine):
        """A publish racing an exception revoke (which enqueues its
        own cleanup publication): no lock-order deadlock, both calls
        succeed, and the exception ends revoked."""
        app = make_app(engine, "race-pr")
        c = self._setup(app)
        _, dev, _ = app.state.test_ids
        future = "2026-12-10T00:00:00+00:00"
        r = c.post("/api/exceptions", json={
            "kind": "allow_domains", "scope_type": "device",
            "device_id": dev, "domains": ["race2.example"],
            "reason": "race", "expires_at": future}, headers=HDR)
        assert r.status_code == 200, r.text
        eid = r.json()["id"]

        def publish():
            return c.post("/api/publications", headers=HDR).status_code

        def revoke():
            return c.delete(f"/api/exceptions/{eid}",
                            headers=HDR).status_code

        results = race(publish, revoke)
        assert sorted(results.values()) == [200, 200], results
        rows = c.get("/api/exceptions").json()["exceptions"]
        item = [x for x in rows if x["id"] == eid][0]
        assert item["active"] is False


class TestLoginRateLimitRace:
    def test_concurrent_failures_not_lost(self, engine):
        """Concurrent failed logins against the same email+client key:
        every failure is counted (FOR UPDATE + savepoint upsert), so
        the lockout engages exactly at MAX_FAILURES."""
        app = make_app(engine, "race-rl")
        c = TestClient(app)
        barrier = threading.Barrier(5)
        results = []

        def fail():
            barrier.wait(timeout=10)
            r = c.post("/api/auth/login", json={
                "email": "a@example.com",
                "password": "definitely wrong password"}, headers=HDR)
            results.append(r.status_code)

        threads = [threading.Thread(target=fail) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        # All five are counted; after 5 failures the key is locked, so
        # any mix of 401 (counted) and 429 (already locked) is fine -
        # but the persisted count must be exactly 5, never less.
        with session_scope(engine) as s:
            rows = s.query(LoginAttempt).all()
            assert len(rows) == 1
            assert rows[0].failures >= 5
        # The next attempt is locked out even with the right password.
        r = c.post("/api/auth/login", json={
            "email": "a@example.com", "password": PASSWORD}, headers=HDR)
        assert r.status_code == 429


class TestAdditionalConcurrencyMatrix:
    def test_legacy_enrollment_vs_ticket(self, engine):
        app = make_app(engine, "race-legacy")
        _, dev, _ = app.state.test_ids
        c = TestClient(app)
        login(c, "a@example.com")
        with session_scope(engine) as s:
            s.query(MDMEnrollment).filter_by(device_id=dev).delete()
        t = c.post(f"/api/mdm/devices/{dev}/enrollment-tickets", json={}, headers=HDR).json()["ticket"]
        anonymous = TestClient(app)
        results = race(lambda: c.post("/api/mdm/enrollments", json={"device_id": dev, "device_udid": "LEGACY-UDID"}, headers=HDR).status_code,
                       lambda: anonymous.post("/api/mdm/enroll", json={"ticket": t, "device_udid": "TICKET-UDID"}).status_code)
        assert sorted(results.values()) == [200, 409], results
        with session_scope(engine) as s:
            assert s.query(MDMEnrollment).filter_by(device_id=dev).filter(MDMEnrollment.state.in_(["pending", "enrolled"])).count() == 1

    def test_exception_approve_reject(self, engine):
        from app.models import AuditEvent
        app = make_app(engine, "race-er-decide")
        tid, dev, _ = app.state.test_ids
        a, b = TestClient(app), TestClient(app)
        login(a, "a@example.com")
        login(b, "b@example.com")
        r = a.post("/api/exception-requests", json={"kind": "allow_domains", "scope_type": "device", "device_id": dev, "domains": ["test.example"], "reason": "race", "duration_minutes": 60}, headers=HDR)
        assert r.status_code == 200, r.text
        rid = r.json()["id"]
        result = race(lambda: a.post(f"/api/exception-requests/{rid}/approve", json={}, headers=HDR).status_code,
                      lambda: b.post(f"/api/exception-requests/{rid}/reject", json={"reason": "no"}, headers=HDR).status_code)
        assert sorted(result.values()) == [200, 409]
        with session_scope(engine) as s:
            row = s.get(ExceptionRequest, rid)
            assert row.status == ("approved" if result["a"] == 200 else "rejected")
            assert s.query(PolicyException).filter_by(tenant_id=tid).count() == (1 if result["a"] == 200 else 0)

    def test_mfa_confirmation_parallel_failures(self, engine):
        app = make_app(engine, "race-mfa")
        c = TestClient(app)
        assert c.post("/api/auth/login", json={"email": "a@example.com", "password": PASSWORD}, headers=HDR).status_code == 200
        assert c.post("/api/auth/mfa/enroll-start", headers=HDR).status_code == 200
        barrier = threading.Barrier(5)
        results = []
        def fail():
            barrier.wait(timeout=10)
            cl = TestClient(app)
            cl.cookies.update(c.cookies)
            results.append(cl.post("/api/auth/mfa/enroll-confirm", json={"password": "wrong password", "code": "000000"}, headers=HDR).status_code)
        threads = [threading.Thread(target=fail) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join(60)
        assert len(results) == 5 and set(results) <= {403, 429}, results
        with session_scope(engine) as s:
            row = s.query(LoginAttempt).one()
            assert row.failures == 5
        assert c.post("/api/auth/mfa/enroll-confirm", json={"password": PASSWORD, "code": "000000"}, headers=HDR).status_code == 429

    def test_offboarding_attest_vs_complete(self, engine):
        app = make_app(engine, "race-attest")
        a, case = TestOffboardingRaces()._verified_case(app, engine, "race-attest")
        b = TestClient(app)
        login(b, "a@example.com")
        result = race(lambda: a.post(f"/api/offboarding/cases/{case}/complete", json={"totp_code": fresh_code(a, "a@example.com"), "confirm": "complete-offboarding"}, headers=HDR).status_code,
                      lambda: b.post(f"/api/offboarding/cases/{case}/attest", json={"step": "abm_release", "totp_code": fresh_code(b, "a@example.com"), "confirm": "attest-abm_release"}, headers=HDR).status_code)
        assert result["a"] == 200 and result["b"] in (200, 409), result
        from app.models import OffboardingCase
        with session_scope(engine) as s:
            assert s.get(OffboardingCase, case).status == "completed"


class TestWorkerPublicationMatrix:
    def _overlay(self, app):
        import json
        from app.publication_ops import tenant_root
        from app.publisher import Publisher
        tid, _, _ = app.state.test_ids
        publisher = Publisher(tenant_root(app.state.test_settings.publications_root, tid))
        m = publisher.current()
        path = publisher.generations_dir / m["generation"] / "exceptions.json"
        return json.loads(path.read_bytes()) if path.exists() else {}

    def test_first_worker_publish_vs_exception_approval(self, engine):
        from app.worker import run_once
        app = make_app(engine, "first-worker-approval")
        c = TestPublicationVsExceptionRace()._setup(app)
        _, dev, _ = app.state.test_ids
        r = c.post("/api/exception-requests", json={"kind": "allow_domains", "scope_type": "device", "device_id": dev, "domains": ["worker.example"], "reason": "race", "duration_minutes": 60}, headers=HDR)
        assert r.status_code == 200, r.text
        rid = r.json()["id"]
        assert c.post("/api/publications/jobs", json={"request_key": "first"}, headers=HDR).status_code == 200
        result = race(lambda: 200 if run_once(engine, app.state.test_settings) else 409,
                      lambda: c.post(f"/api/exception-requests/{rid}/approve", json={}, headers=HDR).status_code)
        assert list(result.values()).count(200) == 2, result
        assert c.post("/api/publications", headers=HDR).status_code == 200
        entries = self._overlay(app)[str(dev)]
        assert len(entries) == 1 and entries[0]["domains"] == ["worker.example"]

    def test_worker_activation_crash_then_revoke_cannot_resurrect(self, engine):
        from app.worker import run_once
        from app.publication_ops import publish_selected
        from app.models import PublicationJob
        app = make_app(engine, "worker-crash-revoke")
        c = TestPublicationVsExceptionRace()._setup(app)
        tid, dev, _ = app.state.test_ids
        r = c.post("/api/exceptions", json={"kind": "allow_domains", "scope_type": "device", "device_id": dev, "domains": ["crash.example"], "reason": "race", "expires_at": (utcnow() + __import__('datetime').timedelta(hours=1)).isoformat()}, headers=HDR)
        assert r.status_code == 200, r.text
        eid = r.json()["id"]
        jid = c.post("/api/publications/jobs", json={"request_key": "crash"}, headers=HDR).json()["id"]
        with session_scope(engine) as s:
            job = s.get(PublicationJob, jid)
            publish_selected(s, tid, app.state.test_settings.publications_root, job.actor_email, publication_job_id=jid)
            s.rollback()
        result = race(lambda: 200 if run_once(engine, app.state.test_settings) else 409,
                      lambda: c.delete(f"/api/exceptions/{eid}", headers=HDR).status_code)
        assert list(result.values()).count(200) == 2, result
        assert run_once(engine, app.state.test_settings)  # durable narrow cleanup
        assert self._overlay(app) == {}
        with session_scope(engine) as s:
            assert s.get(PolicyException, eid).revoked_at is not None
