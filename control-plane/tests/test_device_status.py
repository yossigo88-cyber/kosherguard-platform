"""Device status chain in GET /api/devices (Answer 23 update-state
measurement; spec Part 2A: see device online/offline/stale and the
last confirmed update).

Honest layering, asserted in tests: connectivity is derived from
stored device check-in receipts only (never_reported /
recently_reporting / stale / offline); last_confirmed_update is the
latest stored device receipt (acknowledged command or DDM status
report); nothing claims verified on-device enforcement.
"""

import os
import sys
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (DDMStatusReport, Device, MDMCommand,  # noqa: E402
                        MDMEnrollment, Role, Tenant, User, utcnow)

from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_app(engine):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-x")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="owner@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        fresh = Device(tenant_id=tenant.id, name="fresh-iphone")
        stale = Device(tenant_id=tenant.id, name="stale-ipad")
        offline = Device(tenant_id=tenant.id, name="offline-mac")
        plain = Device(tenant_id=tenant.id, name="never-seen")
        s.add_all([fresh, stale, offline, plain])
        s.flush()
        enr_fresh = MDMEnrollment(
            tenant_id=tenant.id, device_id=fresh.id,
            enrollment_id="enr-fresh", state="enrolled",
            supervision_requested=True, supervision_verified=True,
            last_seen_at=utcnow() - timedelta(minutes=10))
        enr_stale = MDMEnrollment(
            tenant_id=tenant.id, device_id=stale.id,
            enrollment_id="enr-stale", state="enrolled",
            supervision_requested=True, supervision_verified=False,
            last_seen_at=utcnow() - timedelta(hours=5))
        enr_off = MDMEnrollment(
            tenant_id=tenant.id, device_id=offline.id,
            enrollment_id="enr-off", state="pending",
            last_seen_at=utcnow() - timedelta(days=3))
        s.add_all([enr_fresh, enr_stale, enr_off])
        s.flush()
        s.add(MDMCommand(tenant_id=tenant.id,
                         enrollment_pk=enr_fresh.id,
                         command="DeviceLock", status="acknowledged",
                         applied=True,
                         updated_at=utcnow() - timedelta(minutes=30)))
        s.add(MDMCommand(tenant_id=tenant.id,
                         enrollment_pk=enr_fresh.id,
                         command="ProfileList", status="queued"))
        s.add(DDMStatusReport(tenant_id=tenant.id,
                              enrollment_id="enr-fresh",
                              body="{}", declaration_states="{}",
                              received_at=utcnow() - timedelta(minutes=5)))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    return create_app(settings, engine=engine)


def devices_by_name(client):
    rows = client.get("/api/devices").json()["devices"]
    return {d["name"]: d for d in rows}


class TestDeviceStatusChain:
    def test_connectivity_classes_from_receipts(self, engine):
        c = TestClient(make_app(engine))
        mfa_login(c, json={"email": "owner@example.com",
                           "password": PASSWORD}, headers=HDR)
        d = devices_by_name(c)
        assert d["fresh-iphone"]["connectivity"] == "recently_reporting"
        assert d["stale-ipad"]["connectivity"] == "stale"
        assert d["offline-mac"]["connectivity"] == "offline"
        assert d["never-seen"]["connectivity"] == "never_reported"

    def test_enrollment_and_receipt_fields(self, engine):
        c = TestClient(make_app(engine))
        mfa_login(c, json={"email": "owner@example.com",
                           "password": PASSWORD}, headers=HDR)
        d = devices_by_name(c)
        enr = d["fresh-iphone"]["enrollment"]
        assert enr["state"] == "enrolled"
        assert enr["supervision_verified"] is True
        assert enr["last_seen_at"] is not None
        assert d["never-seen"]["enrollment"] is None
        # last device receipt = latest stored receipt (the DDM
        # report 5 min ago is newer than the ack 30 min ago); it is
        # NOT labeled a confirmed policy application
        last = d["fresh-iphone"]["last_device_receipt"]
        assert last is not None
        assert "not a confirmed policy application" in \
            d["fresh-iphone"]["last_device_receipt_basis"]
        assert d["never-seen"]["last_device_receipt"] is None
        # per-change push chain from the server command ledger
        chain = d["fresh-iphone"]["push_chain"]
        assert chain["pending"] == 1
        assert chain["by_status"] == {"acknowledged": 1, "queued": 1}
        assert chain["latest_command"]["command"] == "ProfileList"
        assert chain["latest_command"]["status"] == "queued"
        assert d["stale-ipad"]["push_chain"]["pending"] == 0
        # reported-vs-published: no app policy assigned in this
        # fixture, so nothing is served; an unenrolled device has no
        # enrollment state at all
        assert d["fresh-iphone"]["reported_vs_published"] == \
            "no_declarations_served"
        assert d["never-seen"]["reported_vs_published"] == \
            "no_enrollment"

    def test_honest_labels_present(self, engine):
        c = TestClient(make_app(engine))
        mfa_login(c, json={"email": "owner@example.com",
                           "password": PASSWORD}, headers=HDR)
        for row in devices_by_name(c).values():
            assert "not live presence" in row["connectivity_basis"]
            assert "not verified" in row["enforcement_note"]
            assert "published_revision" in row
            assert "not verified enforcement" in \
                row["reported_vs_published_basis"]


def make_app_with_app_policy(engine, bundle_ids='["com.example.game"]'):
    """Fixture with a served declaration: one device with an app
    policy, so ddm_ops.configurations() returns a real declaration
    whose identifier + server-token the comparison checks."""
    with session_scope(engine) as s:
        tenant = Tenant(name="family-y")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="owner@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        d = Device(tenant_id=tenant.id, name="managed-iphone",
                   state="managed")
        d2 = Device(tenant_id=tenant.id, name="other-ipad",
                    state="managed")
        s.add_all([d, d2])
        s.flush()
        e = MDMEnrollment(tenant_id=tenant.id, device_id=d.id,
                          enrollment_id="enr-main", state="enrolled",
                          supervision_requested=True,
                          supervision_verified=True,
                          last_seen_at=utcnow())
        e2 = MDMEnrollment(tenant_id=tenant.id, device_id=d2.id,
                           enrollment_id="enr-other", state="enrolled",
                           last_seen_at=utcnow())
        s.add_all([e, e2])
        s.flush()
        from app.models import DeviceAppPolicy
        s.add(DeviceAppPolicy(tenant_id=tenant.id, device_id=d.id,
                              mode="blocklist", bundle_ids=bundle_ids))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    return create_app(settings, engine=engine)


def served_token(engine):
    from app import ddm_ops
    with session_scope(engine) as s:
        enr = s.scalar(select(MDMEnrollment).where(
            MDMEnrollment.enrollment_id == "enr-main"))
        configs = ddm_ops.configurations(s, enr)
        assert len(configs) == 1
        return configs[0]["Identifier"], configs[0]["ServerToken"]


def add_ddm_report(engine, enrollment_id, states):
    import json as _json
    with session_scope(engine) as s:
        tenant = s.scalar(select(Tenant).where(
            Tenant.name == "family-y"))
        s.add(DDMStatusReport(
            tenant_id=tenant.id, enrollment_id=enrollment_id,
            body="{}", declaration_states=_json.dumps(states)))


def reported_state(client, name="managed-iphone"):
    mfa_login(client, json={"email": "owner@example.com",
                            "password": PASSWORD}, headers=HDR)
    return devices_by_name(client)[name]


class TestReportedVsPublished:
    def test_matching_report_counts_as_reported_applied(self, engine):
        c = TestClient(make_app_with_app_policy(engine))
        ident, token = served_token(engine)
        add_ddm_report(engine, "enr-main", {
            ident: {"server_token": token, "active": True,
                    "valid": "valid"}})
        row = reported_state(c)
        assert row["reported_vs_published"] == "all_served_reported_applied"
        assert "not verified enforcement" in row["reported_vs_published_basis"]

    def test_stale_token_is_not_reported_applied(self, engine):
        c = TestClient(make_app_with_app_policy(engine))
        ident, _token = served_token(engine)
        add_ddm_report(engine, "enr-main", {
            ident: {"server_token": "stale-token", "active": True,
                    "valid": "valid"}})
        assert reported_state(c)["reported_vs_published"] == "served_not_fully_reported"

    def test_inactive_declaration_is_not_reported_applied(self, engine):
        c = TestClient(make_app_with_app_policy(engine))
        ident, token = served_token(engine)
        add_ddm_report(engine, "enr-main", {
            ident: {"server_token": token, "active": False,
                    "valid": "valid"}})
        assert reported_state(c)["reported_vs_published"] == "served_not_fully_reported"

    def test_invalid_declaration_is_not_reported_applied(self, engine):
        c = TestClient(make_app_with_app_policy(engine))
        ident, token = served_token(engine)
        add_ddm_report(engine, "enr-main", {
            ident: {"server_token": token, "active": True,
                    "valid": "invalid"}})
        assert reported_state(c)["reported_vs_published"] == "served_not_fully_reported"

    def test_report_without_declarations_is_not_applied(self, engine):
        c = TestClient(make_app_with_app_policy(engine))
        add_ddm_report(engine, "enr-main", {})
        assert reported_state(c)["reported_vs_published"] == "served_not_fully_reported"

    def test_other_enrollments_report_does_not_count(self, engine):
        c = TestClient(make_app_with_app_policy(engine))
        ident, token = served_token(engine)
        # the receipt arrived - but from a DIFFERENT enrollment
        add_ddm_report(engine, "enr-other", {
            ident: {"server_token": token, "active": True,
                    "valid": "valid"}})
        assert reported_state(c)["reported_vs_published"] == "no_report_received"

    def test_comparison_error_is_not_silenced(self, engine):
        # a corrupt stored policy makes the served-declaration
        # computation fail; the state must say unavailable, never
        # pretend nothing is served
        c = TestClient(make_app_with_app_policy(
            engine, bundle_ids="not-json"))
        add_ddm_report(engine, "enr-main", {})
        assert reported_state(c)["reported_vs_published"] == "comparison_unavailable"

    def test_apns_state_is_unavailable_not_inferred(self, engine):
        c = TestClient(make_app_with_app_policy(engine))
        row = reported_state(c)
        assert row["push_chain"]["apns"] == "unavailable"
        assert "not observed" in row["push_chain"]["apns_basis"]


def test_old_enrollment_commands_do_not_affect_current_status(engine):
    app = make_app(engine)
    c = TestClient(app)
    mfa_login(c, json={"email": "owner@example.com", "password": PASSWORD}, headers=HDR)
    with session_scope(engine) as s:
        old = s.query(MDMEnrollment).filter_by(enrollment_id="enr-fresh").one()
        old.state = "replaced"
        s.flush()
        new = MDMEnrollment(tenant_id=old.tenant_id, device_id=old.device_id,
                            enrollment_id="new-current", state="enrolled")
        s.add(new)
    row = devices_by_name(c)["fresh-iphone"]
    # No command in the new cycle, despite ack+queued commands in the old.
    assert row["last_device_receipt"] is None
    assert row["push_chain"]["pending"] == 0
    assert row["push_chain"]["by_status"] == {}
    assert row["push_chain"]["latest_command"] is None
