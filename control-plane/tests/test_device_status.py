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
