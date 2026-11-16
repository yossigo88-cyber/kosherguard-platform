"""Milestone 2 policy API tests, including the tighten-only invariant."""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}

BASE = {"default_policy": "allow", "blocklist": ["bad.example"],
        "allowlist": [], "category_allow": [], "category_block": []}
TIGHTER = dict(BASE, category_block=["adult"])
LOOSER = {"default_policy": "allow", "blocklist": [], "allowlist": [],
          "category_allow": [], "category_block": []}


@pytest.fixture()
def client(engine):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-p")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="g@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
              "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"})
    c = TestClient(create_app(settings, engine=engine))
    r = c.post("/api/auth/login",
               json={"email": "g@example.com", "password": PASSWORD},
               headers=HDR)
    assert r.status_code == 200
    return c


def mkpolicy(c, name, **doc):
    body = {"name": name, **doc}
    return c.post("/api/policies", json=body, headers=HDR)


class TestPolicies:
    def test_create_and_list(self, client):
        r = mkpolicy(client, "base", **BASE)
        assert r.status_code == 200, r.json()
        assert r.json()["versions"] == 1
        listing = client.get("/api/policies").json()["policies"]
        assert [p["name"] for p in listing] == ["base"]
        assert listing[0]["blocklist"] == ["bad.example"]

    def test_duplicate_name_rejected(self, client):
        assert mkpolicy(client, "base", **BASE).status_code == 200
        assert mkpolicy(client, "base", **BASE).status_code == 409

    def test_invalid_rules_rejected(self, client):
        r = mkpolicy(client, "bad", default_policy="sideways")
        assert r.status_code == 400

    def test_update_creates_version(self, client):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        r = client.put(f"/api/policies/{pid}",
                       json={"name": "base", **TIGHTER}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["versions"] == 2

    def test_assignment_tighten_only(self, client):
        default = mkpolicy(client, "default", **TIGHTER).json()["id"]
        client.post(f"/api/policies/{default}/select", headers=HDR)
        looser = mkpolicy(client, "looser", **LOOSER).json()["id"]
        device = client.post("/api/devices", json={"name": "phone-1"},
                             headers=HDR).json()["id"]
        r = client.post(f"/api/devices/{device}/assignment",
                        json={"policy_id": looser}, headers=HDR)
        assert r.status_code == 409
        tighter = mkpolicy(client, "tighter", **dict(
            TIGHTER, blocklist=["bad.example", "worse.example"])
        ).json()["id"]
        r = client.post(f"/api/devices/{device}/assignment",
                        json={"policy_id": tighter}, headers=HDR)
        assert r.status_code == 200, r.json()

    def test_default_reselection_recHECKS_assignments(self, client):
        default = mkpolicy(client, "default", **LOOSER).json()["id"]
        client.post(f"/api/policies/{default}/select", headers=HDR)
        mid = mkpolicy(client, "mid", **BASE).json()["id"]
        device = client.post("/api/devices", json={"name": "phone-2"},
                             headers=HDR).json()["id"]
        assert client.post(f"/api/devices/{device}/assignment",
                           json={"policy_id": mid},
                           headers=HDR).status_code == 200
        # Selecting a stricter default would loosen the existing
        # assignment relative to the default: refused.
        strict = mkpolicy(client, "strict", **TIGHTER).json()["id"]
        r = client.post(f"/api/policies/{strict}/select", headers=HDR)
        assert r.status_code == 409

    def test_cross_tenant_policy_invisible(self, client, engine):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        with session_scope(engine) as s:
            other = Tenant(name="other-family")
            s.add(other)
            s.flush()
            s.add(User(tenant_id=other.id, email="o@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        c2 = TestClient(client.app)
        c2.post("/api/auth/login",
                json={"email": "o@example.com", "password": PASSWORD},
                headers=HDR)
        assert c2.get("/api/policies").json()["policies"] == []
        r = c2.put(f"/api/policies/{pid}",
                   json={"name": "stolen", **BASE}, headers=HDR)
        assert r.status_code == 404


SCHED = {"name": "bedtime", "days": [0, 1, 2, 3, 4], "start": "21:00",
         "end": "06:30", "timezone": "America/New_York",
         "block_categories": ["games"], "block_domains": ["fun.example"],
         "enabled": True}


class TestSchedules:
    def test_replace_and_read_back(self, client):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        r = client.put(f"/api/policies/{pid}/schedules",
                       json={"schedules": [SCHED]}, headers=HDR)
        assert r.status_code == 200, r.json()
        body = r.json()
        assert body["versions"] == 2
        assert len(body["schedules"]) == 1
        assert body["schedules"][0]["name"] == "bedtime"
        assert body["schedules"][0]["start"] == 21 * 60
        listing = client.get("/api/policies").json()["policies"]
        assert listing[0]["schedules"][0]["name"] == "bedtime"

    def test_invalid_schedule_rejected_400(self, client):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        bad = dict(SCHED, timezone="Monsey")
        r = client.put(f"/api/policies/{pid}/schedules",
                       json={"schedules": [bad]}, headers=HDR)
        assert r.status_code == 400
        assert "timezone" in r.json()["error"]
        # Nothing was written: still version 1, no schedules.
        p = client.get("/api/policies").json()["policies"][0]
        assert p["versions"] == 1 and p["schedules"] == []

    def test_clear_with_empty_list(self, client):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [SCHED]}, headers=HDR)
        r = client.put(f"/api/policies/{pid}/schedules",
                       json={"schedules": []}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["schedules"] == []

    def test_general_update_preserves_schedules(self, client):
        """Editing a policy must not silently drop its schedules (that
        would loosen filtering without anyone asking)."""
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [SCHED]}, headers=HDR)
        r = client.put(f"/api/policies/{pid}",
                       json={"name": "base", **TIGHTER}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["schedules"][0]["name"] == "bedtime"

    def test_create_with_schedules(self, client):
        r = mkpolicy(client, "base", schedules=[SCHED], **BASE)
        assert r.status_code == 200, r.json()
        assert r.json()["schedules"][0]["name"] == "bedtime"

    def test_cross_tenant_schedules_invisible(self, client, engine):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        with session_scope(engine) as s:
            other = Tenant(name="other-family")
            s.add(other)
            s.flush()
            s.add(User(tenant_id=other.id, email="o@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        c2 = TestClient(client.app)
        c2.post("/api/auth/login",
                json={"email": "o@example.com", "password": PASSWORD},
                headers=HDR)
        r = c2.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [SCHED]}, headers=HDR)
        assert r.status_code == 404

    def test_audit_event_written(self, client, engine):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [SCHED]}, headers=HDR)
        with session_scope(engine) as s:
            from app.models import AuditEvent
            from sqlalchemy import select
            actions = [a.action for a in s.scalars(select(AuditEvent))]
        assert "policy.schedules" in actions


class TestScheduleTightenOnly:
    """The reviewed comparator drops _schedules as metadata, so base-rule
    comparison alone cannot prove a candidate is at least as restrictive
    when the baseline blocks things on a schedule. Schedule-aware
    coverage must close that gap."""

    def _default_with_schedule(self, client):
        mkpolicy(client, "default", **BASE)
        pid = client.get("/api/policies").json()["policies"][0]["id"]
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [SCHED]}, headers=HDR)
        client.post(f"/api/policies/{pid}/select", headers=HDR, json={})
        return pid

    def _assign(self, client, policy_name, **doc):
        pid = mkpolicy(client, policy_name, **doc).json()["id"]
        did = client.post("/api/devices", json={"name": "kid-phone"},
                          headers=HDR).json()["id"]
        return client.post(f"/api/devices/{did}/assignment",
                           json={"policy_id": pid}, headers=HDR), pid, did

    def test_assignment_without_default_schedule_refused(self, client):
        """REPRODUCED GAP (fixed): base rules identical, but the
        candidate lacks the default's bedtime schedule - during the
        window that device would filter weaker than the baseline."""
        self._default_with_schedule(client)
        r, _, _ = self._assign(client, "no-schedule", **BASE)
        assert r.status_code == 409, r.json()
        assert "schedule" in r.json()["error"].lower()

    def test_assignment_with_covering_schedule_accepted(self, client):
        self._default_with_schedule(client)
        r, pid, _ = self._assign(client, "with-schedule", **BASE)
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [SCHED]}, headers=HDR)
        r2 = client.post(
            f"/api/devices/{client.get('/api/devices').json()['devices'][0]['id']}/assignment",
            json={"policy_id": pid}, headers=HDR)
        assert r2.status_code == 200, r2.json()

    def test_wider_window_covers(self, client):
        self._default_with_schedule(client)
        wider = dict(SCHED, start="20:00", end="07:00")
        r, pid, _ = self._assign(client, "wider", **BASE)
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [wider]}, headers=HDR)
        did = client.get("/api/devices").json()["devices"][0]["id"]
        r2 = client.post(f"/api/devices/{did}/assignment",
                         json={"policy_id": pid}, headers=HDR)
        assert r2.status_code == 200, r2.json()

    def test_narrower_window_refused(self, client):
        self._default_with_schedule(client)
        narrower = dict(SCHED, start="22:00")
        r, pid, _ = self._assign(client, "narrower", **BASE)
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [narrower]}, headers=HDR)
        did = client.get("/api/devices").json()["devices"][0]["id"]
        r2 = client.post(f"/api/devices/{did}/assignment",
                         json={"policy_id": pid}, headers=HDR)
        assert r2.status_code == 409, r2.json()

    def test_missing_schedule_blocks_refused(self, client):
        self._default_with_schedule(client)
        weaker = dict(SCHED, block_categories=[], block_domains=[])
        r, pid, _ = self._assign(client, "weaker", **BASE)
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [weaker]}, headers=HDR)
        did = client.get("/api/devices").json()["devices"][0]["id"]
        r2 = client.post(f"/api/devices/{did}/assignment",
                         json={"policy_id": pid}, headers=HDR)
        assert r2.status_code == 409, r2.json()

    def test_base_rules_covering_blocks_accepted(self, client):
        """A candidate that ALWAYS blocks what the default blocks on a
        schedule needs no schedule at all (always >= sometimes)."""
        self._default_with_schedule(client)
        always = dict(BASE, category_block=["games"],
                      blocklist=["bad.example", "fun.example"])
        r, _, _ = self._assign(client, "always-block", **always)
        assert r.status_code == 200, r.json()

    def test_timezone_mismatch_refused(self, client):
        self._default_with_schedule(client)
        other_tz = dict(SCHED, timezone="Europe/London")
        r, pid, _ = self._assign(client, "other-tz", **BASE)
        client.put(f"/api/policies/{pid}/schedules",
                   json={"schedules": [other_tz]}, headers=HDR)
        did = client.get("/api/devices").json()["devices"][0]["id"]
        r2 = client.post(f"/api/devices/{did}/assignment",
                         json={"policy_id": pid}, headers=HDR)
        assert r2.status_code == 409, r2.json()


class TestDefaultMutationReproof:
    """Mutating the SELECTED DEFAULT must re-prove every active
    assignment against the proposed new baseline: after a strengthening
    mutation, an assignment that no longer covers the default would
    filter weaker than the baseline - the invariant the whole
    tighten-only design exists to keep."""

    def _setup(self, client):
        did_default = mkpolicy(client, "default", **BASE).json()["id"]
        client.post(f"/api/policies/{did_default}/select",
                    headers=HDR, json={})
        pid = mkpolicy(client, "kid", **BASE).json()["id"]
        did = client.post("/api/devices", json={"name": "kid-phone"},
                          headers=HDR).json()["id"]
        r = client.post(f"/api/devices/{did}/assignment",
                        json={"policy_id": pid}, headers=HDR)
        assert r.status_code == 200
        return did_default, pid

    def test_strengthen_default_base_rules_refused(self, client):
        dpid, _ = self._setup(client)
        stronger = dict(BASE, category_block=["games"])
        r = client.put(f"/api/policies/{dpid}",
                       json={"name": "default", **stronger}, headers=HDR)
        assert r.status_code == 409, r.json()
        assert "kid" in r.json()["error"]
        # Unchanged: default still has the old document.
        doc = client.get("/api/policies").json()["policies"][0]
        assert doc["category_block"] == []

    def test_strengthen_default_schedules_refused(self, client):
        dpid, _ = self._setup(client)
        r = client.put(f"/api/policies/{dpid}/schedules",
                       json={"schedules": [SCHED]}, headers=HDR)
        assert r.status_code == 409, r.json()

    def test_strengthen_default_covered_assignment_accepted(self, client):
        dpid, pid = self._setup(client)
        # Tighten the assigned policy first so it covers the new baseline.
        tighter = dict(BASE, category_block=["games"])
        r = client.put(f"/api/policies/{pid}",
                       json={"name": "kid", **tighter}, headers=HDR)
        assert r.status_code == 200, r.json()
        r = client.put(f"/api/policies/{dpid}",
                       json={"name": "default", **tighter}, headers=HDR)
        assert r.status_code == 200, r.json()

    def test_weaken_default_allowed(self, client):
        dpid, _ = self._setup(client)
        weaker = dict(BASE, blocklist=[])
        r = client.put(f"/api/policies/{dpid}",
                       json={"name": "default", **weaker}, headers=HDR)
        assert r.status_code == 200, r.json()

    def test_disable_selected_default_refused(self, client):
        dpid, _ = self._setup(client)
        r = client.put(f"/api/policies/{dpid}",
                       json={"name": "default", "enabled": False, **BASE},
                       headers=HDR)
        assert r.status_code == 409, r.json()

    def test_mutate_assigned_default_policy_itself_ok(self, client):
        """A device assigned to the default policy itself must not
        deadlock default mutations (its assignment is the baseline)."""
        dpid, _ = self._setup(client)
        did = client.post("/api/devices", json={"name": "parent-phone"},
                          headers=HDR).json()["id"]
        r = client.post(f"/api/devices/{did}/assignment",
                        json={"policy_id": dpid}, headers=HDR)
        assert r.status_code == 200, r.json()
        stronger = dict(BASE, category_block=["games"])
        # kid-phone's assignment (plain BASE) no longer covers: refused.
        r = client.put(f"/api/policies/{dpid}",
                       json={"name": "default", **stronger}, headers=HDR)
        assert r.status_code == 409, r.json()
