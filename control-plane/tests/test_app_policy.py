"""Application management API (spec Part 10: Applications).

Covers the stored per-device allow/block policy and the app command
routing. Delivery is exercised with the simulated adapter only where
the queueing contract matters; on-device behavior of the generated
payloads is BUILT-UNVERIFIED (see mdm/app_management.py).
"""

import json
import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (DeviceAppPolicy, MDMCommand, Role, Tenant,  # noqa: E402
                        User)

from mdm.app_management import (LEGACY_PROFILE_IDENTIFIERS,  # noqa: E402
                                PROFILE_IDENTIFIER)

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}


def make_client(engine, email="apps@example.com",
                tenant_name="family-apps"):
    with session_scope(engine) as s:
        tenant = Tenant(name=tenant_name)
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
    c = TestClient(create_app(Settings(env), engine=engine))
    r = mfa_login(c, json={'email': email, 'password': PASSWORD}, headers=HDR)
    assert r.status_code == 200
    return c


@pytest.fixture()
def client(engine):
    return make_client(engine)


def mk_device(c, name="phone-apps"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


def mk_enrollment(c, device_id):
    r = c.post("/api/mdm/enrollments",
               json={"device_id": device_id,
                     "supervision_requested": True}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


class TestAppPolicy:
    def test_default_policy_when_unsaved(self, client):
        dev = mk_device(client)
        r = client.get(f"/api/devices/{dev}/app-policy")
        assert r.status_code == 200
        assert r.json() == {"mode": "blocklist", "bundle_ids": [],
                            "saved": False, "applied": False,
                            "shield_active": False}

    def test_put_get_roundtrip(self, client):
        dev = mk_device(client)
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "allowlist",
                             "bundle_ids": ["com.good.one", "com.good.two"]},
                       headers=HDR)
        assert r.status_code == 200, r.json()
        got = client.get(f"/api/devices/{dev}/app-policy").json()
        assert got["mode"] == "allowlist"
        assert got["bundle_ids"] == ["com.good.one", "com.good.two"]
        assert got["saved"] is True

    def test_put_rejects_bad_mode_and_bad_bundle_id(self, client):
        dev = mk_device(client)
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "somelist", "bundle_ids": []},
                       headers=HDR)
        assert r.status_code == 400
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "blocklist",
                             "bundle_ids": ["not a bundle id"]},
                       headers=HDR)
        assert r.status_code == 400

    def test_put_rejects_unknown_device(self, client):
        r = client.put("/api/devices/99999/app-policy",
                       json={"mode": "blocklist", "bundle_ids": []},
                       headers=HDR)
        assert r.status_code == 404

    def test_policy_is_tenant_scoped(self, client, engine):
        dev = mk_device(client)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "allowlist", "bundle_ids": ["com.a.b"]},
                   headers=HDR)
        c2 = make_client(engine, email="other@example.com",
                         tenant_name="family-other-apps")
        r = c2.get(f"/api/devices/{dev}/app-policy")
        assert r.status_code == 404

    def test_update_writes_audit_event(self, client, engine):
        dev = mk_device(client)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "blocklist", "bundle_ids": ["com.bad.app"]},
                   headers=HDR)
        r = client.get("/api/audit-logs")
        actions = [e["action"] for e in r.json()["events"]]
        assert "app_policy.update" in actions


class TestAppPolicyApply:
    def test_apply_without_saved_policy_409(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 409

    def test_apply_without_enrollment_409(self, client):
        dev = mk_device(client)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "blocklist", "bundle_ids": ["com.bad.app"]},
                   headers=HDR)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 409
        assert "enroll" in r.json()["error"].lower()

    def test_apply_queues_install_profile_with_payload(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "allowlist",
                         "bundle_ids": ["com.good.one"]}, headers=HDR)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["command"] == "InstallProfile"
        assert r.json()["status"] == "queued"
        payload = r.json()["payload"]["profile"]
        assert payload["PayloadType"] == "Configuration"
        content = payload["PayloadContent"][0]
        assert content["PayloadType"] == "com.apple.applicationaccess"
        assert content["allowListedAppBundleIDs"] == ["com.good.one"]


class TestAppCommands:
    def test_install_queues_with_store_id(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["command"] == "InstallApplication"
        assert r.json()["payload"]["ITunesStoreID"] == 284815942

    def test_install_with_managed_configuration(self, client):
        """The KosherGuard app's initial managed configuration rides the
        InstallApplication command (Apple contract: application.install.yaml
        Configuration dict). deviceID comes from the server-side device
        record; controlPlaneBaseURL is operator-supplied, never invented."""
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942,
                              "configuration": {
                                  "controlPlaneBaseURL":
                                      "https://cp.example.com"}},
                        headers=HDR)
        assert r.status_code == 200, r.json()
        cfg = r.json()["payload"]["Configuration"]
        assert cfg["controlPlaneBaseURL"] == "https://cp.example.com"
        assert cfg["deviceID"] == dev  # filled from the device record

    def test_install_without_configuration_has_no_key(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert "Configuration" not in r.json()["payload"]

    def test_install_rejects_bad_configuration(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "itunes_store_id": 284815942,
                              "configuration": "not-a-dict"}, headers=HDR)
        assert r.status_code in (400, 422)

    def test_install_requires_store_id(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "install",
                              "bundle_id": "com.example.app"},
                        headers=HDR)
        assert r.status_code == 400

    def test_remove_validates_bundle_id(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "remove",
                              "bundle_id": "com.example.app"},
                        headers=HDR)
        assert r.status_code == 200
        assert r.json()["command"] == "RemoveApplication"
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "remove", "bundle_id": "junk"},
                        headers=HDR)
        assert r.status_code == 400

    def test_list_and_managed_list(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "list"}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["command"] == "InstalledApplicationList"
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "managed-list"}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["command"] == "ManagedApplicationList"

    def test_unknown_action_400(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "wipe"}, headers=HDR)
        assert r.status_code == 400

    def test_commands_require_enrollment(self, client):
        dev = mk_device(client)
        r = client.post(f"/api/devices/{dev}/app-commands",
                        json={"action": "list"}, headers=HDR)
        assert r.status_code == 409

    def test_signed_out_rejected(self, engine):
        env = {"KG_DATABASE_URL": "postgresql://placeholder",
               "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
        c = TestClient(create_app(Settings(env), engine=engine))
        assert c.get("/api/devices/1/app-policy").status_code == 401
        assert c.post("/api/devices/1/app-commands",
                      json={"action": "list"},
                      headers=HDR).status_code == 401

class TestAppPolicyLifecycle:
    """Review finding A1: stable profile identity, mode-switch
    replacement, legacy-identifier cleanup and the unapply
    (RemoveProfile) path that lifts restrictions from the device."""

    def _commands(self, engine):
        with session_scope(engine) as s:
            rows = s.scalars(
                select(MDMCommand).order_by(MDMCommand.id)).all()
            return [(r.command, json.loads(r.payload or "{}"))
                    for r in rows]

    def _policy_identifier(self, engine, device_id):
        with session_scope(engine) as s:
            row = s.scalars(select(DeviceAppPolicy).where(
                DeviceAppPolicy.device_id == device_id)).first()
            return None if row is None else row.profile_identifier

    def _set_profile_identifier(self, engine, device_id, identifier):
        with session_scope(engine) as s:
            row = s.scalars(select(DeviceAppPolicy).where(
                DeviceAppPolicy.device_id == device_id)).first()
            row.profile_identifier = identifier

    def _save_and_apply(self, client, dev, mode="blocklist",
                        ids=("com.bad.app",)):
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": mode, "bundle_ids": list(ids)},
                       headers=HDR)
        assert r.status_code == 200, r.json()
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 200, r.json()

    def test_apply_records_stable_identifier(self, client, engine):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        self._save_and_apply(client, dev, "allowlist", ("com.good.one",))
        assert self._policy_identifier(engine, dev) == \
            PROFILE_IDENTIFIER
        r = client.get(f"/api/devices/{dev}/app-policy")
        assert r.json()["applied"] is True
        installs = [p for c, p in self._commands(engine)
                    if c == "InstallProfile"]
        assert len(installs) == 1
        assert installs[0]["profile"]["PayloadIdentifier"] == \
            PROFILE_IDENTIFIER

    def test_mode_switch_replaces_profile_no_stale(self, client, engine):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        self._save_and_apply(client, dev, "blocklist", ("com.bad.app",))
        self._save_and_apply(client, dev, "allowlist", ("com.good.one",))
        cmds = self._commands(engine)
        installs = [p for c, p in cmds if c == "InstallProfile"]
        removals = [p for c, p in cmds if c == "RemoveProfile"]
        # Save-while-applied requeues immediately (consistency rule),
        # so the second save queues install #2 and the explicit Apply
        # re-queues the same contents as install #3. Same stable
        # identifier on every install means each replaces the previous
        # on device; no stale profile remains, so no removal is
        # needed.
        assert len(installs) == 3
        assert removals == []
        assert all(p["profile"]["PayloadIdentifier"] == PROFILE_IDENTIFIER
                   for p in installs)
        content = installs[-1]["profile"]["PayloadContent"][0]
        assert content["allowListedAppBundleIDs"] == ["com.good.one"]

    def test_legacy_identifier_cleaned_up_on_apply(self, client, engine):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        self._save_and_apply(client, dev)
        legacy = LEGACY_PROFILE_IDENTIFIERS[0]
        self._set_profile_identifier(engine, dev, legacy)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 200, r.json()
        cmds = self._commands(engine)
        removals = [p for c, p in cmds if c == "RemoveProfile"]
        assert removals == [{"Identifier": legacy}]
        # Removal is queued before the replacement install.
        assert [c for c, _ in cmds][-2:] == ["RemoveProfile",
                                             "InstallProfile"]
        assert self._policy_identifier(engine, dev) == \
            PROFILE_IDENTIFIER

    def test_unapply_queues_remove_profile_and_clears(self, client,
                                                      engine):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        self._save_and_apply(client, dev)
        r = client.post(f"/api/devices/{dev}/app-policy/unapply",
                        json={}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["command"] == "RemoveProfile"
        assert r.json()["payload"] == {"Identifier": PROFILE_IDENTIFIER}
        r = client.get(f"/api/devices/{dev}/app-policy")
        # Intent is kept (can re-apply); applied state is cleared.
        assert r.json()["saved"] is True
        assert r.json()["applied"] is False
        assert self._policy_identifier(engine, dev) is None
        # A second unapply has nothing to lift.
        r = client.post(f"/api/devices/{dev}/app-policy/unapply",
                        json={}, headers=HDR)
        assert r.status_code == 409

    def test_unapply_targets_recorded_legacy_identifier(self, client,
                                                        engine):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        self._save_and_apply(client, dev)
        legacy = LEGACY_PROFILE_IDENTIFIERS[1]
        self._set_profile_identifier(engine, dev, legacy)
        r = client.post(f"/api/devices/{dev}/app-policy/unapply",
                        json={}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["payload"] == {"Identifier": legacy}

    def test_unapply_without_applied_policy_409(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        # Saved but never applied.
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "blocklist",
                             "bundle_ids": ["com.bad.app"]}, headers=HDR)
        assert r.status_code == 200, r.json()
        r = client.post(f"/api/devices/{dev}/app-policy/unapply",
                        json={}, headers=HDR)
        assert r.status_code == 409

    def test_unapply_without_saved_policy_409(self, client):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.post(f"/api/devices/{dev}/app-policy/unapply",
                        json={}, headers=HDR)
        assert r.status_code == 409


from mfa_support import mfa_login


class TestShieldGate:
    """Remote activation gate for the PERSONAL shield: owner-only,
    CSRF-protected, tenant-scoped, audited, and independent of the
    supervised policy's applied marker."""

    def test_default_off_in_mirror(self, client):
        dev = mk_device(client)
        r = client.get(f"/api/devices/{dev}/app-policy")
        assert r.status_code == 200
        assert r.json()["shield_active"] is False

    def test_toggle_persists_and_audits(self, client):
        dev = mk_device(client)
        r = client.put(f"/api/devices/{dev}/app-policy/shield",
                       json={"active": True}, headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["shield_active"] is True
        got = client.get(f"/api/devices/{dev}/app-policy").json()
        assert got["shield_active"] is True
        r = client.put(f"/api/devices/{dev}/app-policy/shield",
                       json={"active": False}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["shield_active"] is False
        actions = [e["action"]
                   for e in client.get("/api/audit-logs").json()["events"]]
        assert "app_policy.shield_gate" in actions

    def test_toggle_requires_csrf_header(self, client):
        dev = mk_device(client)
        r = client.put(f"/api/devices/{dev}/app-policy/shield",
                       json={"active": True})
        assert r.status_code in (400, 403)

    def test_toggle_is_tenant_scoped(self, client, engine):
        dev = mk_device(client)
        other = make_client(engine, "sg-other@example.com", "fam-sg-b")
        r = other.put(f"/api/devices/{dev}/app-policy/shield",
                      json={"active": True}, headers=HDR)
        assert r.status_code == 404

    def test_guardian_cannot_toggle(self, client, engine):
        with session_scope(engine) as s:
            tenant_id = s.query(User).filter_by(
                email="apps@example.com").one().tenant_id
            s.add(User(tenant_id=tenant_id, email="sg-guard@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.guardian,
                       delegated_settings='["apps"]'))
        g = TestClient(client.app)
        r = mfa_login(g, json={"email": "sg-guard@example.com",
                               "password": PASSWORD}, headers=HDR)
        assert r.status_code == 200, r.text
        dev = mk_device(client)
        r = g.put(f"/api/devices/{dev}/app-policy/shield",
                  json={"active": True}, headers=HDR)
        assert r.status_code == 403

    def test_gate_independent_of_applied_marker(self, client, engine):
        dev = mk_device(client)
        client.put(f"/api/devices/{dev}/app-policy/shield",
                   json={"active": True}, headers=HDR)
        with session_scope(engine) as s:
            row = s.scalar(select(DeviceAppPolicy))
            assert row is not None
            assert row.shield_active is True
            # The gate is not an enforcement action: nothing applied.
            assert row.profile_identifier is None


class TestSaveOnAppliedReapply:
    """Save-while-applied consistency: both enforcement channels must
    converge on the new contents with no enforcement gap."""

    def test_save_on_applied_requeues_install_profile(self, client,
                                                      engine):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "blocklist",
                         "bundle_ids": ["com.old.app"]}, headers=HDR)
        r = client.post(f"/api/devices/{dev}/app-policy/apply",
                        json={}, headers=HDR)
        assert r.status_code == 200, r.json()
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "blocklist",
                             "bundle_ids": ["com.new.app"]},
                       headers=HDR)
        assert r.status_code == 200, r.json()
        body = r.json()
        assert body["reapplied"] is True
        assert body.get("command_id")
        with session_scope(engine) as s:
            latest = s.scalars(select(MDMCommand)
                               .order_by(MDMCommand.id.desc())).first()
            assert latest.command == "InstallProfile"
            payload = json.loads(latest.payload)["profile"]
            content = payload["PayloadContent"][0]
            assert content["blockedAppBundleIDs"] == ["com.new.app"]
            row = s.scalar(select(DeviceAppPolicy))
            # Enforcement continuity: still marked applied under the
            # stable identifier; the replacement profile installs over
            # it, removal stays exclusive to Unapply.
            assert row.profile_identifier == PROFILE_IDENTIFIER

    def test_save_on_applied_bumps_ddm_token(self, client, engine):
        from app import ddm_ops
        from app.models import MDMEnrollment
        dev = mk_device(client)
        mk_enrollment(client, dev)
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "blocklist",
                         "bundle_ids": ["com.old.app"]}, headers=HDR)
        client.post(f"/api/devices/{dev}/app-policy/apply",
                    json={}, headers=HDR)
        with session_scope(engine) as s:
            enr = s.scalar(select(MDMEnrollment))
            before = ddm_ops.configurations(s, enr)[0]["ServerToken"]
        client.put(f"/api/devices/{dev}/app-policy",
                   json={"mode": "blocklist",
                         "bundle_ids": ["com.new.app"]}, headers=HDR)
        with session_scope(engine) as s:
            enr = s.scalar(select(MDMEnrollment))
            configs = ddm_ops.configurations(s, enr)
            assert len(configs) == 1
            assert configs[0]["ServerToken"] != before

    def test_save_on_unapplied_queues_nothing(self, client, engine):
        dev = mk_device(client)
        mk_enrollment(client, dev)
        r = client.put(f"/api/devices/{dev}/app-policy",
                       json={"mode": "blocklist",
                             "bundle_ids": ["com.a.b"]}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["reapplied"] is False
        assert "reapply_reason" not in r.json()
        with session_scope(engine) as s:
            assert s.scalars(select(MDMCommand)).all() == []
