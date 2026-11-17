"""Answer 26 tests: restore/re-enrollment readiness and the ABM
assignment attestation.

Freshness semantics: the attestation is bound to the device's CURRENT
enrollment cycle (a stale attestation never satisfies a new restore),
the filtering credential must be unrevoked AND unexpired, the assigned
policy must be tighten-only against the protected baseline, and the
configuration must actually be PUBLISHED - not merely saved.
"""

import os
import sys
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (DeviceAssignment, IssuedCredential,  # noqa: E402
                        MDMEnrollment, Policy, Role, Tenant, User, utcnow)
from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
BASE = {"default_policy": "allow", "blocklist": ["bad.example"],
        "allowlist": [], "category_allow": [], "category_block": []}


def make_client(engine, email="owner@example.com", tenant_name="fam-a",
                pub_root="/tmp/kg-pub-test"):
    with session_scope(engine) as s:
        tenant = Tenant(name=tenant_name)
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": pub_root}
    settings = Settings(env)
    c = TestClient(create_app(settings, engine=engine))
    c.app.state.restore_test_settings = settings
    r = mfa_login(c, json={"email": email, "password": PASSWORD}, headers=HDR)
    assert r.status_code == 200, r.text
    return c


@pytest.fixture()
def client(engine, tmp_path):
    return make_client(engine, pub_root=str(tmp_path / "pub"))


def fresh_code(c, email="owner@example.com"):
    return pyotp.TOTP(c.app.state._fixture_mfa[email]).now()


def attest(c, dev, email="owner@example.com"):
    return c.post(f"/api/mdm/devices/{dev}/restore-attest",
                  json={"totp_code": fresh_code(c, email),
                        "confirm": "attest-abm-assignment"}, headers=HDR)


def mk_device(c, name="phone-1"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


def readiness(c, dev):
    r = c.get(f"/api/mdm/devices/{dev}/restore-readiness")
    assert r.status_code == 200, r.json()
    return r.json()


def _enrollment(engine, dev, enrollment_id, state="enrolled"):
    with session_scope(engine) as s:
        tenant = s.query(Tenant).filter_by(name="fam-a").one()
        s.add(MDMEnrollment(tenant_id=tenant.id, device_id=dev,
                            enrollment_id=enrollment_id,
                            device_udid="U-" + enrollment_id, state=state))


def _credential(engine, dev, jti="jti-r1", hours=1):
    with session_scope(engine) as s:
        tenant = s.query(Tenant).filter_by(name="fam-a").one()
        s.add(IssuedCredential(tenant_id=tenant.id, device_id=dev,
                               jti=jti, scope="dataset",
                               expires_at=utcnow() + timedelta(hours=hours)))


def _publish_setup(c):
    r = c.post("/api/policies", json=dict(BASE, name="fam"), headers=HDR)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]
    assert c.post(f"/api/policies/{pid}/select",
                  headers=HDR).status_code == 200
    return pid


class TestRestore:
    def test_readiness_requires_all_checks(self, engine, client):
        dev = mk_device(client)
        body = readiness(client, dev)
        assert body["setup_release_ready"] is False
        assert all(v is False for v in body["checks"].values())

        pid = _publish_setup(client)
        r = client.post(f"/api/devices/{dev}/assignment",
                        json={"policy_id": pid}, headers=HDR)
        assert r.status_code == 200, r.json()
        _enrollment(engine, dev, "ENR-1")
        _credential(engine, dev)
        assert client.post("/api/publications", headers=HDR).status_code \
            == 200

        body = readiness(client, dev)
        # Everything except the ABM attestation is now green.
        assert body["checks"]["device_reenrolled"] is True
        assert body["checks"]["baseline_assignment_valid"] is True
        assert body["checks"]["filtering_credential_active"] is True
        assert body["checks"]["filtering_configuration_published"] is True
        assert body["checks"]["abm_assignment_attested"] is False
        assert body["setup_release_ready"] is False

        r = attest(client, dev)
        assert r.status_code == 200, r.json()
        assert r.json()["attestation_kind"] == "manual_guardian"
        body = readiness(client, dev)
        assert body["setup_release_ready"] is True
        assert body["basis"]["abm_assignment_attested"].startswith(
            "manual guardian attestation")

    def test_attestation_bound_to_current_enrollment(self, engine, client):
        """A stale attestation must never satisfy a new restore: the
        attestation is bound to the enrollment cycle it was recorded
        under, and re-enrollment invalidates it."""
        dev = mk_device(client)
        _enrollment(engine, dev, "ENR-OLD")
        r = attest(client, dev)
        assert r.status_code == 200, r.json()
        assert readiness(client, dev)["checks"][
            "abm_assignment_attested"] is True
        # Re-enrollment: the old cycle is replaced by a new current one.
        with session_scope(engine) as s:
            old = s.query(MDMEnrollment).filter_by(
                enrollment_id="ENR-OLD").one()
            old.state = "replaced"
        _enrollment(engine, dev, "ENR-NEW")
        body = readiness(client, dev)
        assert body["checks"]["abm_assignment_attested"] is False
        assert body["setup_release_ready"] is False

    def test_attest_requires_fresh_mfa_and_confirmation(self, engine,
                                                        client):
        dev = mk_device(client)
        _enrollment(engine, dev, "ENR-1")
        # No MFA code at all.
        r = client.post(f"/api/mdm/devices/{dev}/restore-attest",
                        json={}, headers=HDR)
        assert r.status_code == 403
        # Wrong confirmation phrase.
        r = client.post(f"/api/mdm/devices/{dev}/restore-attest",
                        json={"totp_code": fresh_code(client),
                              "confirm": "wrong"}, headers=HDR)
        assert r.status_code == 400

    def test_attest_requires_current_enrollment(self, client):
        dev = mk_device(client)
        r = attest(client, dev)
        assert r.status_code == 409

    def test_expired_or_revoked_credential_not_active(self, engine,
                                                      client):
        dev = mk_device(client)
        _enrollment(engine, dev, "ENR-1")
        _credential(engine, dev, jti="jti-old", hours=-1)
        assert readiness(client, dev)["checks"][
            "filtering_credential_active"] is False
        _credential(engine, dev, jti="jti-live")
        assert readiness(client, dev)["checks"][
            "filtering_credential_active"] is True
        with session_scope(engine) as s:
            cred = s.query(IssuedCredential).filter_by(
                jti="jti-live").one()
            cred.revoked_at = utcnow()
        assert readiness(client, dev)["checks"][
            "filtering_credential_active"] is False

    def test_saved_but_unpublished_configuration_not_ready(self, engine,
                                                           client):
        """A saved-and-assigned policy is not enough: the required
        configuration must have a real published generation."""
        dev = mk_device(client)
        pid = _publish_setup(client)
        r = client.post(f"/api/devices/{dev}/assignment",
                        json={"policy_id": pid}, headers=HDR)
        assert r.status_code == 200, r.json()
        _enrollment(engine, dev, "ENR-1")
        _credential(engine, dev)
        assert attest(client, dev).status_code == 200
        body = readiness(client, dev)
        assert body["checks"][
            "filtering_configuration_published"] is False
        assert body["setup_release_ready"] is False

    def test_loosened_assignment_fails_baseline_check(self, engine,
                                                      client):
        """If the effective assignment is weaker than the protected
        baseline (e.g. a bad direct edit), readiness must catch it:
        baseline_assignment_valid is False and release is blocked."""
        dev = mk_device(client)
        pid = _publish_setup(client)
        r = client.post(f"/api/devices/{dev}/assignment",
                        json={"policy_id": pid}, headers=HDR)
        assert r.status_code == 200, r.json()
        _enrollment(engine, dev, "ENR-1")
        _credential(engine, dev)
        assert client.post("/api/publications", headers=HDR).status_code \
            == 200
        assert attest(client, dev).status_code == 200
        assert readiness(client, dev)["setup_release_ready"] is True
        # A weaker policy (no blocklist) swapped in by direct edit,
        # bypassing the API's own tighten-only guard - readiness is the
        # backstop that must catch it.
        r = client.post("/api/policies", json=dict(
            BASE, name="weak", blocklist=[]), headers=HDR)
        assert r.status_code == 200, r.text
        weak = r.json()["id"]
        with session_scope(engine) as s:
            asg = s.query(DeviceAssignment).filter_by(
                device_id=dev, active=True).one()
            asg.policy_id = weak
        body = readiness(client, dev)
        assert body["checks"]["baseline_assignment_valid"] is False
        assert body["setup_release_ready"] is False
        assert "less restrictive" in (
            body["basis"]["baseline_assignment_valid"] or "")

    def test_cross_tenant_readiness_404(self, engine, client):
        dev = mk_device(client)
        other = make_client(engine, "b@example.com", "fam-b")
        assert other.get(
            f"/api/mdm/devices/{dev}/restore-readiness").status_code == 404

@pytest.mark.parametrize("stale", ["credential", "publication", "changed-policy", "wrong-device", "disabled-baseline"])
def test_restore_rejects_stale_or_wrong_evidence(engine, client, stale):
    from app.models import Device, DeviceAssignment
    dev = mk_device(client)
    pid = _publish_setup(client)
    assert client.post(f"/api/devices/{dev}/assignment", json={"policy_id": pid}, headers=HDR).status_code == 200
    _enrollment(engine, dev, "restore-cycle")
    _credential(engine, dev)
    assert client.post("/api/publications", headers=HDR).status_code == 200
    assert attest(client, dev).status_code == 200
    assert readiness(client, dev)["setup_release_ready"] is True
    if stale == "publication":
        # New enrollment and credential, with a new manual attestation,
        # must still fail until a configuration for THAT cycle ships.
        with session_scope(engine) as s:
            s.query(MDMEnrollment).filter_by(device_id=dev).one().state = "offboarded"
        _enrollment(engine, dev, "new-restore-cycle")
        _credential(engine, dev, "new-cycle-credential")
        assert attest(client, dev).status_code == 200
    elif stale == "credential":
        with session_scope(engine) as s:
            enr = s.query(MDMEnrollment).filter_by(device_id=dev).one()
            cred = s.query(IssuedCredential).filter_by(device_id=dev).one()
            cred.created_at = enr.created_at - timedelta(seconds=1)
    elif stale == "wrong-device":
        other = mk_device(client, "other")
        with session_scope(engine) as s:
            s.query(IssuedCredential).filter_by(device_id=dev).one().device_id = other
    elif stale == "disabled-baseline":
        with session_scope(engine) as s:
            s.get(Policy, pid).enabled = False
    else:
        r = client.put(f"/api/policies/{pid}", json=dict(BASE, name="fam", blocklist=["bad.example", "new.example"]), headers=HDR)
        assert r.status_code == 200, r.text
    body = readiness(client, dev)
    assert body["setup_release_ready"] is False
    key = "filtering_credential_active" if stale in ("credential", "wrong-device") else (
        "baseline_assignment_valid" if stale == "disabled-baseline" else "filtering_configuration_published")
    assert body["checks"][key] is False


@pytest.mark.parametrize("kind", ["disable_policy", "allow_domains"])
@pytest.mark.parametrize("scope", ["device", "group"])
def test_restore_effective_exception_blocks_readiness_until_cleanup(engine, client, kind, scope):
    from app.worker import run_once
    dev = mk_device(client)
    pid = _publish_setup(client)
    assert client.post(f"/api/devices/{dev}/assignment", json={"policy_id": pid}, headers=HDR).status_code == 200
    _enrollment(engine, dev, "exception-cycle")
    _credential(engine, dev)
    assert client.post("/api/publications", headers=HDR).status_code == 200
    assert attest(client, dev).status_code == 200
    assert readiness(client, dev)["setup_release_ready"] is True
    body = {"kind": kind, "scope_type": scope, "device_id": dev,
            "domains": ["bad.example"] if kind == "allow_domains" else [],
            "reason": "temporary authorized exception",
            "expires_at": (utcnow() + timedelta(hours=1)).isoformat()}
    if scope == "group":
        r = client.post("/api/groups", json={"name": "restore-group", "policy_id": pid}, headers=HDR)
        assert r.status_code == 200, r.text
        gid = r.json()["id"]
        assert client.put(f"/api/groups/{gid}/devices/{dev}", headers=HDR).status_code == 200
        body["group_id"] = gid
        body.pop("device_id")
    r = client.post("/api/exceptions", json=body, headers=HDR)
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    # Even a saved active exception blocks the checklist while unpublished.
    status = readiness(client, dev)
    assert status["checks"]["baseline_assignment_valid"] is True
    assert status["checks"]["filtering_exceptions_clear"] is False
    assert status["setup_release_ready"] is False
    assert client.post("/api/publications", headers=HDR).status_code == 200
    assert readiness(client, dev)["setup_release_ready"] is False
    # A saved revocation is not yet evidence the edge snapshot is clear.
    assert client.delete(f"/api/exceptions/{eid}", headers=HDR).status_code == 200
    assert readiness(client, dev)["checks"]["filtering_exceptions_clear"] is False
    assert run_once(engine, client.app.state.restore_test_settings)
    assert readiness(client, dev)["setup_release_ready"] is True
