"""2026-11-17 security-corrections regression tests (single-threaded).

Covers the non-concurrency halves of the corrections: credential
artifact fault injection (pending cleanup + retry), the revocation
feed's MFA enforcement on the cookie path, invite single-active rule,
policy-disable assignment guard, exception list gating, the honest
revocation rollback message, password-hash upgrade on login, and
adapter-error sanitization. Concurrency races live in
test_concurrency_pg.py.
"""

import base64
import os
import sys
import tempfile
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from app import credential_ops, security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (CredentialArtifact, Role, Tenant, User,  # noqa: E402
                        utcnow)
from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
FIXTURE = base64.b64encode(b"fixture-credential-bytes-v1").decode()
FIXTURE2 = base64.b64encode(b"fixture-credential-bytes-v2").decode()


def make_client(engine, email="o@example.com", role=Role.owner,
                cred_root="/tmp/kg-cred-test", totp=None):
    with session_scope(engine) as s:
        tenant = Tenant(name=f"fam-{email}")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=role, totp_secret=totp))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": tempfile.mkdtemp(prefix="kg-pub-harden-"),
           "KG_CREDENTIALS_ROOT": cred_root}
    return TestClient(create_app(Settings(env), engine=engine))


def login(c, email="o@example.com"):
    r = mfa_login(c, json={"email": email, "password": PASSWORD},
                  headers=HDR)
    assert r.status_code == 200, r.text
    return r


class TestCredentialFaultInjection:
    def _upload(self, c):
        r = c.post("/api/credentials", json={
            "kind": "apns_auth_key", "label": "k1",
            "content_base64": FIXTURE}, headers=HDR)
        assert r.status_code == 200, r.json()
        return r.json()["id"]

    def test_revoke_delete_failure_marks_pending_and_retry_cleans(
            self, engine, tmp_path, monkeypatch):
        """A crash-class delete failure after the row is revoked must
        not silently strand secret bytes: the row records
        pending_cleanup_path, the API discloses cleanup_pending, and
        the maintenance retry removes the bytes and clears the mark."""
        root = str(tmp_path / "creds")
        c = make_client(engine, cred_root=root)
        login(c)
        cid = self._upload(c)
        real_delete = credential_ops.delete_secret
        state = {"fail": True}

        def flaky(r, p):
            if state["fail"]:
                raise OSError("simulated storage failure")
            return real_delete(r, p)

        monkeypatch.setattr(credential_ops, "delete_secret", flaky)
        r = c.delete(f"/api/credentials/{cid}", headers=HDR)
        assert r.status_code == 200, r.json()
        assert r.json()["status"] == "revoked"
        assert r.json()["cleanup_pending"] is True
        with session_scope(engine) as s:
            row = s.query(CredentialArtifact).filter_by(id=cid).one()
            assert row.pending_cleanup_path is not None
            # The secret bytes are still on disk (delete failed)...
            assert os.path.exists(os.path.join(
                root, row.pending_cleanup_path))
        state["fail"] = False
        # ...until the retry path (also wired into list) clears it.
        monkeypatch.setattr(credential_ops, "delete_secret", real_delete)
        r = c.get("/api/credentials")
        assert r.status_code == 200
        item = [x for x in r.json()["credentials"] if x["id"] == cid][0]
        assert item["cleanup_pending"] is False
        with session_scope(engine) as s:
            row = s.query(CredentialArtifact).filter_by(id=cid).one()
            assert row.pending_cleanup_path is None

    def test_rotate_storage_failure_keeps_existing_version(
            self, engine, tmp_path, monkeypatch):
        root = str(tmp_path / "creds")
        c = make_client(engine, cred_root=root)
        login(c)
        cid = self._upload(c)
        monkeypatch.setattr(
            credential_ops, "write_secret",
            lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
        r = c.post(f"/api/credentials/{cid}/rotate", json={
            "kind": "apns_auth_key", "label": "k1",
            "content_base64": FIXTURE2}, headers=HDR)
        assert r.status_code == 503
        r = c.get("/api/credentials")
        item = [x for x in r.json()["credentials"] if x["id"] == cid][0]
        assert item["version"] == 1 and item["status"] == "active"

    def test_upload_db_failure_leaves_no_stranded_bytes(
            self, engine, tmp_path, monkeypatch):
        """If the database commit fails AFTER the secret was written,
        the file is removed again: no orphaned secret with no row."""
        root = str(tmp_path / "creds")
        c = make_client(engine, cred_root=root)
        login(c)

        class Boom:
            def __init__(self, *a, **k):
                pass

            def audit(self, *a, **k):
                raise RuntimeError("simulated audit failure")

        monkeypatch.setattr("app.credential_routes.ScopedSession", Boom)
        with pytest.raises(RuntimeError, match="simulated audit"):
            c.post("/api/credentials", json={
                "kind": "apns_auth_key", "label": "k1",
                "content_base64": FIXTURE}, headers=HDR)
        with session_scope(engine) as s:
            assert s.query(CredentialArtifact).count() == 0
        leftover = []
        for dirpath, _dirs, files in os.walk(root):
            leftover += [f for f in files if not f.startswith(".")]
        assert leftover == []

    def test_delete_secret_refuses_unsafe_path(self):
        with pytest.raises(credential_ops.CredentialError):
            credential_ops.delete_secret("/tmp/x", "../../etc/passwd")
        with pytest.raises(credential_ops.CredentialError):
            credential_ops.delete_secret("/tmp/x", "tenant-1/../../y")
        assert credential_ops.delete_secret(
            "/tmp/x", "tenant-1/" + "a" * 32 + ".bin") is True


class TestRevocationFeedMfa:
    def test_cookie_branch_requires_verified_mfa(self, engine):
        """The cookie path enforces the same MFA rule as current_user:
        a password-only (not-yet-MFA-enrolled) session may not read
        the revocation feed."""
        c = make_client(engine)  # owner without TOTP yet
        r = c.post("/api/auth/login", json={
            "email": "o@example.com", "password": PASSWORD}, headers=HDR)
        assert r.status_code == 200
        assert r.json()["mfa_required"] is True
        assert c.get("/api/credential-revocations").status_code == 403
        # And a completed MFA login can read it.
        login(c)
        assert c.get("/api/credential-revocations").status_code == 200


class TestInviteRules:
    def test_second_active_invite_refused(self, engine):
        c = make_client(engine)
        login(c)
        body = {"email": "new@example.com", "role": "guardian"}
        r = c.post("/api/guardians/invite", json=body, headers=HDR)
        assert r.status_code == 200
        r = c.post("/api/guardians/invite", json=body, headers=HDR)
        assert r.status_code == 409, r.json()

    def test_invite_single_use(self, engine):
        c = make_client(engine)
        login(c)
        r = c.post("/api/guardians/invite", json={
            "email": "n2@example.com", "role": "viewer"}, headers=HDR)
        token = r.json()["invite_token"]
        r = c.post("/api/invites/accept", json={
            "token": token, "password": "another long password"},
            headers=HDR)
        assert r.status_code == 200
        r = c.post("/api/invites/accept", json={
            "token": token, "password": "another long password"},
            headers=HDR)
        assert r.status_code == 400


class TestPolicyDisableGuard:
    def test_cannot_disable_assigned_policy(self, engine):
        c = make_client(engine)
        login(c)
        r = c.post("/api/devices", json={"name": "d1"}, headers=HDR)
        dev = r.json()["id"]
        body = {"name": "p1", "default_policy": "allow",
                "blocklist": ["bad.example"], "allowlist": [],
                "category_allow": [], "category_block": []}
        r = c.post("/api/policies", json=body, headers=HDR)
        pid = r.json()["id"]
        assert c.post(f"/api/policies/{pid}/select",
                      headers=HDR).status_code == 200
        r = c.post("/api/policies", json=dict(body, name="p2"),
                   headers=HDR)
        pid2 = r.json()["id"]
        r = c.post(f"/api/devices/{dev}/assignment",
                   json={"policy_id": pid2}, headers=HDR)
        assert r.status_code == 200, r.json()
        # Disabling the assigned policy is refused; unassigning first
        # makes it legal.
        r = c.put(f"/api/policies/{pid2}", json=dict(body, name="p2",
                                                     enabled=False),
                  headers=HDR)
        assert r.status_code == 409, r.json()
        r = c.post(f"/api/devices/{dev}/assignment",
                   json={"policy_id": pid}, headers=HDR)
        assert r.status_code == 200
        r = c.put(f"/api/policies/{pid2}", json=dict(body, name="p2",
                                                     enabled=False),
                  headers=HDR)
        assert r.status_code == 200, r.json()


class TestExceptionHonesty:
    def test_revocation_rollback_message_is_honest(self, engine,
                                                   monkeypatch):
        """When the republication job cannot be queued, the revocation
        is rolled back and the response must say the exception is
        still active - never 'revoked, but...'."""
        c = make_client(engine)
        login(c)
        body = {"name": "p", "default_policy": "allow",
                "blocklist": ["bad.example"], "allowlist": [],
                "category_allow": [], "category_block": []}
        r = c.post("/api/policies", json=body, headers=HDR)
        pid = r.json()["id"]
        assert c.post(f"/api/policies/{pid}/select",
                      headers=HDR).status_code == 200
        r = c.post("/api/devices", json={"name": "d1"}, headers=HDR)
        dev = r.json()["id"]
        future = (utcnow() + timedelta(hours=2)).isoformat()
        r = c.post("/api/exceptions", json={
            "kind": "allow_domains", "scope_type": "device",
            "device_id": dev, "domains": ["example.com"],
            "reason": "needed", "expires_at": future}, headers=HDR)
        assert r.status_code == 200, r.json()
        eid = r.json()["id"]

        def boom(*a, **k):
            raise ValueError("simulated queue failure")

        monkeypatch.setattr("app.worker.enqueue", boom)
        r = c.delete(f"/api/exceptions/{eid}", headers=HDR)
        assert r.status_code == 500
        assert "NOT revoked" in r.json()["error"]
        assert "remains active" in r.json()["error"]
        # And it really is still active.
        rows = c.get("/api/exceptions").json()["exceptions"]
        item = [x for x in rows if x["id"] == eid][0]
        assert item["active"] is True

    def test_exception_list_gated(self, engine):
        c = make_client(engine, email="v@example.com", role=Role.viewer)
        login(c, "v@example.com")
        assert c.get("/api/exceptions").status_code == 403
        assert c.get("/api/exception-requests").status_code == 403


class TestLoginHashUpgrade:
    def test_old_hash_upgraded_on_login(self, engine):
        """A valid pre-hardening hash (fewer iterations than the current
        configured target, above the parsing floor) is transparently
        rehashed on successful login."""
        import hashlib
        import secrets as _secrets
        salt = _secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(),
                                     salt, 10_000)
        old = f"pbkdf2$10000${salt.hex()}${digest.hex()}"
        assert security.password_needs_upgrade(old)
        c = make_client(engine)
        with session_scope(engine) as s:
            u = s.query(User).filter_by(email="o@example.com").one()
            u.password_hash = old
        login(c)
        with session_scope(engine) as s:
            u = s.query(User).filter_by(email="o@example.com").one()
            assert not security.password_needs_upgrade(u.password_hash)
            assert security.verify_password(PASSWORD, u.password_hash)


class TestAdapterErrorSanitization:
    def test_adapter_errors_redact_secretish_content(self):
        from app import mdm_ops
        msg = mdm_ops.sanitize_adapter_error(
            "push failed: token=abc123 password=hunter2 status 500")
        assert "abc123" not in msg and "hunter2" not in msg
        assert "adapter delivery failed" in msg

@pytest.mark.parametrize("operation", ["upload", "rotate", "revoke"])
def test_real_commit_failure_preserves_active_bytes(engine, tmp_path, monkeypatch, operation):
    from sqlalchemy.orm import Session
    root = str(tmp_path / "secrets")
    c = make_client(engine, cred_root=root)
    login(c)
    cid = None
    if operation != "upload":
        cid = TestCredentialFaultInjection()._upload(c)
    real_commit = Session.commit
    tripped = []

    def fail_artifact_commit(session):
        if not tripped:
            tripped.append(True)
            raise RuntimeError("injected metadata commit failure")
        return real_commit(session)

    monkeypatch.setattr(Session, "commit", fail_artifact_commit)
    with pytest.raises(RuntimeError, match="metadata commit failure"):
        if operation == "upload":
            TestCredentialFaultInjection()._upload(c)
        elif operation == "rotate":
            c.post(f"/api/credentials/{cid}/rotate", json={
                "kind": "apns_auth_key", "label": "k1",
                "content_base64": FIXTURE2}, headers=HDR)
        else:
            c.delete(f"/api/credentials/{cid}", headers=HDR)
    assert tripped
    with session_scope(engine) as s:
        rows = s.query(CredentialArtifact).all()
        assert len(rows) == (0 if operation == "upload" else 1)
        if rows:
            row = rows[0]
            assert row.status == "active" and row.version == 1
            assert open(os.path.join(root, row.storage_path), "rb").read() == base64.b64decode(FIXTURE)
    files = [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs]
    assert len(files) == (0 if operation == "upload" else 1)


def test_partial_secret_write_is_removed(tmp_path, monkeypatch):
    def fail(*a):
        raise OSError("simulated rename failure")
    monkeypatch.setattr(credential_ops.os, "replace", fail)
    with pytest.raises(OSError):
        credential_ops.write_secret(str(tmp_path), 1, b"fixture")
    assert not [p for p in tmp_path.rglob("*") if p.is_file()]


def test_group_assigned_policy_cannot_disable_and_publish_survives(engine, tmp_path):
    c = make_client(engine)
    login(c)
    body = {"name": "baseline", "default_policy": "allow", "blocklist": ["bad.example"]}
    base = c.post("/api/policies", json=body, headers=HDR).json()["id"]
    assert c.post(f"/api/policies/{base}/select", headers=HDR).status_code == 200
    pid = c.post("/api/policies", json=dict(body, name="group"), headers=HDR).json()["id"]
    assert c.post("/api/groups", json={"name": "group", "policy_id": pid}, headers=HDR).status_code == 200
    assert c.put(f"/api/policies/{pid}", json=dict(body, name="group", enabled=False), headers=HDR).status_code == 409
    assert c.post("/api/publications", headers=HDR).status_code == 200


def test_expired_unused_invite_can_be_replaced(engine):
    from app.models import InviteToken
    c = make_client(engine)
    login(c)
    body = {"email": "expired@example.com", "role": "guardian"}
    first = c.post("/api/guardians/invite", json=body, headers=HDR)
    assert first.status_code == 200
    with session_scope(engine) as s:
        s.query(InviteToken).one().expires_at = utcnow() - timedelta(seconds=1)
    assert c.post("/api/guardians/invite", json=body, headers=HDR).status_code == 200
    assert c.post("/api/invites/accept", json={"token": first.json()["invite_token"], "password": PASSWORD}, headers=HDR).status_code == 400


def test_orphan_recovery_respects_live_files_and_grace(engine, tmp_path):
    c = make_client(engine, cred_root=str(tmp_path))
    login(c)
    TestCredentialFaultInjection()._upload(c)
    orphan = credential_ops.write_secret(str(tmp_path), 1, b"orphan-fixture")
    path = tmp_path / orphan
    with session_scope(engine) as s:
        assert credential_ops.recover_orphaned_files(s, str(tmp_path)) == 0
        os.utime(path, (0, 0))
        assert credential_ops.recover_orphaned_files(s, str(tmp_path)) == 1
        live = s.query(CredentialArtifact).one()
        assert (tmp_path / live.storage_path).exists()


def test_secret_delete_cannot_follow_tenant_directory_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "tenant-1").symlink_to(outside, target_is_directory=True)
    with pytest.raises(credential_ops.CredentialError):
        credential_ops.delete_secret(str(root), "tenant-1/" + "a" * 32 + ".bin")


@pytest.mark.parametrize("failure", ["expired", "wrong-scope", "wrong-tenant", "wrong-device", "expiry-mismatch"])
def test_ingestion_registry_binding_failures(engine, failure):
    from app.filter_log_ops import record_decisions, FilterLogError
    from app.models import Device, IssuedCredential
    from test_activity_privacy import _live_claims
    with session_scope(engine) as s:
        t = Tenant(name="ingestion-binding")
        s.add(t); s.flush()
        claims = _live_claims(s, t)
        row = s.query(IssuedCredential).one()
        if failure == "expired":
            row.expires_at = utcnow() - timedelta(seconds=1)
        elif failure == "wrong-scope":
            claims["scope"] = "doh"
        elif failure == "wrong-tenant":
            claims["tenant_id"] = t.id + 10000
        elif failure == "wrong-device":
            d = Device(tenant_id=t.id, name="wrong")
            s.add(d); s.flush(); claims["device_id"] = d.id
        else:
            claims["exp"] = int(row.expires_at.timestamp()) + 100
        s.flush()
        with pytest.raises(FilterLogError):
            record_decisions(s, claims, [{"domain": "blocked.example", "action": "block"}])


def test_approval_rejects_foreign_target_and_hides_corrupt_reference(engine):
    from app.models import Device, MDMEnrollment, SensitiveCommandApproval
    from test_concurrency_pg import make_app, login as race_login, fresh_code
    app = make_app(engine, "approval-tenant")
    c = TestClient(app)
    race_login(c, "a@example.com")
    tid, _, _ = app.state.test_ids
    with session_scope(engine) as s:
        t = Tenant(name="foreign-approval"); s.add(t); s.flush()
        d = Device(tenant_id=t.id, name="PRIVATE-NAME"); s.add(d); s.flush()
        e = MDMEnrollment(tenant_id=t.id, device_id=d.id, enrollment_id="PRIVATE-ID", device_udid="PRIVATE-UDID", state="enrolled")
        s.add(e); s.flush(); pk = e.id
        uid = s.query(User).filter_by(tenant_id=tid, email="a@example.com").one().id
        s.add(SensitiveCommandApproval(tenant_id=tid, enrollment_pk=pk,
            operation="EraseDevice", requested_by_user_id=uid, reason="bad-reference",
            expires_at=utcnow() + timedelta(hours=1)))
    assert c.post(f"/api/mdm/enrollments/{pk}/commands", json={
        "command": "EraseDevice", "reason": "foreign", "confirm": "EraseDevice",
        "totp_code": fresh_code(c, "a@example.com")}, headers=HDR).status_code == 404
    r = c.get("/api/mdm/sensitive-approvals")
    assert r.status_code == 200
    assert not any(word in r.text for word in ("PRIVATE-NAME", "PRIVATE-ID", "PRIVATE-UDID"))


@pytest.mark.parametrize("terminal", ["offboarded", "replaced", "revoked"])
def test_terminal_enrollment_refuses_ordinary_and_sensitive_commands(engine, terminal):
    from app.models import MDMEnrollment
    from test_concurrency_pg import make_app, login as race_login, fresh_code
    app = make_app(engine, "terminal-" + terminal)
    _, _, pk = app.state.test_ids
    c = TestClient(app); race_login(c, "a@example.com")
    with session_scope(engine) as s:
        s.get(MDMEnrollment, pk).state = terminal
    for command in ("DeviceInformation", "EraseDevice"):
        assert c.post(f"/api/mdm/enrollments/{pk}/commands", json={
            "command": command, "reason": "terminal", "confirm": command,
            "totp_code": fresh_code(c, "a@example.com")}, headers=HDR).status_code == 409
