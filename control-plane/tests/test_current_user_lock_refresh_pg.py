"""Forced real-PostgreSQL interleavings for the cookie-session request path.

current_user serializes mutating API requests on the tenant row lock, and
its authorization inputs (session row, role, delegation, MFA state) are
read BEFORE that wait begins. These tests hold the tenant lock, queue a
guardian's mutating request on it (the queueing is observed through
pg_blocking_pids, never guessed with sleeps), commit an authorization
change underneath the waiter, then release the lock and prove what the
resumed request may do.

The committed change is written directly (UPDATE users / DELETE
auth_sessions): HTTP revocation routes serialize on the same tenant row
via the audit_events foreign key, so through HTTP alone this ordering is
a post-release lock-grant race. The direct commit pins that race's
dangerous outcome so the invariant lock_tenant documents - refresh
authorization objects read before waiting - is tested deterministically.
"""
import json as _json
import threading
from contextlib import contextmanager

import pytest
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

import app.main as main_module
from app import security
from app.db import lock_tenant as real_lock_tenant, session_scope
from app.models import PolicyVersion, Role, User

from mfa_support import mfa_login
from test_filter_logs import HDR, client  # noqa: F401  (fixtures; `engine` comes from conftest)
from test_ingestion_offboarding_pg import wait_for_blocked

GUARDIAN = "guardian-wait@example.com"
GUARDIAN_PASSWORD = "guardian long password"


def _guardian(client, engine, capabilities):
    """Add a guardian (with MFA) to the owner's tenant and sign it in
    on a SECOND TestClient sharing the app. Returns (client, user_id)."""
    with session_scope(engine) as s:
        owner = s.scalar(select(User).where(User.email == "logs@example.com"))
        g = User(tenant_id=owner.tenant_id, email=GUARDIAN,
                 password_hash=security.hash_password(GUARDIAN_PASSWORD),
                 role=Role.guardian,
                 delegated_settings=_json.dumps(capabilities))
        s.add(g)
        s.flush()
        gid = g.id
    other = TestClient(client.app)
    other.app.state._fixture_mfa = client.app.state._fixture_mfa
    result = mfa_login(other, json={"email": GUARDIAN,
                                    "password": GUARDIAN_PASSWORD},
                       headers=HDR)
    assert result.status_code == 200, result.text
    return other, gid


def _second_policy(client):
    """A non-baseline policy identical in rules to the baseline, so the
    guardian's tighten-only update is valid while delegated."""
    body = {"name": "child-policy", "default_policy": "block",
            "allowlist": [], "blocklist": [], "category_allow": [],
            "category_block": []}
    result = client.post("/api/policies", json=body, headers=HDR)
    assert result.status_code == 200, result.text
    return result.json()["id"]


def _update_body():
    return {"name": "child-policy", "default_policy": "block",
            "allowlist": [], "blocklist": ["blocked-after-wait.example"],
            "category_allow": [], "category_block": []}


def _signaling_main_lock(monkeypatch):
    """Signal when the guardian request thread reaches the tenant lock,
    then take the real lock (which blocks on the holder)."""
    waiting = threading.Event()
    original = main_module.lock_tenant

    def wrapper(session, tenant_id):
        if threading.current_thread().name != "MainThread":
            waiting.set()
        return original(session, tenant_id)

    monkeypatch.setattr(main_module, "lock_tenant", wrapper)
    return waiting


@contextmanager
def _release_on_exit(holder):
    # Must run before ThreadPoolExecutor joins a blocked request, even
    # when an assertion or setup operation inside the interleaving fails.
    try:
        yield
    finally:
        holder.rollback()
        holder.close()


def _held_tenant_lock(engine, email="logs@example.com"):
    with session_scope(engine) as s:
        tid = s.scalar(select(User.tenant_id).where(User.email == email))
    session = Session(engine)
    real_lock_tenant(session, tid)
    pid = session.scalar(text("SELECT pg_backend_pid()"))
    return session, tid, pid


def _version_count(engine, policy_id):
    with session_scope(engine) as s:
        return len(s.scalars(select(PolicyVersion).where(
            PolicyVersion.policy_id == policy_id)).all())


def test_delegation_revocation_during_lock_wait(client, engine, monkeypatch):
    """A guardian's mutating request blocked on the tenant lock must not
    complete with a delegation that was revoked while it waited."""
    guardian, gid = _guardian(client, engine, ["policies"])
    policy_id = _second_policy(client)
    versions_before = _version_count(engine, policy_id)  # create snapshot
    holder, tid, pid = _held_tenant_lock(engine)
    waiting = _signaling_main_lock(monkeypatch)
    try:
        with ThreadPoolExecutor(1) as pool, _release_on_exit(holder):
            pending = pool.submit(guardian.put, f"/api/policies/{policy_id}",
                                  json=_update_body(), headers=HDR)
            assert waiting.wait(10)
            # Prove the request is queued on the holder's lock, then
            # commit the revocation underneath it.
            wait_for_blocked(engine, pid)
            with engine.begin() as conn:
                conn.execute(text(
                    "UPDATE users SET delegated_settings='[]' "
                    "WHERE id=:gid"), {"gid": gid})
            holder.rollback()
            holder.close()
            result = pending.result(20)
        # The revocation committed first: the resumed request must fail
        # closed, and nothing may have been written.
        assert result.status_code == 403, result.text
        assert _version_count(engine, policy_id) == versions_before
    finally:
        holder.rollback()
        holder.close()


def test_session_revocation_during_lock_wait(client, engine, monkeypatch):
    """A request blocked on the tenant lock must not complete after its
    own session was revoked (e.g. guardian MFA reset deletes sessions)."""
    guardian, gid = _guardian(client, engine, ["policies"])
    policy_id = _second_policy(client)
    versions_before = _version_count(engine, policy_id)  # create snapshot
    holder, tid, pid = _held_tenant_lock(engine)
    waiting = _signaling_main_lock(monkeypatch)
    try:
        with ThreadPoolExecutor(1) as pool, _release_on_exit(holder):
            pending = pool.submit(guardian.put, f"/api/policies/{policy_id}",
                                  json=_update_body(), headers=HDR)
            assert waiting.wait(10)
            wait_for_blocked(engine, pid)
            with engine.begin() as conn:
                conn.execute(text(
                    "DELETE FROM auth_sessions WHERE user_id=:gid"),
                    {"gid": gid})
            holder.rollback()
            holder.close()
            result = pending.result(20)
        assert result.status_code == 401, result.text
        assert _version_count(engine, policy_id) == versions_before
    finally:
        holder.rollback()
        holder.close()


@pytest.mark.parametrize("change, expected", [
    ("UPDATE users SET role='viewer' WHERE id=:gid", 403),
    ("UPDATE users SET staff_role='read_only' WHERE id=:gid", 403),
    ("UPDATE users SET totp_secret=NULL WHERE id=:gid", 403),
    ("UPDATE auth_sessions SET expires_at='2000-01-01' WHERE user_id=:gid", 401),
])
def test_other_authorization_changes_during_lock_wait(
        client, engine, monkeypatch, change, expected):
    guardian, gid = _guardian(client, engine, ["policies"])
    policy_id = _second_policy(client)
    versions_before = _version_count(engine, policy_id)
    holder, tid, pid = _held_tenant_lock(engine)
    waiting = _signaling_main_lock(monkeypatch)
    with ThreadPoolExecutor(1) as pool, _release_on_exit(holder):
        pending = pool.submit(guardian.put, f"/api/policies/{policy_id}",
                              json=_update_body(), headers=HDR)
        assert waiting.wait(10)
        wait_for_blocked(engine, pid)
        with engine.begin() as conn:
            conn.execute(text(change), {"gid": gid})
        holder.rollback()
        result = pending.result(20)
    assert result.status_code == expected, result.text
    assert _version_count(engine, policy_id) == versions_before


def test_http_owner_demotion_commits_before_queued_policy_write(
        client, engine, monkeypatch):
    """All authorization changes here use real HTTP routes. Pause the
    owner's role-change transaction after it locks the tenant, queue the
    target owner's policy write, then let the demotion commit first."""
    import app.guardian_routes as guardian_routes
    target, gid = _guardian(client, engine, ["policies"])
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role='owner' WHERE id=:gid"),
                     {"gid": gid})
    policy_id = _second_policy(client)
    versions_before = _version_count(engine, policy_id)
    acquired = threading.Event()
    release = threading.Event()
    pid_box = []
    original = guardian_routes.lock_tenant

    def pause_after_lock(session, tenant_id):
        original(session, tenant_id)
        pid_box.append(session.scalar(text('SELECT pg_backend_pid()')))
        acquired.set()
        assert release.wait(15)

    monkeypatch.setattr(guardian_routes, 'lock_tenant', pause_after_lock)
    with ThreadPoolExecutor(2) as pool:
        demotion = pool.submit(client.put, f'/api/guardians/{gid}/role',
                               json={'role': 'viewer'}, headers=HDR)
        try:
            assert acquired.wait(10)
            pending = pool.submit(target.put, f'/api/policies/{policy_id}',
                                  json=_update_body(), headers=HDR)
            wait_for_blocked(engine, pid_box[0])
        finally:
            release.set()
        changed = demotion.result(20)
        assert changed.status_code == 200, changed.text
        result = pending.result(20)
    assert result.status_code == 403, result.text
    assert _version_count(engine, policy_id) == versions_before
