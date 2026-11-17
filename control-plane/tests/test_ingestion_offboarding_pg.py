"""Forced real PostgreSQL interleavings; no sleeps as ordering evidence.

The observer checks pg_blocking_pids, so the test proves a database wait,
not merely that a second Python thread happened to start later.
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app import filter_log_ops
from app.db import session_scope
from app.models import Device, FilterDecision, IssuedCredential, OffboardingCase, User, utcnow
from test_filter_logs import client, mint, mk_device, bearer, HDR, _device_auth, TOKEN_KEY
import pyotp

BATCH = {"decisions": [{"domain": "synthetic.example", "action": "block"}]}


def setup(client, engine, scope):
    dev = mk_device(client)
    token = mint(client, dev, scope=scope)
    with session_scope(engine) as s:
        device = s.get(Device, dev)
        case = OffboardingCase(tenant_id=device.tenant_id, device_id=dev,
            kind="loss_of_authority", status="verified",
            created_by_user_id=s.scalar(select(User.id).where(User.tenant_id == device.tenant_id)),
            verified_at=utcnow(), abm_release_attested_at=utcnow())
        s.add(case); s.flush()
        case_id = case.id
    return dev, token, case_id


def complete(client, case):
    secret = client.app.state._fixture_mfa['logs@example.com']
    return client.post(f'/api/offboarding/cases/{case}/complete', headers=HDR,
        json={'totp_code': pyotp.TOTP(secret).now(), 'confirm': 'complete-offboarding'})


def assert_empty(engine, dev):
    with session_scope(engine) as s:
        assert s.get(Device, dev).state == 'offboarded'
        assert s.query(FilterDecision).filter_by(device_id=dev).count() == 0
        assert all(c.revoked_at for c in s.scalars(select(IssuedCredential).where(
            IssuedCredential.device_id == dev)))


@pytest.mark.parametrize('scope', ['proxy', 'doh'])
def test_verified_ingestion_resumes_after_offboarding_is_rejected(client, engine, monkeypatch, scope):
    """Signature accepted first, completion commits, ingestion resumes last."""
    dev, token, case = setup(client, engine, scope)
    verified, resume = threading.Event(), threading.Event()
    original = filter_log_ops.verify_edge_token

    def paused(*args, **kwargs):
        claims = original(*args, **kwargs)
        verified.set()
        assert resume.wait(15)
        return claims

    monkeypatch.setattr(filter_log_ops, 'verify_edge_token', paused)
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(TestClient(client.app).post, '/api/filter-logs',
                              headers=bearer(token), json=BATCH)
        try:
            assert verified.wait(10)
            result = complete(client, case)
            assert result.status_code == 200, result.text
        finally:
            resume.set()
        result = pending.result(15)
    assert result.status_code == 403, result.text
    assert_empty(engine, dev)


def wait_for_blocked(engine, holder_pid):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with engine.connect() as c:
            blocked = c.scalar(text('SELECT count(*) FROM pg_stat_activity '
                'WHERE :holder = ANY(pg_blocking_pids(pid))'), {'holder': holder_pid})
        if blocked:
            return
        time.sleep(.02)
    pytest.fail('offboarding never blocked on the ingestion database lock')


@pytest.mark.parametrize('scope', ['proxy', 'doh'])
def test_ingestion_holds_lock_until_commit_then_offboarding_purges(client, engine, monkeypatch, scope):
    """Pause AFTER registry validation, before INSERT. Offboarding must wait.

    Old code lets completion commit here, then inserts a surviving row.
    New code forces completion to wait, then deletes the committed row.
    """
    dev, token, case = setup(client, engine, scope)
    validated, resume = threading.Event(), threading.Event()
    holder = {}
    original = filter_log_ops.purge_expired

    def paused(session, *args, **kwargs):
        if threading.current_thread().name != 'MainThread':
            holder['pid'] = session.scalar(text('SELECT pg_backend_pid()'))
            validated.set()
            assert resume.wait(20)
        return original(session, *args, **kwargs)

    monkeypatch.setattr(filter_log_ops, 'purge_expired', paused)
    with ThreadPoolExecutor(2) as pool:
        ingest = pool.submit(TestClient(client.app).post, '/api/filter-logs',
                             headers=bearer(token), json=BATCH)
        offboard = None
        try:
            assert validated.wait(10)
            offboard = pool.submit(complete, client, case)
            wait_for_blocked(engine, holder['pid'])
            assert not offboard.done()
        finally:
            resume.set()
        result = ingest.result(15)
        assert result.status_code == 200, result.text
        result = offboard.result(15)
        assert result.status_code == 200, result.text
    assert_empty(engine, dev)
    result = TestClient(client.app).post('/api/filter-logs', headers=bearer(token), json=BATCH)
    assert result.status_code == 403, result.text
    assert_empty(engine, dev)


@pytest.mark.parametrize('failure', ['offboarded', 'revoked', 'expired', 'scope',
    'tenant', 'device', 'policy', 'missing-device', 'missing-exp'])
def test_postlock_authorization_rejects_invalid_binding(client, engine, failure):
    dev = mk_device(client)
    token = mint(client, dev)
    claims = _device_auth().verify_token(TOKEN_KEY.encode(), token, 'proxy')
    with session_scope(engine) as s:
        cred = s.scalar(select(IssuedCredential).where(IssuedCredential.jti == claims['jti']))
        if failure == 'offboarded': s.get(Device, dev).state = 'offboarded'
        elif failure == 'revoked': cred.revoked_at = utcnow()
        elif failure == 'expired': cred.expires_at = utcnow() - timedelta(seconds=1)
        elif failure == 'scope': claims['scope'] = 'doh'
        elif failure == 'tenant': claims['tenant_id'] = int(claims['tenant_id']) + 100000
        elif failure == 'device': claims['device_id'] = mk_device(client, 'other')
        elif failure == 'policy': claims['policy_id'] = 999999
        elif failure == 'missing-device': claims.pop('device_id')
        elif failure == 'missing-exp': claims.pop('exp')
    with session_scope(engine) as s:
        # Warm stale objects too: populate_existing must replace these.
        s.get(Device, dev)
        s.scalar(select(IssuedCredential).where(IssuedCredential.jti == claims['jti']))
        with pytest.raises(filter_log_ops.FilterLogError) as exc:
            filter_log_ops.record_decisions(s, claims, BATCH['decisions'])
        assert exc.value.status == 403
        assert s.query(FilterDecision).filter_by(device_id=dev).count() == 0


def test_mint_cannot_restore_offboarded_access(client, engine):
    dev, token, case = setup(client, engine, 'proxy')
    assert complete(client, case).status_code == 200
    for scope in ('proxy', 'doh', 'dataset'):
        result = client.post(f'/api/devices/{dev}/dataset-credential',
                             json={'scope': scope}, headers=HDR)
        assert result.status_code == 409, result.text
    assert_empty(engine, dev)


@pytest.mark.parametrize('mutation', ['revoke', 'expire', 'offboard', 'rebind'])
def test_waiter_refreshes_cached_authority_after_tenant_lock(engine, mutation):
    """A warm ORM cache is not authorization after waiting on a tenant lock."""
    from app.db import lock_tenant
    from app.models import Tenant
    from sqlalchemy.orm import Session
    from test_activity_privacy import _live_claims
    with session_scope(engine) as s:
        tenant = Tenant(name='cache-wait')
        s.add(tenant); s.flush()
        claims = _live_claims(s, tenant)
        tid, dev = tenant.id, claims['device_id']
        other = Device(tenant_id=tid, name='other')
        s.add(other); s.flush(); other_id = other.id
    warmed, resume = threading.Event(), threading.Event()

    def ingest():
        with Session(engine) as s:
            # Strong references retain the old identity-map values.
            cached_device = s.get(Device, dev)
            cached_credential = s.scalar(select(IssuedCredential))
            warmed.set()
            assert resume.wait(15)
            with pytest.raises(filter_log_ops.FilterLogError):
                filter_log_ops.record_decisions(s, claims, BATCH['decisions'])
            assert cached_device.id == dev and cached_credential.jti == claims['jti']
            s.rollback()

    with ThreadPoolExecutor(1) as pool:
        waiting = pool.submit(ingest)
        try:
            assert warmed.wait(10)
            with Session(engine) as s:
                lock_tenant(s, tid)
                holder = s.scalar(text('SELECT pg_backend_pid()'))
                cred = s.scalar(select(IssuedCredential))
                if mutation == 'revoke': cred.revoked_at = utcnow()
                elif mutation == 'expire': cred.expires_at = utcnow() - timedelta(seconds=1)
                elif mutation == 'offboard': s.get(Device, dev).state = 'offboarded'
                else: cred.device_id = other_id
                s.flush()
                resume.set()
                wait_for_blocked(engine, holder)
                s.commit()
            waiting.result(15)
        finally:
            resume.set()
    with session_scope(engine) as s:
        assert s.query(FilterDecision).count() == 0


def test_worker_rechecks_actor_after_revocation_lock_wait(client, engine, tmp_path):
    """A queued publication cannot use pre-wait guardian/owner authority."""
    from app.db import lock_tenant
    from test_publications import make_default_policy
    from app.models import Role, PublicationJob
    from app.worker import enqueue, run_once
    from app.config import Settings
    from sqlalchemy.orm import Session
    make_default_policy(client)
    with session_scope(engine) as s:
        actor = s.scalar(select(User).where(User.email == 'logs@example.com'))
        tid, uid = actor.tenant_id, actor.id
        job = enqueue(s, tid, uid, actor.email, 'forced-revocation-wait')
        job_id = job.id
    settings = Settings({'KG_DATABASE_URL': 'postgresql://placeholder',
        'KG_PUBLICATIONS_ROOT': str(tmp_path / 'publications')})
    with ThreadPoolExecutor(1) as pool:
        with Session(engine) as s:
            lock_tenant(s, tid)
            holder = s.scalar(text('SELECT pg_backend_pid()'))
            pending = pool.submit(run_once, engine, settings)
            try:
                wait_for_blocked(engine, holder)
                s.get(User, uid).role = Role.viewer
                s.commit()
            finally:
                s.rollback()
        assert pending.result(15)
    with session_scope(engine) as s:
        row = s.get(PublicationJob, job_id)
        assert row.status == 'queued' and row.attempts == 1
        assert row.result is None
        assert row.last_error == 'publication failed; inspect local worker diagnostics'
    assert not (tmp_path / 'publications').exists()
