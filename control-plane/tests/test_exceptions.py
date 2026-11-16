"""Scoped time-limited exceptions: delegation, limits, publication, edge."""
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from test_publications import client, pub_root, login, make_default_policy, HDR, BASE
from test_protected_baseline import guardian_client, grant
from app.models import AuditEvent, User
from app.db import session_scope
from app.publication_ops import tenant_root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../dns-edge')))
from policy_bundle import load_bundle


def future(hours):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def setup(client):
    login(client)
    make_default_policy(client)
    did = client.post('/api/devices', json={'name': 'kid-phone'},
                      headers=HDR).json()['id']
    return did


def block_policy(client, did):
    pid = client.post('/api/policies', json=dict(
        BASE, name='school',
        blocklist=list(BASE['blocklist']) + ['games.example']),
        headers=HDR).json()['id']
    gid = client.post('/api/groups', json={'name': 'school',
                                           'policy_id': pid},
                      headers=HDR).json()['id']
    assert client.put(f'/api/groups/{gid}/devices/{did}',
                      headers=HDR).status_code == 200
    return pid, gid


def test_guardian_limited_exception_publishes_and_expires(client, engine,
                                                          pub_root):
    did = setup(client)
    pid, gid = block_policy(client, did)
    g, uid = guardian_client(client, engine)
    # Default deny: no exception capability granted yet.
    assert g.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': did,
        'domains': ['games.example'], 'reason': 'contest',
        'expires_at': future(2)}, headers=HDR).status_code == 403
    grant(client, uid, ['exceptions'])
    # Guardian limits: no protection removal, max 24 hours.
    assert g.post('/api/exceptions', json={
        'kind': 'disable_policy', 'scope_type': 'device', 'device_id': did,
        'reason': 'x', 'expires_at': future(2)}, headers=HDR).status_code == 403
    assert g.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': did,
        'domains': ['games.example'], 'reason': 'x',
        'expires_at': future(48)}, headers=HDR).status_code == 403
    r = g.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'group', 'group_id': gid,
        'domains': ['games.example'], 'reason': 'class tournament',
        'expires_at': future(2)}, headers=HDR)
    assert r.status_code == 200, r.text
    # Publication carries the active window; the edge honors it.
    assert client.post('/api/publications', headers=HDR).status_code == 200
    with session_scope(engine) as s:
        tid = s.scalar(select(User).where(User.email == 'g@example.com')).tenant_id
    root = tenant_root(pub_root, tid)
    now = datetime.now(timezone.utc)
    assert load_bundle(root, now=lambda: now).for_device(did).decide(
        'games.example').action == 'allow'
    # After the window the group policy's block applies again.
    later = now + timedelta(hours=3)
    assert load_bundle(root, now=lambda: later).for_device(did).decide(
        'games.example').action == 'block'
    # Revocation removes it from the next generation.
    assert g.delete(f"/api/exceptions/{r.json()['id']}",
                    headers=HDR).status_code == 200
    assert client.post('/api/publications', headers=HDR).status_code == 200
    assert load_bundle(root, now=lambda: now).for_device(did).decide(
        'games.example').action == 'block'
    with session_scope(engine) as s:
        actions = list(s.scalars(select(AuditEvent.action)))
        assert 'exception.create' in actions and 'exception.revoke' in actions


def test_owner_high_impact_scope_and_validation(client, engine, pub_root):
    did = setup(client)
    pid, gid = block_policy(client, did)
    # Expiration is mandatory; cross-tenant targets are 404.
    assert client.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': did,
        'domains': ['games.example'], 'reason': 'x'},
        headers=HDR).status_code == 400
    assert client.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': 999999,
        'domains': ['games.example'], 'reason': 'x',
        'expires_at': future(2)}, headers=HDR).status_code == 404
    r = client.post('/api/exceptions', json={
        'kind': 'disable_policy', 'scope_type': 'device', 'device_id': did,
        'reason': 'repair window', 'expires_at': future(72)}, headers=HDR)
    assert r.status_code == 200, r.text
    assert client.post('/api/publications', headers=HDR).status_code == 200
    with session_scope(engine) as s:
        tid = s.scalar(select(User).where(User.email == 'g@example.com')).tenant_id
    now = datetime.now(timezone.utc)
    assert load_bundle(tenant_root(pub_root, tid), now=lambda: now).for_device(
        did).decide('games.example').action == 'allow'
    # A viewer cannot create or revoke exceptions.
    login(client, 'v@example.com')
    assert client.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': did,
        'domains': ['x.example'], 'reason': 'x',
        'expires_at': future(1)}, headers=HDR).status_code == 403
    assert client.delete(f"/api/exceptions/{r.json()['id']}",
                         headers=HDR).status_code == 403


def test_guardian_exception_cannot_weaken_protected_baseline(client, engine,
                                                             pub_root):
    """13:32 rule: delegated exceptions relax guardian-added restrictions
    but never the owner-controlled protected baseline (domain, default
    or schedule blocks), at the edge both consumers load."""
    did = setup(client)
    pid, gid = block_policy(client, did)
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['exceptions'])
    r = g.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'group', 'group_id': gid,
        'domains': ['bad.example', 'games.example'], 'reason': 'test',
        'expires_at': future(2)}, headers=HDR)
    assert r.status_code == 200, r.text
    assert client.post('/api/publications', headers=HDR).status_code == 200
    with session_scope(engine) as s:
        tid = s.scalar(select(User).where(User.email == 'g@example.com')).tenant_id
    root = tenant_root(pub_root, tid)
    now = datetime.now(timezone.utc)
    device_engine = load_bundle(root, now=lambda: now).for_device(did)
    # bad.example is blocked by the protected baseline (default policy):
    # the exception cannot open it.
    decision = device_engine.decide('bad.example')
    assert decision.action == 'block'
    assert 'protected baseline' in decision.reason
    # games.example is blocked only by the guardian-added group policy:
    # a legitimate exception relaxes it.
    assert device_engine.decide('games.example').action == 'allow'


def test_revoke_enqueues_republication(client, engine, pub_root):
    """Revocation is eventual: it enqueues a republication that must
    execute even though the revoking guardian lacks publish delegation,
    and the resulting edge generation must no longer carry the bypass."""
    did = setup(client)
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['exceptions'])  # no 'publish' delegation
    r = g.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': did,
        'domains': ['games.example'], 'reason': 'x',
        'expires_at': future(2)}, headers=HDR)
    assert r.status_code == 200, r.text
    ex_id = r.json()['id']
    assert client.post('/api/publications', headers=HDR).status_code == 200
    with session_scope(engine) as s:
        tid = s.scalar(select(User).where(User.email == 'g@example.com')).tenant_id
    root = tenant_root(pub_root, tid)
    now = datetime.now(timezone.utc)
    assert load_bundle(root, now=lambda: now).for_device(did).decide(
        'games.example').rule == 'exception_allow_domains'
    assert g.delete(f"/api/exceptions/{ex_id}", headers=HDR).status_code == 200
    from app.models import PublicationJob
    from app.worker import run_once
    from test_baseline_edges import settings
    with session_scope(engine) as s:
        job = s.scalar(select(PublicationJob).where(
            PublicationJob.request_key.like(f'exception-revoke-{ex_id}-%')))
    assert job is not None and job.status == 'queued'
    # Narrow system cleanup: the real revoker stays the job's actor (no
    # fabricated owner/MFA approval), marked server-side as
    # exception-revoke cleanup.
    assert job.actor_user_id == uid
    assert job.system_action == 'exception-revoke'
    # The guardian revoker has no publish delegation; the job still runs.
    assert run_once(engine, settings(pub_root))
    with session_scope(engine) as s:
        job = s.get(PublicationJob, job.id)
        assert job.status == 'completed', job.last_error
        import json as _json
        assert _json.loads(job.result)['revision']
        cleanup_audit = s.scalar(select(AuditEvent).where(
            AuditEvent.action == 'publication.completed',
            AuditEvent.detail.like(f'%job {job.id}%')))
        assert 'exception-revoke' in cleanup_audit.detail
        assert f'initiated by user {uid}' in cleanup_audit.detail
    from app.publisher import Publisher
    manifest = Publisher(tenant_root(pub_root, tid)).current()
    assert manifest['published_by'].startswith('system:exception-revoke')
    # The resulting generation no longer carries the exception.
    decision = load_bundle(root, now=lambda: now).for_device(did).decide(
        'games.example')
    assert decision.rule != 'exception_allow_domains'
    assert 'exception' not in decision.reason


def test_cross_tenant_exception_targeting_refused(client, engine):
    did = setup(client)
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['exceptions'])
    # A device id outside the guardian's tenant must not be targetable.
    with session_scope(engine) as s:
        from app.models import Device, Tenant
        other = Tenant(name='foreign-tenant')
        s.add(other)
        s.flush()
        s.add(Device(tenant_id=other.id, name='foreign'))
        s.flush()
        foreign_id = s.scalar(select(Device).where(
            Device.tenant_id == other.id)).id
    r = g.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device',
        'device_id': foreign_id, 'domains': ['x.example'], 'reason': 'x',
        'expires_at': future(1)}, headers=HDR)
    assert r.status_code in (400, 404)


def test_revoke_cleanup_survives_owner_unavailable(client, engine, pub_root):
    """If the owner is demoted or loses MFA enrollment, the revocation
    cleanup publication must still run: the revoked bypass must not stay
    effective waiting for an owner who cannot act."""
    did = setup(client)
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['exceptions'])
    r = g.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': did,
        'domains': ['games.example'], 'reason': 'x',
        'expires_at': future(2)}, headers=HDR)
    assert r.status_code == 200, r.text
    assert g.delete(f"/api/exceptions/{r.json()['id']}",
                    headers=HDR).status_code == 200
    # Owner becomes unable to publish: demoted and MFA unenrolled.
    with session_scope(engine) as s:
        owner = s.scalar(select(User).where(User.email == 'g@example.com'))
        owner.role = owner.role.viewer
        owner.totp_secret = None
    from app.models import PublicationJob
    from app.worker import run_once
    from test_baseline_edges import settings
    assert run_once(engine, settings(pub_root))
    with session_scope(engine) as s:
        job = s.scalar(select(PublicationJob).where(
            PublicationJob.request_key.like('exception-revoke-%')))
        assert job.status == 'completed', job.last_error


def test_api_enqueued_job_has_no_system_marker(client, engine):
    """The jobs API must not be able to mint the cleanup marker: ordinary
    enqueues keep the full actor re-check at execution."""
    login(client)
    make_default_policy(client)
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['publish'])
    jid = g.post('/api/publications/jobs',
                 json={'request_key': 'exception-revoke-forged'},
                 headers=HDR).json()['id']
    from app.models import PublicationJob
    with session_scope(engine) as s:
        job = s.get(PublicationJob, jid)
        assert job.system_action is None


def test_cleanup_does_not_ship_pending_changes(client, engine, pub_root):
    """Revocation cleanup is removal-only: it must republish the last
    published snapshot minus the revoked exception, never the tenant's
    current saved state. A saved-but-unpublished delegated weakening
    (still above baseline) and a newly saved owner disable_policy
    exception both stay pending."""
    did = setup(client)
    pid, gid = block_policy(client, did)  # school policy: +games.example
    # Strengthen the assigned policy with a second block, then publish
    # with an exception on the first.
    r = client.put(f'/api/policies/{pid}', json=dict(
        BASE, name='school',
        blocklist=['bad.example', 'games.example', 'chat.example']),
        headers=HDR)
    assert r.status_code == 200, r.text
    r = client.post('/api/exceptions', json={
        'kind': 'allow_domains', 'scope_type': 'device', 'device_id': did,
        'domains': ['games.example'], 'reason': 'tournament',
        'expires_at': future(2)}, headers=HDR)
    assert r.status_code == 200, r.text
    ex_id = r.json()['id']
    assert client.post('/api/publications', headers=HDR).status_code == 200
    with session_scope(engine) as s:
        tid = s.scalar(select(User).where(User.email == 'g@example.com')).tenant_id
    root = tenant_root(pub_root, tid)
    now = datetime.now(timezone.utc)
    eng1 = load_bundle(root, now=lambda: now).for_device(did)
    assert eng1.decide('games.example').action == 'allow'      # exception
    assert eng1.decide('chat.example').action == 'block'       # published
    # Pending change 1: delegated weakening above baseline (drop chat).
    r = client.put(f'/api/policies/{pid}', json=dict(
        BASE, name='school', blocklist=['bad.example', 'games.example']),
        headers=HDR)
    assert r.status_code == 200, r.text
    # Pending change 2: a brand-new owner disable_policy exception.
    r = client.post('/api/exceptions', json={
        'kind': 'disable_policy', 'scope_type': 'device', 'device_id': did,
        'reason': 'repair window', 'expires_at': future(2)}, headers=HDR)
    assert r.status_code == 200, r.text
    # Revoke the original exception; the cleanup runs.
    assert client.delete(f"/api/exceptions/{ex_id}",
                         headers=HDR).status_code == 200
    from app.worker import run_once
    from test_baseline_edges import settings
    assert run_once(engine, settings(pub_root))
    eng2 = load_bundle(root, now=lambda: now).for_device(did)
    # Revoked exception removed...
    assert eng2.decide('games.example').action == 'block'
    # ...but neither pending change shipped.
    assert eng2.decide('chat.example').action == 'block'  # weakening pending
    assert eng2.decide('bad.example').action == 'block'   # no disable_policy
