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
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../dns-edge')))
    from policy_bundle import load_bundle
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
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../dns-edge')))
    from policy_bundle import load_bundle
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
