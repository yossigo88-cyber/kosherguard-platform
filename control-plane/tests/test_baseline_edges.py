"""Edge invariants: no-baseline denial, disabled group policy, revoked
publish delegation at worker execution, platform category flag."""
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.config import Settings
from app.db import session_scope
from app.models import PublicationJob, Policy, User
from app.worker import run_once
from test_publications import client, pub_root, login, make_default_policy, HDR, BASE
from test_protected_baseline import guardian_client, grant


def settings(root):
    return Settings({'KG_DATABASE_URL': 'postgresql://local-test',
                     'KG_PUBLICATIONS_ROOT': root})


def test_guardian_blocked_until_owner_selects_baseline(client, engine):
    login(client)  # no default selected yet
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['policies'])
    r = g.post('/api/policies', json=dict(BASE, name='early'), headers=HDR)
    assert r.status_code == 409 and 'baseline' in r.json()['error']
    base = make_default_policy(client)
    r = g.post('/api/policies', json=dict(BASE, name='tighter',
                                          blocklist=['bad.example']),
               headers=HDR)
    assert r.status_code == 200, r.text


def test_disabled_assigned_group_policy_refuses_publish(client, engine,
                                                        pub_root):
    login(client)
    make_default_policy(client)
    pid = client.post('/api/policies', json=dict(
        BASE, name='group-school', blocklist=['bad.example']),
        headers=HDR).json()['id']
    gid = client.post('/api/groups', json={'name': 'school',
                                           'policy_id': pid},
                      headers=HDR).json()['id']
    did = client.post('/api/devices', json={'name': 'test-phone'},
                      headers=HDR).json()['id']
    assert client.put(f'/api/groups/{gid}/devices/{did}',
                      headers=HDR).status_code == 200
    assert client.post('/api/publications', headers=HDR).status_code == 200
    # A disabled policy must never reach devices silently; publication
    # refuses rather than dropping the device to the weaker default.
    with session_scope(engine) as s:
        s.get(Policy, pid).enabled = False
    r = client.post('/api/publications', headers=HDR)
    assert r.status_code == 409 and 'disabled policy' in r.json()['error']


def test_worker_rechecks_publish_delegation_at_execution(client, engine,
                                                         pub_root):
    login(client)
    make_default_policy(client)
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['publish'])
    jid = g.post('/api/publications/jobs', json={'request_key': 'delegated'},
                 headers=HDR).json()['id']
    # Delegation revoked before the worker picks the job up: it must not
    # run under the stale queue-time grant.
    grant(client, uid, [])
    assert run_once(engine, settings(pub_root))
    with session_scope(engine) as s:
        job = s.get(PublicationJob, jid)
        assert job.status == 'queued' and job.last_error is not None
    now = datetime.now(timezone.utc) + timedelta(hours=1)
    for _ in range(4):
        now += timedelta(minutes=10)
        assert run_once(engine, settings(pub_root), now=now)
    with session_scope(engine) as s:
        assert s.get(PublicationJob, jid).status == 'failed'
    now += timedelta(minutes=10)
    # Re-granting lets the next queued job publish normally.
    grant(client, uid, ['publish'])
    jid2 = g.post('/api/publications/jobs', json={'request_key': 'granted'},
                  headers=HDR).json()['id']
    assert run_once(engine, settings(pub_root), now=now)
    with session_scope(engine) as s:
        assert s.get(PublicationJob, jid2).status == 'completed'


def test_category_admin_requires_owner_and_platform_flag(client, engine):
    login(client)
    assert client.post('/api/admin/categories', json={
        'domain': 'bad.example', 'category': 'adult', 'verdict': 'block',
        'source': 'review'}, headers=HDR).status_code == 403
    with session_scope(engine) as s:
        s.scalar(select(User).where(
            User.email == 'g@example.com')).is_platform_admin = True
        s.scalar(select(User).where(
            User.email == 'g@example.com')).staff_role = 'owner'
    assert client.post('/api/admin/categories', json={
        'domain': 'bad.example', 'category': 'adult', 'verdict': 'block',
        'source': 'review'}, headers=HDR).status_code == 200
    # A guardian never reaches category admin, even with the flag set.
    g, uid = guardian_client(client, engine)
    grant(client, uid, ['policies'])
    with session_scope(engine) as s:
        s.scalar(select(User).where(
            User.email == 'parent@example.com')).is_platform_admin = True
    assert g.post('/api/admin/categories', json={
        'domain': 'x.example', 'category': 'adult', 'verdict': 'block',
        'source': 'review'}, headers=HDR).status_code == 403
