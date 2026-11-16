"""Durable worker integration, real PostgreSQL, no external effects."""
import json
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.config import Settings
from app.db import session_scope
from app.models import PublicationJob, PublicationState, User
from app.publisher import Publisher
from app.publication_ops import tenant_root
from app.worker import enqueue, run_once
from test_publications import client, pub_root, login, make_default_policy, HDR


def settings(root):
    return Settings({'KG_DATABASE_URL': 'postgresql://local-test',
                     'KG_PUBLICATIONS_ROOT': root})


def test_http_queue_restart_and_idempotency(client, engine, pub_root):
    login(client)
    make_default_policy(client)
    payload = {'request_key': 'retry-client-request'}
    a = client.post('/api/publications/jobs', json=payload, headers=HDR)
    b = client.post('/api/publications/jobs', json=payload, headers=HDR)
    assert a.status_code == 200 and a.json()['id'] == b.json()['id']
    assert a.json()['status'] == 'queued'
    jid = a.json()['id']
    # A fresh worker session sees a request committed by the HTTP session.
    assert run_once(engine, settings(pub_root))
    assert not run_once(engine, settings(pub_root))
    result = client.get(f'/api/publications/jobs/{jid}').json()
    assert result['status'] == 'completed' and result['attempts'] == 1
    assert result['result']['revision'] == 1


def test_cross_tenant_and_viewer_denied(client, engine, pub_root):
    login(client)
    queued = client.post('/api/publications/jobs',
                         json={'request_key': 'same'}, headers=HDR).json()
    login(client, email='v@example.com')
    assert client.post('/api/publications/jobs',
                       json={'request_key': 'v'}, headers=HDR).status_code == 403
    with session_scope(engine) as s:
        job = s.get(PublicationJob, queued['id'])
        # A forged tenant mismatch must not disclose the job via lookup.
        owner = s.scalar(select(User).where(User.email == 'g@example.com'))
        from app.models import Tenant
        t = Tenant(name='other'); s.add(t); s.flush()
        job.tenant_id = t.id
    login(client)
    assert client.get(f"/api/publications/jobs/{queued['id']}").status_code == 404


def test_retry_backoff_and_terminal_failure(client, engine, pub_root):
    login(client)  # deliberately no selected policy
    jid = client.post('/api/publications/jobs', json={'request_key': 'fail'},
                      headers=HDR).json()['id']
    now = datetime.now(timezone.utc) + timedelta(seconds=1)
    for n in range(1, 6):
        assert run_once(engine, settings(pub_root), now=now)
        with session_scope(engine) as s:
            job = s.get(PublicationJob, jid)
            assert job.attempts == n
            assert job.status == ('failed' if n == 5 else 'queued')
            if n < 5:
                assert not run_once(engine, settings(pub_root), now=now)
                now = job.available_at + timedelta(seconds=1)
    assert not run_once(engine, settings(pub_root), now=now+timedelta(hours=1))


def test_after_activation_before_commit_recovery(client, engine, pub_root):
    login(client); make_default_policy(client)
    jid = client.post('/api/publications/jobs', json={'request_key': 'crash'},
                      headers=HDR).json()['id']
    from app.publication_ops import publish_selected
    with session_scope(engine) as s:
        job = s.get(PublicationJob, jid)
        tenant_id = job.tenant_id
        publish_selected(s, tenant_id, pub_root, job.actor_email,
                         publication_job_id=jid)
        s.rollback()  # emulate killed worker AFTER disk activation
    assert run_once(engine, settings(pub_root))
    with session_scope(engine) as s:
        job = s.get(PublicationJob, jid)
        assert json.loads(job.result)['recovered']
        assert s.get(PublicationState, tenant_id).revision == 1
        assert Publisher(tenant_root(pub_root, tenant_id)).current()['revision'] == 1


def test_locked_job_is_not_picked_by_second_worker(client, engine, pub_root):
    login(client); make_default_policy(client)
    jid = client.post('/api/publications/jobs', json={'request_key': 'lock'},
                      headers=HDR).json()['id']
    with session_scope(engine) as s:
        s.scalar(select(PublicationJob).where(PublicationJob.id == jid).with_for_update())
        assert not run_once(engine, settings(pub_root))
    assert run_once(engine, settings(pub_root))


def test_demoted_actor_cannot_execute_queued_privileged_job(client, engine, pub_root):
    from app.models import Role
    login(client);make_default_policy(client)
    jid=client.post('/api/publications/jobs',json={'request_key':'revoked-actor'},headers=HDR).json()['id']
    with session_scope(engine) as s:
        actor=s.scalar(select(User).where(User.email=='g@example.com'));actor.role=Role.viewer
    assert run_once(engine,settings(pub_root))
    with session_scope(engine) as s:
        job=s.get(PublicationJob,jid)
        assert job.status != 'completed'
        assert s.get(PublicationState,job.tenant_id).revision==0
