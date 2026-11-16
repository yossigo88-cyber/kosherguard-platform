import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from test_publications import client, pub_root, login, make_default_policy, HDR
from app.policy_preview import preview, TEMPLATES
from app.db import session_scope
from app.models import Policy
import pytest


def test_strict_template_and_domain_only():
    rules = TEMPLATES['strict-review']['rules']
    from app.policy_ops import normalize_engine_doc
    assert preview(normalize_engine_doc(rules), 'unknown.example')['action'] == 'block'
    with pytest.raises(ValueError): preview(normalize_engine_doc(rules), 'https://private.example/path?token=secret')


def test_preview_matches_policy_and_tenant_scope(client, engine):
    login(client); pid = make_default_policy(client)
    r = client.post(f'/api/policies/{pid}/preview', json={'domain': 'bad.example'}, headers=HDR)
    assert r.status_code == 200 and r.json()['action'] == 'block'
    assert 'not verified device' in r.json()['scope']
    assert client.get('/api/policy-templates').status_code == 200
    with session_scope(engine) as s:
        from app.models import Tenant
        t = Tenant(name='foreign'); s.add(t); s.flush()
        s.get(Policy, pid).tenant_id = t.id
    assert client.post(f'/api/policies/{pid}/preview', json={'domain': 'bad.example'}, headers=HDR).status_code == 404


def test_preview_schedule_and_offset_validation():
    from datetime import datetime
    doc = {"default_policy": "allow", "allowlist": [], "blocklist": [],
           "category_rules": {"allow": [], "block": []},
           "_schedules": [{"name": "night", "days": [0,1,2,3,4,5,6],
             "start": 1260, "end": 360, "timezone": "America/New_York",
             "start_date": "2026-11-17", "end_date": "2026-11-17",
             "block_domains": ["games.example"], "block_categories": [], "enabled": True}]}
    assert preview(doc, 'games.example', moment=datetime.fromisoformat('2026-11-17T22:00:00-05:00'))['action'] == 'block'
    assert preview(doc, 'games.example', moment=datetime.fromisoformat('2026-11-17T12:00:00-05:00'))['action'] == 'allow'
    with pytest.raises(ValueError): preview(doc, 'games.example', moment=datetime(2026,11,17))
    for domain in ['a b.example', 'bad.example:443', 'https://bad.example', 'localhost']:
        with pytest.raises(ValueError): preview(doc, domain)
