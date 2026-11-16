"""Real MFA, direct API bypasses, explicit delegation and baseline invariants."""
import os,sys,json
sys.path.insert(0,os.path.dirname(__file__))
from test_publications import client,pub_root,login,make_default_policy,HDR,BASE,PASSWORD
from app.models import User,Role,Tenant,Policy,AuditEvent
from app.db import session_scope
from sqlalchemy import select
from fastapi.testclient import TestClient
from mfa_support import mfa_login


def guardian_client(client,engine):
    with session_scope(engine) as s:
        owner=s.scalar(select(User).where(User.email=='g@example.com'))
        u=User(tenant_id=owner.tenant_id,email='parent@example.com',password_hash=owner.password_hash,role=Role.guardian)
        s.add(u);s.flush();uid=u.id
    c=TestClient(client.app)
    assert mfa_login(c,json={'email':'parent@example.com','password':PASSWORD},headers=HDR).status_code==200
    return c,uid


def grant(owner,uid,capabilities):
    r=owner.put(f'/api/guardians/{uid}/delegation',json={'capabilities':capabilities},headers=HDR)
    assert r.status_code==200,r.text


def test_default_deny_baseline_replacement_schedule_and_delegation(client,engine):
    login(client);base=make_default_policy(client)
    g,uid=guardian_client(client,engine)
    assert g.post('/api/devices',json={'name':'x'},headers=HDR).status_code==403
    grant(client,uid,['policies','schedules','devices','groups','apps','publish'])
    for body in [dict(BASE,name='fam',blocklist=[]),dict(BASE,name='fam',enabled=False),dict(BASE,name='fam',allowlist=['bad.example'])]:
        assert g.put(f'/api/policies/{base}',json=body,headers=HDR).status_code==403
    assert g.put(f'/api/policies/{base}/schedules',json={'schedules':[]},headers=HDR).status_code==403
    assert g.post(f'/api/policies/{base}/select',headers=HDR).status_code==403
    assert g.post('/api/policies',json=dict(BASE,name='weak',blocklist=[]),headers=HDR).status_code==409
    assert g.put(f'/api/guardians/{uid}/delegation',json={'capabilities':['policies']},headers=HDR).status_code==403
    assert client.put(f'/api/guardians/{uid}/delegation',json={'capabilities':['baseline']},headers=HDR).status_code==400
    # Legitimate delegated tighter policy, schedule and group assignment.
    r=g.post('/api/policies',json=dict(BASE,name='tighter',blocklist=['bad.example','games.example']),headers=HDR)
    assert r.status_code==200,r.text
    pid=r.json()['id']
    d=g.post('/api/devices',json={'name':'delegated-phone'},headers=HDR);assert d.status_code==200
    did=d.json()['id']
    assert g.put(f'/api/policies/{pid}/schedules',json={'schedules':[dict(name='school',days=[0],start='09:00',end='17:00',timezone='America/New_York',block_domains=['video.example'])]},headers=HDR).status_code==200
    gid=g.post('/api/groups',json={'name':'school','policy_id':pid},headers=HDR).json()['id']
    assert g.put(f'/api/groups/{gid}/devices/{did}',headers=HDR).status_code==200
    assert g.post(f'/api/devices/{did}/assignment',json={'policy_id':pid},headers=HDR).status_code==200
    assert g.put(f'/api/policies/{pid}',json=dict(BASE,name='tighter',blocklist=[]),headers=HDR).status_code==409
    grant(client,uid,[])
    assert g.put(f'/api/policies/{pid}/schedules',json={'schedules':[]},headers=HDR).status_code==403


def test_baseline_owner_audit_cross_tenant_and_profile_bypass(client,engine):
    login(client);base=make_default_policy(client);g,uid=guardian_client(client,engine)
    grant(client,uid,['devices','apps','policies'])
    assert g.post('/api/admin/categories',json={'domain':'bad.example','category':'safe','verdict':'allow','source':'x'},headers=HDR).status_code==403
    for command in ['RemoveProfile','InstallProfile','RemoveApplication','DeviceLock']:
        assert g.post('/api/mdm/enrollments/999/commands',json={'command':command,'payload':{}},headers=HDR).status_code==403
    assert g.post('/api/devices/999/app-commands',json={'action':'remove','bundle_id':'com.kosherguard.app'},headers=HDR).status_code==403
    assert g.put('/api/devices/999/app-policy',json={'mode':'blocklist','bundle_ids':[]},headers=HDR).status_code==403
    with session_scope(engine) as s:
        t=Tenant(name='foreign');s.add(t);s.flush()
        other=User(tenant_id=t.id,email='other@example.com',role=Role.guardian,password_hash='synthetic');s.add(other)
        p=Policy(tenant_id=t.id,name='foreign',engine_doc=json.dumps(dict(default_policy='block',allowlist=[],blocklist=[],category_rules={'allow':[],'block':[]})));s.add(p);s.flush();foreign=p.id;otherid=other.id
    assert client.put(f'/api/guardians/{otherid}/delegation',json={'capabilities':['policies']},headers=HDR).status_code==404
    assert client.put(f'/api/policies/{foreign}',json=dict(BASE,name='bad'),headers=HDR).status_code==404
    assert g.put(f'/api/policies/{foreign}',json=dict(BASE,name='bad'),headers=HDR).status_code==404
    assert client.put(f'/api/policies/{base}',json=dict(BASE,name='updated-baseline'),headers=HDR).status_code==200
    with session_scope(engine) as s:
        actions=list(s.scalars(select(AuditEvent.action)))
        assert 'policy.update' in actions and 'policy.select_default' in actions and 'guardian.delegation' in actions
