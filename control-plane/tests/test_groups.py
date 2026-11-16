"""Tenant groups -> publication -> scheduled device evaluation."""
import os,sys,json
sys.path.insert(0,os.path.dirname(__file__))
from datetime import datetime
from sqlalchemy import select
from test_publications import client,pub_root,login,make_default_policy,HDR,BASE
from app.models import User,Policy,PolicyVersion,Device,DeviceGroup,Tenant
from app.db import session_scope
from app.publication_ops import tenant_root


def setup(client):
    login(client);base=make_default_policy(client)
    body=dict(BASE,name='group-school',schedules=[dict(name='school',days=list(range(7)),start='09:00',end='17:00',timezone='America/New_York',block_domains=['games.example'])])
    p=client.post('/api/policies',json=body,headers=HDR);assert p.status_code==200,p.text
    g=client.post('/api/groups',json={'name':'school','policy_id':p.json()['id']},headers=HDR)
    assert g.status_code==200,g.text
    d=client.post('/api/devices',json={'name':'test-phone'},headers=HDR).json()['id']
    return base,p.json()['id'],g.json()['id'],d


def test_group_policy_publishes_schedule_and_direct_precedence(client,engine,pub_root):
    base,pid,gid,did=setup(client)
    assert client.put(f'/api/groups/{gid}/devices/{did}',headers=HDR).status_code==200
    assert client.post('/api/publications',headers=HDR).status_code==200
    sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__),'../../dns-edge')))
    from policy_bundle import load_bundle
    with session_scope(engine) as s:tid=s.scalar(select(User).where(User.email=='g@example.com')).tenant_id
    bundle=load_bundle(tenant_root(pub_root,tid),now=lambda:datetime.fromisoformat('2026-11-17T10:00:00-05:00'))
    assert bundle.for_device(did).decide('games.example').action=='block'
    # Explicit direct assignment wins; removing membership never erases it.
    assert client.post(f'/api/devices/{did}/assignment',json={'policy_id':base},headers=HDR).status_code==200
    assert client.delete(f'/api/groups/{gid}/devices/{did}',headers=HDR).status_code==200
    assert client.post('/api/publications',headers=HDR).status_code==200
    assert load_bundle(tenant_root(pub_root,tid)).for_device(did).decide('games.example').action=='allow'


def test_groups_role_tenant_name_membership_and_tighten_only(client,engine):
    base,pid,gid,did=setup(client)
    assert client.post('/api/groups',json={'name':'school'},headers=HDR).status_code==409
    assert client.post('/api/groups',json={'name':'  '},headers=HDR).status_code==400
    assert client.put(f'/api/groups/{gid}/devices/{did}',headers=HDR).status_code==200
    second=client.post('/api/groups',json={'name':'bedtime','policy_id':pid},headers=HDR).json()['id']
    assert client.put(f'/api/groups/{second}/devices/{did}',headers=HDR).status_code==200
    groups=client.get('/api/groups').json()['groups']
    assert next(g for g in groups if g['id']==gid)['device_ids']==[]
    assert next(g for g in groups if g['id']==second)['device_ids']==[did]
    with session_scope(engine) as s:
        t=Tenant(name='foreign');s.add(t);s.flush()
        other=DeviceGroup(tenant_id=t.id,name='foreign');s.add(other);s.flush();foreign=other.id
    assert client.put(f'/api/groups/{foreign}/devices/{did}',headers=HDR).status_code==404
    assert client.put(f'/api/groups/{gid}/devices/999999',headers=HDR).status_code==404
    # Weakening an assigned group policy cannot skip the baseline proof.
    weak=dict(BASE,name='group-school',blocklist=[])
    assert client.put(f'/api/policies/{pid}',json=weak,headers=HDR).status_code==409
    login(client,'v@example.com')
    for method,path,body in [('post','/api/groups',{'name':'bad'}),('put',f'/api/groups/{gid}',{'name':'bad'}),('put',f'/api/groups/{gid}/devices/{did}',{}),('delete',f'/api/groups/{second}/devices/{did}',{})]:
        assert client.request(method,path,json=body,headers=HDR).status_code==403
    assert all(g['id']!=foreign for g in client.get('/api/groups').json()['groups'])
