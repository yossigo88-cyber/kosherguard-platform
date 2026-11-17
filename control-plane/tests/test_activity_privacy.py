"""Physical retention and identifier minimization, no real browsing data."""
import os,sys
sys.path.insert(0,os.path.dirname(__file__))
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func
from app.db import session_scope
from app.models import Device, IssuedCredential, Tenant, FilterDecision
from app.filter_log_ops import record_decisions, purge_expired, recent_decisions


def _live_claims(s, t):
    """record_decisions requires a live issuance-registry row for the
    token's jti (revoked/expired/unknown credentials are refused), so
    direct unit callers register one."""
    dev = Device(tenant_id=t.id, name='privacy-device')
    s.add(dev); s.flush()
    s.add(IssuedCredential(tenant_id=t.id, device_id=dev.id,
                           jti='privacy-jti', scope='proxy',
                           expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    s.flush()
    return {'tenant_id': t.id, 'scope': 'proxy', 'jti': 'privacy-jti',
            'device_id': dev.id}


def test_allowed_never_stored_and_free_text_not_copied(engine):
    with session_scope(engine) as s:
        t=Tenant(name='privacy');s.add(t);s.flush()
        claims=_live_claims(s,t)
        assert record_decisions(s,claims,[{'domain':'allowed.example','action':'allow'}]) == 0
        assert s.scalar(select(func.count()).select_from(FilterDecision)) == 0
        assert record_decisions(s,claims,[{'domain':'blocked.example','action':'block','reason':'https://private.example/path?token=secret','rule':'secret'}]) == 1
        row=s.scalar(select(FilterDecision))
        assert row.reason=='policy blocked domain' and row.rule=='blocked'


def test_record_decisions_refuses_revoked_or_unknown_credential(engine):
    """A validly signed token whose jti is revoked, expired or absent
    from the issuance registry can no longer write decisions."""
    import pytest as _pytest
    from app.filter_log_ops import FilterLogError
    with session_scope(engine) as s:
        t=Tenant(name='privacy2');s.add(t);s.flush()
        claims=_live_claims(s,t)
        dec=[{'domain':'blocked.example','action':'block'}]
        # unknown jti
        with _pytest.raises(FilterLogError):
            record_decisions(s,{'tenant_id':t.id,'scope':'proxy','jti':'nope'},dec)
        # revoked
        cred=s.scalar(select(IssuedCredential))
        cred.revoked_at=datetime.now(timezone.utc);s.flush()
        with _pytest.raises(FilterLogError):
            record_decisions(s,claims,dec)
        assert s.scalar(select(func.count()).select_from(FilterDecision)) == 0


def test_physical_purge_per_tenant_and_default_seven_days(engine):
    now=datetime.now(timezone.utc)
    with session_scope(engine) as s:
        a=Tenant(name='a');b=Tenant(name='b',blocked_log_retention_days=2)
        s.add_all([a,b]);s.flush()
        for t,action,days in [(a,'allow',0),(a,'block',8),(a,'block',6),(b,'block',3),(b,'block',1)]:
            s.add(FilterDecision(tenant_id=t.id,domain='synthetic.example',source='dns',action=action,received_at=now-timedelta(days=days)))
        s.flush()
        assert purge_expired(s,tenant_id=a.id,now=now)==2
        assert s.scalar(select(func.count()).select_from(FilterDecision))==3
        assert purge_expired(s,now=now)==1
        assert s.scalar(select(func.count()).select_from(FilterDecision))==2


from test_filter_logs import client, make_client, mint, mk_device, bearer, HDR


def test_retention_api_owner_bounds_isolation_no_cache_and_atomic_batch(client, engine):
    token=mint(client,mk_device(client))
    assert client.get('/api/privacy/retention').json()['blocked_days']==7
    for days in [0,31,True,'7']:
        assert client.put('/api/privacy/retention',json={'days':days},headers=HDR).status_code==422
    assert client.put('/api/privacy/retention',json={'days':1},headers=HDR).status_code==200
    r=client.post('/api/filter-logs',headers=bearer(token),json={'decisions':[
        {'domain':'blocked.example','action':'block'}, {'domain':'https://private.example/path','action':'block'}]})
    assert r.status_code==400
    assert client.get('/api/filter-logs').json()['decisions']==[]
    assert client.get('/api/filter-logs').headers['cache-control']=='no-store, private'
    with session_scope(engine) as s:
        t=s.scalar(select(Tenant).where(Tenant.name=='family-logs'))
        s.add(FilterDecision(tenant_id=t.id,domain='old.example',source='dns',action='block',received_at=datetime.now(timezone.utc)-timedelta(days=2)))
    assert client.get('/api/filter-logs').json()['decisions']==[]
    with session_scope(engine) as s:
        assert s.scalar(select(func.count()).select_from(FilterDecision))==0
