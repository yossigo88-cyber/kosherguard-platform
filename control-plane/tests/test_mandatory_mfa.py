"""Direct API tests: password-only privileged sessions cannot operate."""
import pyotp
import os,sys
sys.path.insert(0,os.path.dirname(__file__))
from test_publications import client, pub_root, HDR, PASSWORD

def login(client, email="g@example.com"):
    return client.post("/api/auth/login", json={"email":email,"password":PASSWORD}, headers=HDR)
from app.db import session_scope
from app.models import User
from sqlalchemy import select


def test_password_session_restricted_then_verified_login(client):
    login(client)
    assert client.get('/api/auth/me').status_code == 200
    for path in ['/api/policies', '/api/devices', '/api/audit-logs']:
        assert client.get(path).status_code == 403
    assert client.post('/api/policies', json={'name':'x','default_policy':'block'}, headers=HDR).status_code == 403
    secret = client.post('/api/auth/mfa/enroll-start', headers=HDR).json()['secret']
    assert client.post('/api/auth/mfa/enroll-confirm', json={'password':PASSWORD,'code':pyotp.TOTP(secret).now()}, headers=HDR).status_code == 200
    assert client.get('/api/policies').status_code == 403  # no silent session promotion
    assert client.post('/api/auth/login', json={'email':'g@example.com','password':PASSWORD}, headers=HDR).status_code == 401
    assert client.post('/api/auth/login', json={'email':'g@example.com','password':PASSWORD,'totp_code':pyotp.TOTP(secret).now()}, headers=HDR).status_code == 200
    assert client.get('/api/policies').status_code == 200


def test_viewer_direct_mutations_denied(client):
    login(client, 'v@example.com')
    for method,path,body in [
        ('post','/api/policies',{'name':'bad','default_policy':'allow'}),
        ('put','/api/policies/123',{'name':'bad','default_policy':'allow'}),
        ('put','/api/policies/123/schedules',{'schedules':[]}),
        ('post','/api/policies/123/select',{}),
        ('post','/api/devices',{'name':'bad'}),
        ('post','/api/devices/123/assignment',{'policy_id':123}),
    ]:
        assert client.request(method,path,json=body,headers=HDR).status_code == 403, path


def test_old_session_role_promotion_and_reset_revocation(client, engine):
    from mfa_support import mfa_login
    from fastapi.testclient import TestClient
    from app.models import Role, AuthSession, PendingMfaEnrollment
    assert mfa_login(client,json={'email':'g@example.com','password':PASSWORD},headers=HDR).status_code == 200
    viewer=TestClient(client.app)
    login(viewer,'v@example.com')
    with session_scope(engine) as s:
        u=s.scalar(select(User).where(User.email=='v@example.com'));uid=u.id
        u.role=Role.guardian
    assert viewer.get('/api/devices').status_code == 403
    # Verified owner can recover another account, not strip own MFA.
    # Recovery requires fresh TOTP + confirmation in addition to the
    # password.
    import pyotp as _pyotp
    owner_secret = client.app.state._fixture_mfa['g@example.com']
    fresh = {'password': PASSWORD,
             'totp_code': _pyotp.TOTP(owner_secret).now(),
             'confirm': 'mfa-reset'}
    assert client.post(f'/api/guardians/{uid}/mfa-reset',json={'password':PASSWORD},headers=HDR).status_code == 403
    assert client.post(f'/api/guardians/{uid}/mfa-reset',json=fresh,headers=HDR).status_code == 200
    assert viewer.get('/api/auth/me').status_code == 401
    with session_scope(engine) as s:
        owner=s.scalar(select(User).where(User.email=='g@example.com'));oid=owner.id
        assert not list(s.scalars(select(AuthSession).where(AuthSession.user_id==uid)))
    fresh['totp_code'] = _pyotp.TOTP(owner_secret).now()
    assert client.post(f'/api/guardians/{oid}/mfa-reset',json=fresh,headers=HDR).status_code == 400


def test_preexisting_password_session_not_granted_by_new_secret(client, engine):
    login(client)
    with session_scope(engine) as s:
        u=s.scalar(select(User).where(User.email=='g@example.com'))
        u.totp_secret=pyotp.random_base32()
    assert client.get('/api/policies').status_code == 403


def test_mfa_confirmation_attempt_limit_survives_new_pending_secret(client):
    login(client)
    client.post('/api/auth/mfa/enroll-start',headers=HDR)
    for _ in range(5):
        r=client.post('/api/auth/mfa/enroll-confirm',json={'password':PASSWORD,'code':'not-a-code'},headers=HDR)
        assert r.status_code==400
    client.post('/api/auth/mfa/enroll-start',headers=HDR)
    assert client.post('/api/auth/mfa/enroll-confirm',json={'password':PASSWORD,'code':'not-a-code'},headers=HDR).status_code==429
