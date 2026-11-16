"""Explicit real MFA enrollment helper for non-auth feature-test accounts.

Never installed in the application and never bypasses authentication. Auth and
MFA-specific tests use raw login to test restricted sessions themselves.
"""
import pyotp

def mfa_login(client, **kwargs):
    key = kwargs.get('json', {}).get('email')
    known = getattr(client.app.state, '_fixture_mfa', {})
    if key in known and not kwargs['json'].get('totp_code'):
        kwargs = dict(kwargs, json=dict(kwargs['json'], totp_code=pyotp.TOTP(known[key]).now()))
    result = client.post('/api/auth/login', **kwargs)
    if result.status_code != 200 or not result.json().get('mfa_required'):
        return result
    hdr = kwargs.get('headers', {})
    started = client.post('/api/auth/mfa/enroll-start', headers=hdr)
    assert started.status_code == 200, started.text
    secret = started.json()['secret']
    known[key] = secret
    client.app.state._fixture_mfa = known
    confirmed = client.post('/api/auth/mfa/enroll-confirm', headers=hdr,
        json={'password': kwargs['json']['password'], 'code': pyotp.TOTP(secret).now()})
    assert confirmed.status_code == 200, confirmed.text
    body = dict(kwargs['json'], totp_code=pyotp.TOTP(secret).now())
    return client.post('/api/auth/login', **dict(kwargs, json=body))
