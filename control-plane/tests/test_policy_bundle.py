"""Real authoring/publication -> assigned scheduled DoH decisions."""
import os
import sys
import json
from datetime import datetime
import pytest
from fastapi.testclient import TestClient
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../dns-edge')))
from test_publications import client, pub_root, login, make_default_policy, HDR, BASE
from app.db import session_scope
from app.models import Device, DeviceAssignment, Policy, PolicyVersion, User
from app.publication_ops import publish_selected, tenant_root
from app.publisher import Publisher
from policy_bundle import load_bundle


def test_assigned_schedule_bundle_and_real_doh_wire(client, engine, pub_root):
    login(client)
    default_id = make_default_policy(client)
    with session_scope(engine) as s:
        owner = s.query(User).filter_by(email='g@example.com').one()
        tenant = owner.tenant_id
        doc = dict(default_policy='allow', allowlist=[], blocklist=['bad.example'],
                   category_rules={'allow': [], 'block': []}, _schedules=[dict(
                       name='school', days=list(range(7)), start='09:00', end='17:00',
                       timezone='America/New_York', block_domains=['games.example'],
                       start_date='2026-11-17', end_date='2026-11-17')])
        p = Policy(tenant_id=tenant, name='school', engine_doc=json.dumps(doc))
        s.add(p); s.flush()
        s.add(PolicyVersion(policy_id=p.id, version=1, engine_doc=p.engine_doc))
        d = Device(tenant_id=tenant, name='scheduled'); s.add(d); s.flush()
        s.add(DeviceAssignment(tenant_id=tenant, device_id=d.id, policy_id=p.id))
        device_id = d.id
        s.flush()
        publish_selected(s, tenant, pub_root, owner.email)
    clock = [datetime.fromisoformat('2026-11-17T10:00:00-05:00')]
    root = tenant_root(pub_root, tenant)
    bundle = load_bundle(root, now=lambda: clock[0])
    assert bundle.for_device(device_id).decide('games.example').action == 'block'
    assert bundle.for_device('unassigned').decide('games.example').action == 'allow'
    clock[0] = datetime.fromisoformat('2026-11-18T10:00:00-05:00')
    assert bundle.for_device(device_id).decide('games.example').action == 'allow'
    clock[0] = datetime.fromisoformat('2026-11-17T10:00:00-05:00')
    # POST a real DNS wire message to an authenticated DoH route. Both
    # default and assigned policies block bad.example, no upstream needed.
    import dnslib
    from doh_server import create_app
    from doh_identity import verify_token
    import importlib.util
    fp = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../url-filter-server/app/device_auth.py'))
    spec = importlib.util.spec_from_file_location('bundle_auth', fp)
    da = importlib.util.module_from_spec(spec); spec.loader.exec_module(da)
    key = b'bundle-local-test-key-long-enough'
    token = da.issue_token(key, str(device_id), str(tenant), scope='doh')
    app = TestClient(create_app(pub_root, key, now=lambda: clock[0]))
    data = bytes(dnslib.DNSRecord.question('games.example').pack())
    headers = {'Authorization': 'Bearer '+token, 'Content-Type': 'application/dns-message'}
    r = app.post('/dns-query', content=data, headers=headers)
    assert r.status_code == 200, r.text
    assert str(dnslib.DNSRecord.parse(r.content).rr[0].rdata) == '0.0.0.0'
    assert app.post('/dns-query', content=data).status_code == 401
    # Another tenant has no publication, never falls back to this tenant.
    wrong = da.issue_token(key, str(device_id), str(tenant+1000), scope='doh')
    assert app.post('/dns-query', content=data, headers=dict(headers, Authorization='Bearer '+wrong)).status_code == 503
    # Corrupt incoming generation retains LKG already loaded by this app.
    path = os.path.join(root, 'current', 'assigned-policy-'+str(p.id)+'.json')
    with open(path, 'w') as f: f.write('{}')
    with pytest.raises(ValueError): load_bundle(root)
    assert app.post('/dns-query', content=data, headers=headers).status_code == 200


def test_dated_candidate_cannot_weaken_unbounded_schedule():
    from app.policy_ops import prove_against_doc, PolicyError
    raw = dict(default_policy='allow', allowlist=[], blocklist=[],
               category_rules={'allow': [], 'block': []})
    window = dict(name='bedtime', days=list(range(7)), start='21:00', end='06:00',
                  timezone='America/New_York', block_domains=['games.example'])
    baseline = dict(raw, _schedules=[window])
    candidate = dict(raw, _schedules=[dict(window, start_date='2026-11-17')])
    with pytest.raises(PolicyError): prove_against_doc(candidate, baseline, 'protected')
    prove_against_doc(baseline, candidate, 'dated')


def test_published_proxy_uses_assigned_schedule_and_refuses_other_tenant(client, engine, pub_root):
    login(client); make_default_policy(client)
    with session_scope(engine) as s:
        owner = s.query(User).filter_by(email='g@example.com').one()
        tenant = owner.tenant_id
        publish_selected(s, tenant, pub_root, owner.email)
    import importlib.util, socket, threading
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../proxy-edge/server.py'))
    spec = importlib.util.spec_from_file_location('bundle_proxy_server', path)
    server = importlib.util.module_from_spec(spec); spec.loader.exec_module(server)
    key = b'bundle-proxy-local-test-key-long'
    proxy = server.build_published_proxy(('127.0.0.1', 0), tenant_root(pub_root, tenant), key)
    t = threading.Thread(target=proxy.serve_forever); t.start()
    def request(token):
        with socket.create_connection(proxy.server_address, timeout=3) as sock:
            sock.sendall(('CONNECT bad.example:443 HTTP/1.1\r\nProxy-Authorization: Bearer '+token+'\r\n\r\n').encode())
            return sock.recv(2048).split(b'\r\n')[0]
    try:
        token = server.device_auth.issue_token(key, '1', str(tenant), scope='proxy', policy_id=1)
        assert b'403' in request(token)
        foreign = server.device_auth.issue_token(key, '1', str(tenant+1), scope='proxy', policy_id=1)
        assert b'403' in request(foreign)
    finally:
        proxy.shutdown(); proxy.server_close(); t.join()


def test_invalid_assigned_generation_reload_keeps_default_schedule(client, engine, pub_root):
    login(client); make_default_policy(client)
    with session_scope(engine) as s:
        owner = s.query(User).filter_by(email='g@example.com').one()
        tenant = owner.tenant_id
        publish_selected(s, tenant, pub_root, owner.email)
    from runner import DNSEdgeRunner
    root = tenant_root(pub_root, tenant)
    r = DNSEdgeRunner(root)
    old = r.bundle
    from app.publisher import canonical_json
    # A valid replacement is published, then corrupted on disk before
    # the edge sees it. Hash verification must prevent activation.
    valid = dict(default_policy='allow', allowlist=[], blocklist=['bad.example'],
                 category_rules={'allow': [], 'block': []})
    with Publisher(root).locked():
        Publisher(root).publish(2, canonical_json(valid),
            canonical_json({'domains': {}}), {'tenant_id': tenant},
            extra_documents={'device-map.json': canonical_json({
                'default_policy_id': 1, 'devices': {'1': {'policy_id': 2,
                    'policy': 'assigned-policy-2.json'}}}),
                'assigned-policy-2.json': canonical_json(valid)})
    with open(os.path.join(root, 'current', 'assigned-policy-2.json'), 'w') as f:
        f.write('{}')
    assert not r.check_for_update()
    assert r.bundle is old and r._revision == 1
    assert old.for_device('1').decide('bad.example').action == 'block'


def test_supplemental_path_traversal_refused(tmp_path):
    from app.publisher import canonical_json, PublicationError
    p = Publisher(str(tmp_path))
    with p.locked(), pytest.raises(PublicationError):
        p.publish(1, canonical_json(dict(default_policy='allow',
            allowlist=[], blocklist=[], category_rules={'allow': [], 'block': []})),
            canonical_json({'domains': {}}), {},
            extra_documents={'../other.json': b'{}'})
    assert not (tmp_path.parent / 'other.json').exists()
