"""Proxy-level exception integration: the exception overlay and the
protected-baseline floor apply to actual proxy requests, not only to
the shared policy_bundle code the DNS edge also loads."""

import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "filtering-engine", "src")))
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "dns-edge")))

import category_db  # noqa: E402
import server  # noqa: E402  proxy-edge's server, before url-filter shadows it
from policy_bundle import PolicyBundle  # noqa: E402
from schedules import ScheduledPolicyEngine  # noqa: E402
from test_server import authed_request, status_of, device_auth  # noqa: E402

KEY = b"proxy-test-signing-key"
NOW = datetime.now(timezone.utc)

BASELINE = {"default_policy": "allow", "allowlist": [],
            "blocklist": ["bad.example"],
            "category_rules": {"allow": [], "block": []}}
ASSIGNED = {"default_policy": "allow", "allowlist": [],
            "blocklist": ["bad.example", "games.example"],
            "category_rules": {"allow": [], "block": []}}

EXCEPTION = {
    'kind': 'allow_domains',
    'domains': ['bad.example', 'games.example'],
    'starts_at': (NOW - timedelta(hours=1)).isoformat(),
    'expires_at': (NOW + timedelta(hours=1)).isoformat(),
    'exception_id': 3}


class Engines:
    pass


def make_bundle():
    engines = Engines()
    engines.default = ScheduledPolicyEngine(
        BASELINE, category_db.CategoryDB({}), now=lambda: NOW)
    engines.per_policy = {2: ScheduledPolicyEngine(
        ASSIGNED, category_db.CategoryDB({}), now=lambda: NOW)}
    return PolicyBundle(engines=engines,
                        devices={'dev-1': 2, 'dev-2': 2},
                        revision=5, tenant_id='tenant-1',
                        exceptions={'dev-1': (EXCEPTION,)}, now=NOW)


@pytest.fixture()
def proxy_with_exceptions():
    decisions = []
    srv = server.FilteringProxy(
        ("127.0.0.1", 0), None, read_timeout=5, connect_timeout=2,
        decision_log=decisions.append, token_key=KEY)
    srv.policy_bundle = make_bundle()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, decisions
    srv.shutdown()
    srv.server_close()


def token(device_id='dev-1'):
    return device_auth.issue_token(
        KEY, device_id, 'tenant-1', 'proxy', lifetime_seconds=60,
        policy_id=2)


def test_proxy_honors_exception_for_guardian_added_block(
        proxy_with_exceptions):
    srv, _ = proxy_with_exceptions
    out = authed_request(srv.server_address[1],
                         b"CONNECT games.example:443 HTTP/1.1\r\n\r\n",
                         token=token())
    # Allowed by the exception: the proxy tries the upstream connect
    # (502 here - nothing listens - but crucially not 403).
    assert b"403" not in status_of(out)


def test_proxy_baseline_floor_blocks_despite_exception(
        proxy_with_exceptions):
    srv, _ = proxy_with_exceptions
    out = authed_request(srv.server_address[1],
                         b"CONNECT bad.example:443 HTTP/1.1\r\n\r\n",
                         token=token())
    assert b"403" in status_of(out)
    assert b"protected baseline" in out


def test_proxy_device_without_exception_stays_blocked(
        proxy_with_exceptions):
    srv, _ = proxy_with_exceptions
    out = authed_request(srv.server_address[1],
                         b"CONNECT games.example:443 HTTP/1.1\r\n\r\n",
                         token=token(device_id='dev-2'))
    assert b"403" in status_of(out)
