"""Filtering proxy tests against a live loopback server."""

import http.server
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "filtering-engine", "src")))

import category_db  # noqa: E402
import policy_engine  # noqa: E402
import engine_set  # noqa: E402
import server  # noqa: E402

POLICY = {"default_policy": "allow", "allowlist": [], "blocklist": ["bad.example"],
          "category_rules": {"allow": [], "block": ["gambling"]}}
CATS = {"bet365.com": ["gambling"]}


def make_engine_set():
    eng = policy_engine.PolicyEngine(POLICY, category_db.CategoryDB(CATS))
    return engine_set.EngineSet(eng)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def proxy():
    decisions = []
    srv = server.FilteringProxy(("127.0.0.1", 0), make_engine_set(),
                                read_timeout=5, decision_log=decisions.append)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, decisions
    srv.shutdown()
    srv.server_close()


def http_request(port, raw):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(raw)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return data


def test_blocked_http_gets_403_block_page(proxy):
    srv, decisions = proxy
    port = srv.server_address[1]
    out = http_request(port, b"GET http://bad.example/ HTTP/1.1\r\nHost: bad.example\r\n\r\n")
    assert b"403" in out.split(b"\r\n", 1)[0]
    assert b"Blocked by KosherGuard" in out
    assert decisions and decisions[-1]["action"] == "block"


def test_category_blocked_http_gets_403(proxy):
    srv, decisions = proxy
    port = srv.server_address[1]
    out = http_request(port, b"GET http://bet365.com/ HTTP/1.1\r\nHost: bet365.com\r\n\r\n")
    assert b"403" in out.split(b"\r\n", 1)[0]
    assert decisions[-1]["rule"] == "category_block"


def test_blocked_connect_refused(proxy):
    srv, decisions = proxy
    port = srv.server_address[1]
    out = http_request(port, b"CONNECT bad.example:443 HTTP/1.1\r\n\r\n")
    assert b"403" in out.split(b"\r\n", 1)[0]


def test_malformed_request_400(proxy):
    srv, _ = proxy
    port = srv.server_address[1]
    out = http_request(port, b"GARBAGE\r\n\r\n")
    assert b"400" in out.split(b"\r\n", 1)[0]


def test_allowed_http_is_relayed(proxy):
    """An allowed request reaches a real local upstream and returns its body."""
    srv, decisions = proxy
    proxy_port = srv.server_address[1]

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"upstream-body-ok"
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    up_port = free_port()
    upstream = http.server.HTTPServer(("127.0.0.1", up_port), H)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    try:
        req = (f"GET http://127.0.0.1:{up_port}/page HTTP/1.1\r\n"
               f"Host: 127.0.0.1:{up_port}\r\n\r\n").encode()
        out = http_request(proxy_port, req)
        assert b"200" in out.split(b"\r\n", 1)[0]
        assert b"upstream-body-ok" in out
        assert decisions[-1]["action"] == "allow"
    finally:
        upstream.shutdown()
        upstream.server_close()


# ---------------------------------------------------------------------------
# 8B: authenticated per-device proxy access (policy-bound device tokens)
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "url-filter-server", "app")))
import device_auth  # noqa: E402

KEY = b"proxy-test-signing-key"
OTHER_KEY = b"not-the-server-key"

PERMISSIVE = {"default_policy": "allow", "allowlist": [], "blocklist": [],
              "category_rules": {"allow": [], "block": []}}
STRICT = {"default_policy": "allow", "allowlist": [],
          "blocklist": ["bad.example"],
          "category_rules": {"allow": [], "block": ["gambling"]}}


def make_authed_engine_set():
    default_eng = policy_engine.PolicyEngine(
        PERMISSIVE, category_db.CategoryDB({}))
    strict_eng = policy_engine.PolicyEngine(
        STRICT, category_db.CategoryDB(CATS))
    permissive_eng = policy_engine.PolicyEngine(
        PERMISSIVE, category_db.CategoryDB({}))
    return engine_set.EngineSet(
        default_eng, per_policy={1: permissive_eng, 2: strict_eng},
        default_policy_id=1)


def make_token(policy_id=2, scope="proxy", key=KEY, expired=False,
               device_id="dev-1"):
    now = time.time() - 120 if expired else None
    lifetime = 60
    return device_auth.issue_token(
        key, device_id, "tenant-1", scope, lifetime_seconds=lifetime,
        now=now, policy_id=policy_id)


@pytest.fixture()
def authed_proxy():
    decisions = []
    srv = server.FilteringProxy(
        ("127.0.0.1", 0), make_authed_engine_set(),
        read_timeout=5, connect_timeout=2,
        decision_log=decisions.append, token_key=KEY)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, decisions
    srv.shutdown()
    srv.server_close()


def authed_request(port, raw_head, token=None):
    if token is not None:
        raw_head = raw_head.replace(
            b"\r\n\r\n",
            b"\r\nproxy-authorization: Bearer " + token.encode() + b"\r\n\r\n")
    return http_request(port, raw_head)


def status_of(out):
    return out.split(b"\r\n", 1)[0]


def test_no_credentials_gets_407_with_challenge(authed_proxy):
    srv, decisions = authed_proxy
    out = http_request(srv.server_address[1],
                       b"GET http://example.com/ HTTP/1.1\r\n\r\n")
    assert b"407" in status_of(out)
    assert b"proxy-authenticate:" in out.lower()
    assert not decisions  # nothing filtered or relayed


def test_malformed_token_gets_407(authed_proxy):
    srv, _ = authed_proxy
    out = authed_request(srv.server_address[1],
                         b"GET http://example.com/ HTTP/1.1\r\n\r\n",
                         token="not-a-token")
    assert b"407" in status_of(out)


def test_wrong_scheme_gets_407(authed_proxy):
    srv, _ = authed_proxy
    port = srv.server_address[1]
    tok = make_token()
    req = (b"GET http://example.com/ HTTP/1.1\r\nproxy-authorization: Basic "
           + tok.encode() + b"\r\n\r\n")
    assert b"407" in status_of(http_request(port, req))


def test_wrong_scope_gets_407(authed_proxy):
    srv, _ = authed_proxy
    tok = make_token(scope="dataset")
    out = authed_request(srv.server_address[1],
                         b"GET http://example.com/ HTTP/1.1\r\n\r\n", token=tok)
    assert b"407" in status_of(out)


def test_expired_token_gets_407(authed_proxy):
    srv, _ = authed_proxy
    tok = make_token(expired=True)
    out = authed_request(srv.server_address[1],
                         b"GET http://example.com/ HTTP/1.1\r\n\r\n", token=tok)
    assert b"407" in status_of(out)


def test_wrong_key_gets_407(authed_proxy):
    srv, _ = authed_proxy
    tok = make_token(key=OTHER_KEY)
    out = authed_request(srv.server_address[1],
                         b"GET http://example.com/ HTTP/1.1\r\n\r\n", token=tok)
    assert b"407" in status_of(out)


def test_unbound_token_gets_403(authed_proxy):
    srv, _ = authed_proxy
    tok = make_token(policy_id=None)
    out = authed_request(srv.server_address[1],
                         b"GET http://example.com/ HTTP/1.1\r\n\r\n", token=tok)
    assert b"403" in status_of(out)
    assert b"not bound" in out


def test_unknown_policy_binding_gets_403(authed_proxy):
    srv, _ = authed_proxy
    tok = make_token(policy_id=99)
    out = authed_request(srv.server_address[1],
                         b"GET http://example.com/ HTTP/1.1\r\n\r\n", token=tok)
    assert b"403" in status_of(out)


def test_revoked_token_gets_407():
    tok = make_token()
    payload = device_auth.verify_token(KEY, tok, "proxy")
    decisions = []
    srv = server.FilteringProxy(
        ("127.0.0.1", 0), make_authed_engine_set(),
        read_timeout=5, connect_timeout=2,
        decision_log=decisions.append, token_key=KEY,
        revoked_jtis={payload["jti"]})
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        out = authed_request(srv.server_address[1],
                             b"GET http://example.com/ HTTP/1.1\r\n\r\n",
                             token=tok)
        assert b"407" in status_of(out)
    finally:
        srv.shutdown()
        srv.server_close()


def test_strict_policy_blocks_via_token(authed_proxy):
    """The token's policy binding picks the engine, not the client address."""
    srv, decisions = authed_proxy
    out = authed_request(srv.server_address[1],
                         b"GET http://bad.example/ HTTP/1.1\r\n\r\n",
                         token=make_token(policy_id=2))
    assert b"403" in status_of(out)
    assert b"Blocked by KosherGuard" in out
    assert decisions[-1]["action"] == "block"
    assert decisions[-1]["device"] == "dev-1"


def test_permissive_policy_allows_same_host(authed_proxy):
    """Same host, different policy binding: CONNECT allowed -> upstream 502,
    proving the strict policy did not apply."""
    srv, decisions = authed_proxy
    out = authed_request(srv.server_address[1],
                         b"CONNECT bad.example:443 HTTP/1.1\r\n\r\n",
                         token=make_token(policy_id=1))
    assert b"502" in status_of(out)
    assert decisions[-1]["action"] == "allow"


def test_strict_policy_blocks_connect(authed_proxy):
    srv, decisions = authed_proxy
    out = authed_request(srv.server_address[1],
                         b"CONNECT bad.example:443 HTTP/1.1\r\n\r\n",
                         token=make_token(policy_id=2))
    assert b"403" in status_of(out)
    assert decisions[-1]["action"] == "block"


def test_token_never_in_decision_log(authed_proxy):
    srv, decisions = authed_proxy
    tok = make_token(policy_id=2)
    authed_request(srv.server_address[1],
                   b"GET http://bad.example/ HTTP/1.1\r\n\r\n", token=tok)
    assert decisions
    for entry in decisions:
        assert tok not in repr(entry)


def test_credentials_stripped_from_relayed_request(authed_proxy):
    captured = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            captured["headers"] = dict(self.headers)
            body = b"ok"
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    up_port = free_port()
    upstream = http.server.HTTPServer(("127.0.0.1", up_port), H)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    srv, _ = authed_proxy
    try:
        req = (f"GET http://127.0.0.1:{up_port}/page HTTP/1.1\r\n"
               f"Host: 127.0.0.1:{up_port}\r\n"
               "proxy-connection: keep-alive\r\n\r\n").encode()
        out = authed_request(srv.server_address[1], req,
                             token=make_token(policy_id=1))
        assert b"200" in status_of(out)
        lowered = {k.lower() for k in captured["headers"]}
        assert "proxy-authorization" not in lowered
        assert "proxy-connection" not in lowered
    finally:
        upstream.shutdown()
        upstream.server_close()


class _FeedHandler(http.server.BaseHTTPRequestHandler):
    body = b'{"revoked_jtis": []}'

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *a):
        pass


def test_revocation_feed_runtime_refresh():
    """Runtime distribution: a FilteringProxy built on the feed's
    shared set refuses a token after the background loop refreshes,
    with no restart or rewiring."""
    import json as _json
    sys.path.insert(0, os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..",
        "url-filter-server", "app")))
    import revocations  # noqa: E402
    feed_srv = http.server.HTTPServer(("127.0.0.1", 0), _FeedHandler)
    threading.Thread(target=feed_srv.serve_forever, daemon=True).start()
    tok = make_token()
    feed = revocations.RevocationFeed(
        f"http://127.0.0.1:{feed_srv.server_address[1]}",
        token_provider=lambda: tok)
    stop = feed.start_refresh_loop(interval=0.1)
    srv = server.FilteringProxy(
        ("127.0.0.1", 0), make_authed_engine_set(),
        read_timeout=5, connect_timeout=2,
        decision_log=lambda r: None, token_key=KEY,
        revoked_jtis=feed.shared_set)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    req = b"GET http://example.com/ HTTP/1.1\r\n\r\n"
    try:
        out = authed_request(srv.server_address[1], req, token=tok)
        assert b"407" not in status_of(out)
        jti = device_auth.verify_token(KEY, tok, "proxy")["jti"]
        _FeedHandler.body = _json.dumps({"revoked_jtis": [jti]}).encode()
        end = time.time() + 5
        ok = False
        while time.time() < end:
            out = authed_request(srv.server_address[1], req, token=tok)
            if b"407" in status_of(out):
                ok = True
                break
            time.sleep(0.05)
        assert ok
    finally:
        stop.set()
        srv.shutdown()
        srv.server_close()
        feed_srv.shutdown()
        feed_srv.server_close()
