"""Filtering proxy tests against a live loopback server."""

import http.server
import os
import socket
import sys
import threading

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
