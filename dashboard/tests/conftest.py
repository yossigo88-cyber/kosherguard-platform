"""Shared fixtures for the dashboard tests.

Every test runs against a REAL dashboard server bound to an ephemeral
localhost port with a throwaway SQLite database, exercising the same
HTTP path a browser uses. Startup needs no sleeps: make_server binds
and activates its listening socket inside the constructor, so the port
accepts connections as soon as the fixture returns.
"""

import http.client
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import auth  # noqa: E402
from server import make_server  # noqa: E402

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "test-password-9"


class Client:
    """Minimal HTTP client with cookie and CSRF-header handling."""

    def __init__(self, port):
        self.port = port
        self.cookie = None

    def request(self, method, path, body=None, csrf=True, with_cookie=True,
                raw_headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-KosherGuard-Request"] = "1"
        if with_cookie and self.cookie:
            headers["Cookie"] = self.cookie
        if raw_headers:
            headers.update(raw_headers)
        payload = json.dumps(body) if body is not None else ("" if method != "GET" else None)
        if method != "GET" and body is None:
            payload = "{}"
        conn.request(method, path, payload, headers)
        response = conn.getresponse()
        data = response.read()
        set_cookie = response.getheader("Set-Cookie")
        conn.close()
        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            parsed = {"_raw": data}
        return response.status, parsed, response.getheaders(), set_cookie

    def login(self, username=ADMIN_USERNAME, password=ADMIN_PASSWORD):
        status, body, _, set_cookie = self.request(
            "POST", "/api/login", {"username": username, "password": password}
        )
        if status == 200 and set_cookie:
            self.cookie = set_cookie.split(";", 1)[0]
        return status, body

    def get(self, path, **kw):
        return self.request("GET", path, **kw)[:2]

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body, **kw)[:2]

    def put(self, path, body=None, **kw):
        return self.request("PUT", path, body, **kw)[:2]

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)[:2]


@pytest.fixture
def server(tmp_path):
    srv = make_server("127.0.0.1", 0, tmp_path / "test.db", ADMIN_USERNAME, ADMIN_PASSWORD,
                     publish_dir=tmp_path / "published")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


@pytest.fixture
def client(server):
    c = Client(server.server_address[1])
    status, _ = c.login()
    assert status == 200
    return c


@pytest.fixture
def anon_client(server):
    return Client(server.server_address[1])


@pytest.fixture
def limited_server(tmp_path):
    """A server whose login limiter locks after 2 failures for 600s."""
    srv = make_server(
        "127.0.0.1", 0, tmp_path / "limited.db", ADMIN_USERNAME, ADMIN_PASSWORD,
        limiter=auth.LoginLimiter(max_failures=2, lockout_seconds=600),
    )
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)
