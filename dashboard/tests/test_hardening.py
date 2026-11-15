"""Stage 9A hardening tests: secure cookies, proxy-aware login
limiting, password minimum, failed-login auditing, session cleanup,
health endpoint, and HTTP server safety bounds."""

import http.client
import json
import socket
import threading

import pytest

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, Client

import auth
import db as db_module
import server as server_module
from server import make_server


@pytest.fixture
def custom_server(tmp_path):
    """Start servers with custom hardening settings; all are shut down."""
    started = []

    def start(name="test.db", **kwargs):
        srv = make_server("127.0.0.1", 0, tmp_path / name,
                          ADMIN_USERNAME, ADMIN_PASSWORD, **kwargs)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        started.append((srv, thread))
        return srv, Client(srv.server_address[1])

    yield start
    for srv, thread in started:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


# -- secure cookies -----------------------------------------------------

def test_localhost_cookie_omits_secure_flag(custom_server):
    _, client = custom_server()
    status, _, _, set_cookie = client.request(
        "POST", "/api/login", {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert status == 200
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert "Secure" not in set_cookie


def test_production_cookie_sets_secure_flag(custom_server):
    _, client = custom_server(secure_cookies=True)
    status, _, _, set_cookie = client.request(
        "POST", "/api/login", {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert status == 200
    assert "Secure" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert f"Max-Age={auth.SESSION_LIFETIME_SECONDS}" in set_cookie
    # Clearing the cookie (logout) applies the same attributes.
    client.cookie = set_cookie.split(";", 1)[0]
    status, _, _, cleared = client.request("POST", "/api/logout", {})
    assert status == 200
    assert "Secure" in cleared
    assert "Max-Age=0" in cleared


def test_env_flag_rejects_ambiguous_values():
    assert server_module._env_flag(None, "X") is False
    assert server_module._env_flag("1", "X") is True
    assert server_module._env_flag("YES", "X") is True
    assert server_module._env_flag("0", "X") is False
    with pytest.raises(SystemExit):
        server_module._env_flag("maybe", "X")


def test_env_proxy_list_validation():
    assert server_module._env_proxy_list(None, "X") == frozenset()
    assert server_module._env_proxy_list(
        "127.0.0.1, 10.0.0.2", "X") == frozenset({"127.0.0.1", "10.0.0.2"})
    with pytest.raises(SystemExit):
        server_module._env_proxy_list("not-an-ip", "X")


# -- proxy-aware login limiting ------------------------------------------

def login_with(client, password, forwarded_for=None):
    headers = {"X-Forwarded-For": forwarded_for} if forwarded_for else None
    return client.request("POST", "/api/login",
                          {"username": ADMIN_USERNAME, "password": password},
                          raw_headers=headers)[0]


def test_limiter_direct_connection_ignores_forwarded_header(custom_server):
    """Without a trusted proxy, a spoofed X-Forwarded-For cannot move the
    limiter to another bucket: failures accumulate on the socket peer."""
    _, client = custom_server(
        limiter=auth.LoginLimiter(max_failures=2, lockout_seconds=60))
    assert login_with(client, "wrong-password", "1.2.3.4") == 401
    assert login_with(client, "wrong-password", "9.9.9.9") == 401
    # A third distinct spoofed address is still the same socket peer.
    assert login_with(client, "wrong-password", "8.8.8.8") == 429


def test_limiter_trusted_proxy_keys_per_client(custom_server):
    _, client = custom_server(
        trusted_proxies={"127.0.0.1"},
        limiter=auth.LoginLimiter(max_failures=2, lockout_seconds=60))
    assert login_with(client, "wrong-password", "1.2.3.4") == 401
    assert login_with(client, "wrong-password", "1.2.3.4") == 401
    assert login_with(client, "wrong-password", "1.2.3.4") == 429
    # A different client behind the same proxy is not locked out, and
    # the administrator can still sign in from elsewhere: no permanent
    # or shared lockout.
    assert login_with(client, "wrong-password", "5.6.7.8") == 401
    assert login_with(client, ADMIN_PASSWORD, "5.6.7.8") == 200


def test_limiter_malformed_forwarded_header_falls_back(custom_server):
    _, client = custom_server(
        trusted_proxies={"127.0.0.1"},
        limiter=auth.LoginLimiter(max_failures=2, lockout_seconds=60))
    assert login_with(client, "wrong-password", "not-an-ip") == 401
    assert login_with(client, "wrong-password", "garbage,,,") == 401
    # Malformed headers fall back to the socket peer: the third attempt
    # is limited even with a fresh malformed value.
    assert login_with(client, "wrong-password", "???") == 429


# -- password minimum ------------------------------------------------------

def test_seed_rejects_short_password(tmp_path):
    with pytest.raises(SystemExit):
        make_server("127.0.0.1", 0, tmp_path / "a.db", ADMIN_USERNAME, "elevenchar1")
    srv = make_server("127.0.0.1", 0, tmp_path / "b.db", ADMIN_USERNAME, "twelvechars1")
    srv.server_close()


def test_password_change_minimum_and_legacy_admin(tmp_path, custom_server):
    # An administrator seeded before the minimum was raised keeps
    # signing in; only NEW passwords must meet the new minimum.
    db_path = tmp_path / "legacy.db"
    conn = db_module.connect(db_path)
    db_module.init_db(conn)
    conn.execute(
        "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
        (ADMIN_USERNAME, auth.hash_password("ten-chars!"), "2026-01-01T00:00:00+00:00"))
    conn.commit()
    conn.close()
    srv, client = custom_server(name="legacy.db")
    assert srv is not None
    status, _ = client.login(ADMIN_USERNAME, "ten-chars!")
    assert status == 200
    status, body = client.post("/api/change-password", {
        "current_password": "ten-chars!", "new_password": "elevenchar1"})
    assert status == 400
    assert "12" in body["error"]
    status, _ = client.post("/api/change-password", {
        "current_password": "ten-chars!", "new_password": "twelvechars1"})
    assert status == 200
    status, _ = client.login(ADMIN_USERNAME, "twelvechars1")
    assert status == 200


# -- failed-login auditing -------------------------------------------------

def test_failed_login_audited_without_secrets(custom_server):
    _, client = custom_server()
    status, body = client.login(ADMIN_USERNAME, "wrong-password")
    assert status == 401
    assert body["error"] == "invalid username or password"
    status, _ = client.login("nosuchadmin", "wrong-password")
    assert status == 401
    status, _ = client.login()
    assert status == 200
    status, body = client.get("/api/audit")
    entries = body["entries"]
    failed = [e for e in entries if e["action"] == "auth.login_failed"]
    assert len(failed) == 2
    admins = {e["admin"] for e in failed}
    assert admins == {ADMIN_USERNAME, "nosuchadmin"}
    # Secrets never reach the audit log; success and logout auditing
    # are preserved.
    for entry in entries:
        assert "wrong-password" not in entry["admin"]
        assert "wrong-password" not in entry["detail"]
        assert ADMIN_PASSWORD not in entry["detail"]
    actions = [e["action"] for e in entries]
    assert "auth.login" in actions
    status, _ = client.post("/api/logout", {})
    assert status == 200
    # Logout destroys the session, so sign back in to read the log.
    status, _ = client.login()
    assert status == 200
    _, body = client.get("/api/audit")
    assert "auth.logout" in [e["action"] for e in body["entries"]]


# -- session cleanup ---------------------------------------------------------

def _expire_token(db_path, token):
    conn = db_module.connect(db_path)
    conn.execute("UPDATE sessions SET expires_at = ? WHERE token = ?",
                 ("2020-01-01T00:00:00+00:00", token))
    conn.commit()
    conn.close()


def test_expired_session_rejected_and_cleaned_up(custom_server):
    srv, client = custom_server()
    status, _ = client.login()
    assert status == 200
    token = client.cookie.split("=", 1)[1]
    _expire_token(srv.store.db_path, token)
    # An expired session is invalid even though cleanup has not run.
    status, _ = client.get("/api/me")
    assert status == 401

    # A second expired row plus a valid one: cleanup removes only the
    # expired record.
    other = Client(client.port)
    status, _ = other.login()
    assert status == 200
    conn = db_module.connect(srv.store.db_path)
    stale = auth.create_session(conn, 1)
    conn.execute("UPDATE sessions SET expires_at = ? WHERE token = ?",
                 ("2020-01-01T00:00:00+00:00", stale))
    conn.commit()
    removed = auth.cleanup_expired_sessions(conn)
    assert removed == 1
    remaining = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    conn.close()
    assert remaining == 1
    # The valid session survives cleanup and still works.
    status, body = other.get("/api/me")
    assert status == 200
    assert body["username"] == ADMIN_USERNAME


# -- health endpoint ---------------------------------------------------------

def test_health_endpoint_public_and_minimal(custom_server):
    _, client = custom_server()
    status, body = client.request("GET", "/api/health", csrf=False,
                                  with_cookie=False)[:2]
    assert status == 200
    assert body == {"status": "ok"}
    assert ADMIN_USERNAME not in json.dumps(body)
    assert ".db" not in json.dumps(body)


def test_health_endpoint_database_failure(custom_server):
    srv, client = custom_server()
    from pathlib import Path
    blocker = Path(srv.store.db_path).parent / "blocker"
    blocker.write_text("not a directory")
    srv.store.db_path = blocker / "dashboard.db"
    status, body = client.request("GET", "/api/health", csrf=False,
                                  with_cookie=False)[:2]
    assert status == 503
    assert body == {"status": "unavailable"}
    assert "blocker" not in json.dumps(body)


# -- HTTP server safety bounds ----------------------------------------------

def test_connection_bound_refuses_excess_and_header_timeout(custom_server):
    srv, client = custom_server(max_connections=1, request_timeout=2.0)
    port = client.port

    # Hold the single slot with an incomplete header block.
    slow = socket.create_connection(("127.0.0.1", port), timeout=10)
    slow.sendall(b"GET /api/health HTTP/1.1\r\nHost: x\r\n")  # no blank line
    try:
        # The next connection is refused immediately, not queued.
        second = socket.create_connection(("127.0.0.1", port), timeout=10)
        second.sendall(b"GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n")
        second.settimeout(10)
        try:
            refused = second.recv(4096) == b""
        except ConnectionResetError:
            refused = True  # closed with unread data -> RST: still refused
        assert refused
        second.close()

        # The slow client is dropped once the header timeout elapses;
        # blocking recv (with a failure bound) instead of a sleep.
        slow.settimeout(10)
        while True:
            chunk = slow.recv(4096)
            if not chunk:
                break
    finally:
        slow.close()

    # The server recovers and serves normal requests.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/api/health")
    response = conn.getresponse()
    assert response.status == 200
    conn.close()


def test_existing_api_behavior_preserved(client):
    status, body = client.get("/api/overview")
    assert status == 200
    assert "categories" in body
