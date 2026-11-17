"""Stage 9A hardening tests: secure cookies, proxy-aware login
limiting, password minimum, failed-login auditing, session cleanup,
health endpoint, and HTTP server safety bounds."""

import http.client
import json
import socket
import threading
import time

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
                 ("2020-01-01T00:00:00+00:00", auth.hash_session_token(token)))
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
                 ("2020-01-01T00:00:00+00:00", auth.hash_session_token(stale)))
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


# -- Content-Length strictness ------------------------------------------

def _raw_response(port, request: bytes, read_timeout: float = 10.0) -> bytes:
    """Send raw request bytes and read the full response until the
    server closes the connection (blocking recv with a failure bound,
    never a sleep)."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=read_timeout)
    sock.sendall(request)
    sock.settimeout(read_timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()
    return b"".join(chunks)


def test_content_length_negative_rejected_without_reading_body(custom_server):
    """A negative Content-Length is rejected BEFORE any body byte is
    read (a plain int() would accept it, and read() would then wait for
    an unbounded body). The prompt 400 - long before the 30-second
    inactivity timeout could fire - proves no body read happened."""
    _, client = custom_server()
    response = _raw_response(
        client.port,
        b"POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n")
    assert b" 400 " in response.split(b"\r\n", 1)[0]
    assert b"invalid Content-Length" in response


def test_content_length_malformed_rejected(custom_server):
    _, client = custom_server()
    for bad in (b"abc", b"1.5", b"+5", b"12x"):
        response = _raw_response(
            client.port,
            b"POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Length: "
            + bad + b"\r\n\r\n")
        assert b" 400 " in response.split(b"\r\n", 1)[0], bad
        assert b"invalid Content-Length" in response, bad


def test_content_length_oversized_rejected_and_connection_closed(custom_server):
    """The 1 MB cap still holds, the rejected connection is closed so
    unread bytes cannot be parsed as the next request (the helper only
    returns at EOF), and the server keeps serving afterwards."""
    _, client = custom_server()
    response = _raw_response(
        client.port,
        b"POST /api/login HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 1048577\r\n\r\n")
    assert b" 413 " in response.split(b"\r\n", 1)[0]
    assert b"request body too large" in response
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("GET", "/api/health")
    assert conn.getresponse().status == 200
    conn.close()


# -- slow-trickle total deadline ----------------------------------------

def _wait_slot_released(port, within=15):
    """The killed trickle connection releases its slot just after the
    client observes EOF, so poll for recovery (bounded) instead of
    sleeping a fixed guess."""
    deadline = time.monotonic() + within
    while True:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/api/health")
            status = conn.getresponse().status
            conn.close()
            if status == 200:
                return
        except (ConnectionError, OSError, http.client.HTTPException):
            pass
        if time.monotonic() > deadline:
            raise AssertionError("connection slot was not released")
        time.sleep(0.05)


def _trickle_loop(sock, started):
    """Keep an incomplete request alive: receive until the server closes
    the connection, sending one byte (well inside the inactivity
    window) whenever no close arrived. Returns (elapsed, received)."""
    received = b""
    while True:
        # Poll for the server closing the connection; the recv timeout
        # paces the trickle far inside the inactivity window. No fixed
        # sleeps: the close (EOF or RST) is the synchronization.
        sock.settimeout(0.1)
        try:
            data = sock.recv(4096)
        except socket.timeout:
            data = None
        except ConnectionResetError:
            # Killed with our trickled bytes still unread: the close
            # arrives as a RST rather than a clean FIN.
            data = b""
        if data == b"":
            return time.monotonic() - started, received
        if data:
            received += data
        if time.monotonic() - started > 30:
            raise AssertionError(
                "server did not terminate the slow-trickle request")
        try:
            sock.sendall(b"x")
        except (BrokenPipeError, ConnectionResetError):
            # The close raced our send; the connection is just as dead.
            return time.monotonic() - started, received


def test_slow_trickle_terminated_by_total_deadline(custom_server):
    """A client sending one byte well inside every 3-second inactivity
    window would hold its connection forever under a per-read timeout
    alone. The total request deadline (6s here) terminates it and the
    slot is released - in both the header and the body phase."""
    _, client = custom_server(max_connections=1, request_timeout=3.0,
                              total_request_timeout=6.0)
    port = client.port

    def trickle(first_bytes: bytes) -> float:
        overall = time.monotonic() + 20
        while True:
            sock = socket.create_connection(("127.0.0.1", port), timeout=10)
            sock.sendall(first_bytes)
            started = time.monotonic()
            try:
                closed_after, _ = _trickle_loop(sock, started)
            finally:
                sock.close()
            # An instant EOF means the single slot was still held by
            # the previous recovery check and this connection was
            # refused: retry, bounded. A real deadline kill takes
            # seconds.
            if closed_after > 0.5:
                return closed_after
            if time.monotonic() > overall:
                raise AssertionError("could not start a trickle connection")
            time.sleep(0.05)

    # Header phase: request line and one header, never completed.
    # The kill must come from the 6s total deadline, not the 3s
    # inactivity timeout: it outlasts an inactivity window but stays
    # far below the 30s guard.
    elapsed = trickle(b"POST /api/login HTTP/1.1\r\nHost: x\r\n")
    assert elapsed > 3.5, f"killed early by inactivity timeout? {elapsed:.2f}s"
    assert elapsed < 20, f"total deadline not enforced? {elapsed:.2f}s"
    _wait_slot_released(port)


def test_body_slow_trickle_closed_at_deadline_without_response(custom_server):
    """A request body that never completes is cut off at the total
    deadline: the server sends NO response (a client timeout is not an
    internal error), closes the connection (its unread bytes can never
    be parsed as a subsequent request), and releases the slot
    promptly. Runs under the same max_connections=1 setup so the slot
    check is decisive."""
    _, client = custom_server(max_connections=1, request_timeout=3.0,
                              total_request_timeout=6.0)
    port = client.port
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    # The declared body is far larger than the trickle can ever fill
    # (~10 bytes/second for at most 30 seconds), so the request truly
    # never completes and only the total deadline can end it.
    sock.sendall(
        b"POST /api/login HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 100000\r\nContent-Type: application/json\r\n\r\n{}")
    started = time.monotonic()
    try:
        closed_after, received = _trickle_loop(sock, started)
    finally:
        sock.close()
    # 1. Terminated at approximately the 6s total deadline: not before
    #    it, and within a few seconds after - not merely "under 20s".
    assert 5.0 < closed_after < 10.0, f"deadline kill at {closed_after:.2f}s"
    # 2. No response bytes ever arrived: the timeout was not reported
    #    as a 500, and the closed connection cannot serve another
    #    request.
    assert received == b"", f"unexpected response bytes: {received!r}"
    # 3. The single connection slot is released promptly.
    _wait_slot_released(port, within=5)


def test_total_deadline_must_cover_inactivity_timeout(tmp_path):
    with pytest.raises(ValueError):
        make_server("127.0.0.1", 0, tmp_path / "t.db", ADMIN_USERNAME,
                    ADMIN_PASSWORD, request_timeout=10.0,
                    total_request_timeout=5.0)


# -- cookie deployment guard ----------------------------------------------

def test_cookie_guard_localhost_omitted_ok():
    # Local development without KG_SECURE_COOKIES keeps working.
    server_module._require_cookie_safety("127.0.0.1", False, frozenset())
    server_module._require_cookie_safety("localhost", False, frozenset())
    server_module._require_cookie_safety("::1", False, frozenset())


def test_cookie_guard_deployment_with_secure_ok():
    # HTTPS/proxy deployment with Secure cookies explicitly enabled.
    server_module._require_cookie_safety("0.0.0.0", True, frozenset())
    server_module._require_cookie_safety(
        "127.0.0.1", True, frozenset({"127.0.0.1"}))


def test_cookie_guard_refuses_insecure_deployment():
    # Trusted proxies configured but Secure cookies omitted/disabled.
    with pytest.raises(SystemExit):
        server_module._require_cookie_safety(
            "127.0.0.1", False, frozenset({"127.0.0.1"}))
    # Explicit non-loopback binds without Secure cookies.
    for host in ("0.0.0.0", "192.168.1.20", "dashboard.example.internal"):
        with pytest.raises(SystemExit):
            server_module._require_cookie_safety(host, False, frozenset())
    # Both signals at once.
    with pytest.raises(SystemExit):
        server_module._require_cookie_safety(
            "0.0.0.0", False, frozenset({"10.0.0.2"}))
