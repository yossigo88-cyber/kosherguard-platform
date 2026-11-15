"""HTTP server for the KosherGuard admin dashboard.

A standard-library ThreadingHTTPServer serves the JSON API and the
static interface. Development binding is 127.0.0.1 only; the DNS engine
is never exposed by this server, and the dashboard itself is a
development application, not a deployed production service (see the
Stage 7 specification's deployment restrictions).

Request safety rules enforced here:
- Every /api/* endpoint except /api/login requires a valid session.
- Every state-changing request (POST/PUT/DELETE) requires the
  X-KosherGuard-Request header; combined with the SameSite=Strict
  session cookie this blocks cross-site request forgery.
- Request bodies are capped: Content-Length must be a plain
  non-negative decimal integer (checked before reading); malformed,
  negative, or oversized values are rejected and the connection is
  closed, so unread bytes cannot poison the next request on it.
- Every connection has a per-read inactivity timeout AND a total
  deadline for receiving one complete request, so a slow-trickle
  client that keeps sending single bytes cannot hold a handler slot
  forever.
- All errors are returned as JSON {"error": ...}; no stack traces or
  internals are sent to clients.
- Static files are served only from the static directory, with path
  traversal rejected.
- Responses carry X-Content-Type-Options, X-Frame-Options, and (for the
  interface) a restrictive Content-Security-Policy.

Run (development):
    KG_ADMIN_PASSWORD='choose-a-strong-password' \
        python3 src/server.py --host 127.0.0.1 --port 8080 \
        --db data/dashboard.db
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import io
import re
import socket
import sys
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import auth
import db as db_module
from store import Store, StoreError
from util import utcnow

MAX_BODY_BYTES = 1024 * 1024  # 1 MB, generous enough for domain imports
STATIC_DIR = Path(__file__).resolve().parents[1] / "static"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'self'; form-action 'self'"
)


def _env_flag(raw, name: str) -> bool:
    """Parse a boolean environment setting. Ambiguous values are a
    startup error, so a production security setting (for example
    KG_SECURE_COOKIES) can never silently fall back to the insecure
    default because of a typo."""
    if raw is None:
        return False
    value = raw.strip().lower()
    if value in ("1", "true", "yes"):
        return True
    if value in ("0", "false", "no"):
        return False
    raise SystemExit(f"{name} must be one of 1/0/true/false/yes/no, got {raw!r}")


def _env_int(raw, name: str, default: int, minimum: int = 1) -> int:
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}")
    if value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}, got {value}")
    return value


def _env_float(raw, name: str, default: float, minimum: float = 1.0) -> float:
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}")
    if value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}, got {value}")
    return value


def _env_proxy_list(raw, name: str) -> frozenset:
    """Parse a comma-separated list of trusted proxy IP addresses."""
    if not raw:
        return frozenset()
    proxies = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.ip_address(part)
        except ValueError:
            raise SystemExit(f"{name}: {part!r} is not a valid IP address")
        proxies.add(part)
    return frozenset(proxies)


class _DeadlineRawIO(io.RawIOBase):
    """Raw read side of the request socket with a TOTAL deadline.

    A per-read inactivity timeout alone cannot stop a slow-trickle
    client that sends one byte just before each timeout expires, and a
    buffered reader can hide many tiny reads inside a single read()
    call. Every recv therefore re-checks the request's total deadline
    and is armed with the smaller of the inactivity timeout and the
    time left until it; once the deadline passes, the read fails with
    socket.timeout. BaseHTTPRequestHandler.handle_one_request catches
    that exactly like an inactivity timeout: it closes the connection,
    which releases the handler thread and its connection slot.
    """

    def __init__(self, handler, sock):
        super().__init__()
        self._handler = handler
        self._sock = sock

    def readable(self):
        return True

    def readinto(self, b):
        remaining = self._handler._read_deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("total request deadline exceeded")
        self._sock.settimeout(
            min(self._handler.server.request_timeout, remaining))
        return self._sock.recv_into(b)

    def close(self):
        # The socket is owned and closed by the server itself
        # (shutdown_request); only stop wrapping it.
        self._sock = None
        super().close()


def _is_loopback_host(host: str) -> bool:
    """True only for a known loopback bind address. An unresolvable
    hostname fails safe: it is treated as a deployment bind."""
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip()).is_loopback
    except ValueError:
        return False


def _require_cookie_safety(host: str, secure_cookies: bool, trusted_proxies) -> None:
    """Refuse to start a deployment-shaped configuration with insecure
    session cookies. Localhost development may omit KG_SECURE_COOKIES;
    a configured trusted proxy or a non-loopback bind means the
    dashboard is being deployed, and then Secure cookies must be
    enabled explicitly so the setting can never be forgotten."""
    if secure_cookies:
        return
    reasons = []
    if trusted_proxies:
        reasons.append("trusted proxies are configured (KG_TRUSTED_PROXIES)")
    if not _is_loopback_host(host):
        reasons.append(f"the bind address {host!r} is not loopback")
    if reasons:
        raise SystemExit(
            "Refusing to start with insecure session cookies: "
            + " and ".join(reasons)
            + ". Set KG_SECURE_COOKIES=1 (HTTPS deployment) or bind "
            "127.0.0.1 with no trusted proxies for local development."
        )


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, db_path, admin_username, admin_password,
                 limiter=None, static_dir=STATIC_DIR, secure_cookies=False,
                 trusted_proxies=(), max_connections=32, request_timeout=30.0,
                 total_request_timeout=60.0, publish_dir=None):
        self.store = Store(db_path, publish_root=publish_dir)
        self.static_dir = Path(static_dir)
        self.limiter = limiter or auth.LoginLimiter()
        self.secure_cookies = bool(secure_cookies)
        self.trusted_proxies = frozenset(trusted_proxies)
        self.request_timeout = float(request_timeout)
        self.total_request_timeout = float(total_request_timeout)
        if self.total_request_timeout < self.request_timeout:
            raise ValueError(
                "total_request_timeout must be at least request_timeout")
        self._connection_slots = threading.BoundedSemaphore(max(1, int(max_connections)))
        conn = db_module.connect(db_path)
        try:
            db_module.init_db(conn)
            self._seed_admin(conn, admin_username, admin_password)
            auth.cleanup_expired_sessions(conn)
        finally:
            conn.close()
        super().__init__(address, DashboardHandler)

    # Bound concurrent request handling: when every slot is taken, the
    # extra connection is refused instead of spawning an unbounded
    # number of handler threads.
    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    @staticmethod
    def _seed_admin(conn, username: str, password: str | None) -> None:
        """Create the first administrator if the table is empty.

        The password comes from KG_ADMIN_PASSWORD (or the explicit
        argument used by tests); it is hashed immediately and never
        stored or logged in clear. Starting without a password when no
        administrator exists is refused: an open dashboard is worse than
        no dashboard.
        """
        if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] > 0:
            return
        if not password:
            raise SystemExit(
                "No administrator exists yet. Set KG_ADMIN_PASSWORD in the "
                "environment to seed the first admin account; refusing to "
                "start with an open dashboard."
            )
        if len(password) < auth.MIN_PASSWORD_LENGTH:
            raise SystemExit(
                f"KG_ADMIN_PASSWORD must be at least {auth.MIN_PASSWORD_LENGTH} characters."
            )
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, auth.hash_password(password), utcnow()),
        )
        conn.commit()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "KosherGuardDashboard/1.0"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        # Slow or incomplete clients (including idle keep-alive
        # connections) cannot hold a handler thread forever: each read
        # is bounded by the inactivity timeout, and the rfile wrapper
        # additionally bounds the TOTAL time one request may take to
        # arrive (headers plus body).
        self._read_deadline = time.monotonic() + self.server.total_request_timeout
        self.request.settimeout(self.server.request_timeout)
        # Replace the buffered reader with one whose raw layer enforces
        # the total deadline on every single recv (see _DeadlineRawIO);
        # nothing has been read yet, so the original buffer is empty.
        self.rfile.close()
        self.rfile = io.BufferedReader(
            _DeadlineRawIO(self, self.request), io.DEFAULT_BUFFER_SIZE)

    def handle_one_request(self):
        # Each request on a keep-alive connection gets its own total
        # receiving deadline; idle time between requests stays bounded
        # by the per-read inactivity timeout.
        self._read_deadline = time.monotonic() + self.server.total_request_timeout
        self.request.settimeout(self.server.request_timeout)
        super().handle_one_request()

    # -- plumbing ------------------------------------------------------

    def log_message(self, fmt, *args):  # keep logs free of request bodies
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str, extra_headers=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if content_type.startswith("application/json"):
            self.send_header("Cache-Control", "no-store")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj, extra_headers=None) -> None:
        self._send(
            status,
            json.dumps(obj).encode("utf-8"),
            "application/json",
            extra_headers,
        )

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _body(self) -> dict:
        """The already-read request body (mutations read it up front so a
        request rejected later never leaves unread bytes on the socket)."""
        return self._cached_body

    def _read_body(self) -> dict:
        header = self.headers.get("Content-Length")
        if header is None:
            # No declared length: if the client sent body bytes anyway,
            # they would be parsed as the next request on this
            # keep-alive connection, so close it.
            self.close_connection = True
            raise StoreError("missing Content-Length", 411)
        text = header.strip()
        # Only a plain non-negative decimal integer is accepted: no
        # sign, no inner whitespace, no Unicode digits (int() would
        # silently accept those), no trailing garbage. A negative or
        # malformed value is rejected BEFORE any body byte is read.
        if not re.fullmatch(r"[0-9]+", text):
            # The true body length is unknowable: close the connection
            # so unread bytes cannot poison the next request.
            self.close_connection = True
            raise StoreError("invalid Content-Length", 400)
        digits = text.lstrip("0") or "0"
        if len(digits) > len(str(MAX_BODY_BYTES)):
            # Far above the maximum (also keeps int() away from huge
            # digit strings); rejected without reading the body.
            self.close_connection = True
            raise StoreError("request body too large", 413)
        length = int(digits)
        if length > MAX_BODY_BYTES:
            # Reject without reading the oversized body; close the
            # connection so the unread bytes cannot poison the next request.
            self.close_connection = True
            raise StoreError("request body too large", 413)
        raw = self.rfile.read(length)
        # The body is fully received: the total deadline no longer
        # applies, so restore the plain inactivity timeout for the
        # response.
        self.request.settimeout(self.server.request_timeout)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise StoreError("request body must be valid JSON", 400)
        if not isinstance(data, dict):
            raise StoreError("request body must be a JSON object", 400)
        return data

    def _client_address(self) -> str:
        """The client address used for login limiting.

        X-Forwarded-For is honored only when the immediate socket peer
        is a configured trusted proxy (KG_TRUSTED_PROXIES); then the
        LAST entry - the one the trusted proxy appended - is used, and
        only if it parses as an IP address. An untrusted peer, a
        missing header, or a malformed entry all fall back to the
        socket peer, so a forged header can never steer or bypass the
        limiter.
        """
        peer = self.client_address[0]
        if peer in self.server.trusted_proxies:
            forwarded = self.headers.get("X-Forwarded-For")
            if forwarded:
                candidate = forwarded.rsplit(",", 1)[-1].strip()
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    pass
        return peer

    def _session_token(self) -> str | None:
        header = self.headers.get("Cookie")
        if not header:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(header)
        except cookies.CookieError:
            return None
        morsel = jar.get("kg_session")
        return morsel.value if morsel else None

    def _admin(self, conn):
        return auth.resolve_session(conn, self._session_token())

    # -- dispatch ------------------------------------------------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        # Headers are fully received at this point; restore the plain
        # inactivity timeout for producing and sending the response
        # (the total deadline bounds RECEIVING the request only).
        self.request.settimeout(self.server.request_timeout)
        path = self.path.split("?", 1)[0]
        try:
            if path.startswith("/api/"):
                self._dispatch_api(method, path)
            elif method == "GET":
                self._serve_static(path)
            else:
                self._error(404, "not found")
        except (socket.timeout, TimeoutError):
            # The per-read inactivity timeout or the total receiving
            # deadline fired while reading this request's BODY (header
            # timeouts never reach here: handle_one_request catches
            # them itself). The request is incomplete, so its unread
            # bytes must never be parsed as a subsequent request, and a
            # client timeout is not an internal server error. Close the
            # connection immediately, without a response - exactly like
            # the header-phase path in handle_one_request.
            self.close_connection = True
            self.log_message("request body timed out; connection closed")
            return
        except StoreError as exc:
            self._error(exc.status, str(exc))
        except auth.AuthError as exc:
            self._error(401, str(exc))
        except Exception:  # never leak internals
            self.log_message("unhandled error in %s %s", method, path)
            import traceback

            traceback.print_exc()
            self._error(500, "internal error")

    def _require_csrf_header(self) -> None:
        if self.headers.get("X-KosherGuard-Request") != "1":
            raise StoreError("missing X-KosherGuard-Request header", 403)

    def _dispatch_api(self, method: str, path: str) -> None:
        from urllib.parse import parse_qs, urlsplit

        query = parse_qs(urlsplit(self.path).query)

        def q(name):
            values = query.get(name)
            return values[0] if values else None

        self._cached_body = None
        if method in ("POST", "PUT", "DELETE"):
            # Read (and size-check) the body before any check that might
            # reject the request, so the connection stays well-formed.
            self._cached_body = self._read_body()
            self._require_csrf_header()

        # The health check runs before the shared connection opens so
        # it can REPORT a database failure instead of failing with one.
        if method == "GET" and path == "/api/health":
            self._handle_health()
            return

        conn = db_module.connect(self.server.store.db_path)
        try:
            # The only public endpoint.
            if method == "POST" and path == "/api/login":
                self._handle_login(conn)
                return

            admin = self._admin(conn)  # everything below requires a session
            store = self.server.store

            if method == "POST" and path == "/api/logout":
                token = self._session_token()
                auth.destroy_session(conn, token)
                store.audit(conn, admin["username"], "auth.logout", "signed out")
                conn.commit()
                self._json(200, {"ok": True}, {"Set-Cookie": self._clear_cookie()})
                return
            if method == "GET" and path == "/api/me":
                self._json(200, {"username": admin["username"]})
                return
            if method == "POST" and path == "/api/change-password":
                self._handle_change_password(conn, admin)
                return
            if method == "GET" and path == "/api/overview":
                self._json(200, store.overview_counts())
                return
            if method == "GET" and path == "/api/config":
                self._json(200, {
                    "environment": "development",
                    "devices_connected": False,
                    "mdm_operational": False,
                    "note": "Development application. No Apple MDM connection, "
                            "no enrolled devices, no remote policy push.",
                })
                return

            m = re.fullmatch(
                r"/api/policies(?:/(\d+)(?:/(enabled|test|versions|rollback|select)(?:/(\d+))?)?)?",
                path)
            if m and path.startswith("/api/policies"):
                self._handle_policies(method, m, q, store, admin, conn)
                return

            if path == "/api/config/status" and method == "GET":
                self._json(200, store.config_status())
                return
            if path == "/api/config/publish" and method == "POST":
                self._json(200, store.publish_config(admin["username"]))
                return
            if path == "/api/config/rollback" and method == "POST":
                data = self._body()
                revision = data.get("revision")
                if not isinstance(revision, int):
                    raise StoreError("revision must be an integer", 400)
                self._json(200, store.rollback_config(admin["username"], revision))
                return
            m_cfg = re.fullmatch(r"/api/config/revisions(?:/(\d+))?", path)
            if m_cfg and method == "GET":
                if m_cfg.group(1) is None:
                    limit = q("limit") or 100
                    self._json(200, {"revisions": store.list_config_revisions(limit)})
                else:
                    self._json(200, store.get_config_revision(int(m_cfg.group(1))))
                return

            m = re.fullmatch(r"/api/categories(?:/([a-z0-9-]+)(?:/(enabled))?)?", path)
            if m and path.startswith("/api/categories"):
                self._handle_categories(method, m, q, store, admin, conn)
                return

            if path.startswith("/api/domains"):
                self._handle_domains(method, path, q, store, admin, conn)
                return

            if method == "GET" and path == "/api/audit":
                limit = q("limit") or 200
                self._json(200, {"entries": store.list_audit(limit)})
                return

            self._error(404, "not found")
        finally:
            conn.close()

    # -- auth endpoints --------------------------------------------------

    def _session_cookie(self, token: str) -> str:
        cookie = (
            f"kg_session={token}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={auth.SESSION_LIFETIME_SECONDS}"
        )
        if self.server.secure_cookies:
            cookie += "; Secure"
        return cookie

    def _clear_cookie(self) -> str:
        cookie = "kg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        if self.server.secure_cookies:
            cookie += "; Secure"
        return cookie

    def _handle_health(self) -> None:
        """Public minimal health check. Reveals only that the process is
        responding and its database is usable: no usernames, paths,
        configuration, or internal errors."""
        try:
            conn = db_module.connect(self.server.store.db_path)
            try:
                conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone()
            finally:
                conn.close()
        except Exception:
            self.log_message("health check: database unavailable")
            self._json(503, {"status": "unavailable"})
            return
        self._json(200, {"status": "ok"})

    def _handle_login(self, conn) -> None:
        data = self._body()
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise StoreError("username and password must be strings", 400)
        key = (username, self._client_address())
        if self.server.limiter.is_locked(key):
            raise StoreError("too many failed attempts; try again later", 429)
        row = conn.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()
        if row is None or not auth.verify_password(password, row["password_hash"]):
            self.server.limiter.record_failure(key)
            self._audit_login_failure(conn, username)
            raise auth.AuthError("invalid username or password")
        self.server.limiter.record_success(key)
        token = auth.create_session(conn, row["id"])
        store = self.server.store
        store.audit(conn, username, "auth.login", "signed in")
        conn.commit()
        self._json(200, {"username": username}, {"Set-Cookie": self._session_cookie(token)})

    def _audit_login_failure(self, conn, username: str) -> None:
        """Record a failed login attempt. Never records the password or
        any secret, and an audit failure never changes the
        client-facing authentication result or leaks database details."""
        try:
            self.server.store.audit(
                conn, username[:64], "auth.login_failed",
                "failed login attempt (invalid username or password)",
            )
            conn.commit()
        except Exception:
            self.log_message("could not record failed-login audit entry")

    def _handle_change_password(self, conn, admin) -> None:
        data = self._body()
        current = data.get("current_password")
        new = data.get("new_password")
        if not isinstance(current, str) or not isinstance(new, str):
            raise StoreError("current_password and new_password must be strings", 400)
        row = conn.execute(
            "SELECT * FROM admins WHERE id = ?", (admin["id"],)
        ).fetchone()
        if not auth.verify_password(current, row["password_hash"]):
            raise auth.AuthError("current password is incorrect")
        if len(new) < auth.MIN_PASSWORD_LENGTH:
            raise StoreError(
                f"new password must be at least {auth.MIN_PASSWORD_LENGTH} characters", 400
            )
        with conn:
            conn.execute(
                "UPDATE admins SET password_hash = ? WHERE id = ?",
                (auth.hash_password(new), admin["id"]),
            )
            conn.execute("DELETE FROM sessions WHERE admin_id = ?", (admin["id"],))
            self.server.store.audit(conn, admin["username"], "auth.password_change", "password changed")
        self._json(200, {"ok": True}, {"Set-Cookie": self._clear_cookie()})

    # -- resource endpoints ----------------------------------------------

    def _handle_policies(self, method, m, q, store, admin, conn) -> None:
        policy_id, sub, sub_id = m.group(1), m.group(2), m.group(3)
        if policy_id is None:
            if method == "GET":
                enabled = q("enabled")
                enabled = None if enabled is None else enabled == "true"
                self._json(200, {"policies": store.list_policies(q("search"), enabled)})
                return
            if method == "POST":
                self._json(201, store.create_policy(admin["username"], self._body()))
                return
        elif sub is None:
            if method == "GET":
                self._json(200, store.get_policy(int(policy_id)))
                return
            if method == "PUT":
                self._json(200, store.update_policy(admin["username"], int(policy_id), self._body()))
                return
            if method == "DELETE":
                store.delete_policy(admin["username"], int(policy_id))
                self._json(200, {"ok": True})
                return
        elif sub == "enabled" and method == "POST":
            data = self._body()
            self._json(200, store.set_policy_enabled(admin["username"], int(policy_id), data.get("enabled")))
            return
        elif sub == "test" and method == "POST":
            data = self._body()
            self._json(200, store.test_domain(int(policy_id), data.get("domain")))
            return
        elif sub == "versions" and method == "GET":
            if sub_id is None:
                self._json(200, {"versions": store.list_policy_versions(int(policy_id))})
            else:
                self._json(200, store.get_policy_version(int(policy_id), int(sub_id)))
            return
        elif sub == "rollback" and method == "POST":
            data = self._body()
            version = data.get("version")
            if not isinstance(version, int):
                raise StoreError("version must be an integer", 400)
            self._json(200, store.rollback_policy(admin["username"], int(policy_id), version))
            return
        elif sub == "select" and method == "POST":
            self._json(200, store.select_policy_for_publication(
                admin["username"], int(policy_id)))
            return
        self._error(404, "not found")

    def _handle_categories(self, method, m, q, store, admin, conn) -> None:
        name, sub = m.group(1), m.group(2)
        if name is None:
            if method == "GET":
                self._json(200, {"categories": store.list_categories(q("search"))})
                return
            if method == "POST":
                self._json(201, store.create_category(admin["username"], self._body()))
                return
        elif sub is None and method == "PUT":
            self._json(200, store.update_category(admin["username"], name, self._body()))
            return
        elif sub == "enabled" and method == "POST":
            data = self._body()
            self._json(200, store.set_category_enabled(admin["username"], name, data.get("enabled")))
            return
        self._error(404, "not found")

    def _handle_domains(self, method, path, q, store, admin, conn) -> None:
        if path == "/api/domains":
            if method == "GET":
                self._json(200, {
                    "domains": store.list_domains(q("search"), q("category"), q("rule"))
                })
                return
            if method == "POST":
                self._json(201, store.create_domain(admin["username"], self._body()))
                return
        elif path == "/api/domains/import":
            if method == "POST":
                data = self._body()
                records = data.get("records")
                if records is None and isinstance(data.get("jsonl"), str):
                    records = []
                    for i, line in enumerate(data["jsonl"].splitlines(), start=1):
                        if not line.strip():
                            continue
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError as exc:
                            raise StoreError(f"import line {i}: invalid JSON: {exc}", 400)
                self._json(200, store.import_domains(admin["username"], records))
                return
        else:
            domain = path[len("/api/domains/"):]
            from engine_bridge import normalize_domain

            domain = normalize_domain(domain)
            if method == "GET":
                self._json(200, store.get_domain(domain))
                return
            if method == "PUT":
                self._json(200, store.update_domain(admin["username"], domain, self._body()))
                return
            if method == "DELETE":
                store.delete_domain(admin["username"], domain)
                self._json(200, {"ok": True})
                return
        self._error(404, "not found")

    # -- static files ------------------------------------------------------

    def _serve_static(self, path: str) -> None:
        if path in ("/", "/index.html"):
            path = "/index.html"
        # Reject traversal before touching the filesystem.
        candidate = (self.server.static_dir / path.lstrip("/")).resolve()
        if not str(candidate).startswith(str(self.server.static_dir.resolve()) + os.sep):
            self._error(404, "not found")
            return
        if not candidate.is_file():
            # The interface uses hash-based routes (#/policies etc.), so
            # there is no fallback: anything that is not a real file is 404.
            self._error(404, "not found")
            return
        content_type = CONTENT_TYPES.get(candidate.suffix, "application/octet-stream")
        self._send(200, candidate.read_bytes(), content_type)


def make_server(host: str, port: int, db_path, admin_username: str = "admin",
                admin_password: str | None = None, limiter=None,
                secure_cookies: bool = False, trusted_proxies=(),
                max_connections: int = 32, request_timeout: float = 30.0,
                total_request_timeout: float = 60.0,
                publish_dir=None) -> DashboardServer:
    return DashboardServer(
        (host, port), db_path, admin_username, admin_password, limiter=limiter,
        secure_cookies=secure_cookies, trusted_proxies=trusted_proxies,
        max_connections=max_connections, request_timeout=request_timeout,
        total_request_timeout=total_request_timeout, publish_dir=publish_dir,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="KosherGuard admin dashboard (development)")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default=str(Path(__file__).resolve().parents[1] / "data" / "dashboard.db"))
    parser.add_argument(
        "--publish-dir",
        default=os.environ.get(
            "KG_PUBLISH_DIR",
            str(Path(__file__).resolve().parents[2] / "data" / "published")),
        help="directory engine configuration generations are published into "
             "(default: <repository>/data/published or KG_PUBLISH_DIR)")
    args = parser.parse_args(argv)

    password = os.environ.get("KG_ADMIN_PASSWORD")
    username = os.environ.get("KG_ADMIN_USERNAME", "admin")
    # Security-relevant settings refuse ambiguous values instead of
    # silently falling back to an insecure default (Stage 9A).
    secure_cookies = _env_flag(os.environ.get("KG_SECURE_COOKIES"), "KG_SECURE_COOKIES")
    trusted_proxies = _env_proxy_list(
        os.environ.get("KG_TRUSTED_PROXIES"), "KG_TRUSTED_PROXIES")
    max_connections = _env_int(
        os.environ.get("KG_MAX_CONNECTIONS"), "KG_MAX_CONNECTIONS", 32)
    request_timeout = _env_float(
        os.environ.get("KG_REQUEST_TIMEOUT"), "KG_REQUEST_TIMEOUT", 30.0)
    total_request_timeout = _env_float(
        os.environ.get("KG_TOTAL_REQUEST_TIMEOUT"), "KG_TOTAL_REQUEST_TIMEOUT", 60.0)
    if total_request_timeout < request_timeout:
        raise SystemExit(
            "KG_TOTAL_REQUEST_TIMEOUT must be at least KG_REQUEST_TIMEOUT "
            "(the total deadline must cover each individual read)"
        )
    # A deployment-shaped configuration (trusted proxies or a
    # non-loopback bind) must not start with Secure cookies disabled
    # just because KG_SECURE_COOKIES was omitted.
    _require_cookie_safety(args.host, secure_cookies, trusted_proxies)
    server = make_server(
        args.host, args.port, args.db, username, password,
        secure_cookies=secure_cookies, trusted_proxies=trusted_proxies,
        max_connections=max_connections, request_timeout=request_timeout,
        total_request_timeout=total_request_timeout,
        publish_dir=args.publish_dir,
    )
    print(f"KosherGuard admin dashboard (development) on http://{args.host}:{args.port}")
    print("No Apple MDM connection exists; this dashboard manages local policy data only.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
