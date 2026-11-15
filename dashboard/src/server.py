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
- Request bodies are capped (Content-Length checked before reading).
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
import json
import os
import re
import sys
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


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, db_path, admin_username, admin_password,
                 limiter=None, static_dir=STATIC_DIR):
        self.store = Store(db_path)
        self.static_dir = Path(static_dir)
        self.limiter = limiter or auth.LoginLimiter()
        conn = db_module.connect(db_path)
        try:
            db_module.init_db(conn)
            self._seed_admin(conn, admin_username, admin_password)
        finally:
            conn.close()
        super().__init__(address, DashboardHandler)

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
        if len(password) < 8:
            raise SystemExit("KG_ADMIN_PASSWORD must be at least 8 characters.")
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, auth.hash_password(password), utcnow()),
        )
        conn.commit()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "KosherGuardDashboard/1.0"
    protocol_version = "HTTP/1.1"

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
        length = self.headers.get("Content-Length")
        if length is None:
            raise StoreError("missing Content-Length", 411)
        try:
            length = int(length)
        except ValueError:
            raise StoreError("invalid Content-Length", 400)
        if length > MAX_BODY_BYTES:
            # Reject without reading the oversized body; close the
            # connection so the unread bytes cannot poison the next request.
            self.close_connection = True
            raise StoreError("request body too large", 413)
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise StoreError("request body must be valid JSON", 400)
        if not isinstance(data, dict):
            raise StoreError("request body must be a JSON object", 400)
        return data

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
        path = self.path.split("?", 1)[0]
        try:
            if path.startswith("/api/"):
                self._dispatch_api(method, path)
            elif method == "GET":
                self._serve_static(path)
            else:
                self._error(404, "not found")
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

            m = re.fullmatch(r"/api/policies(?:/(\d+)(?:/(enabled|test))?)?", path)
            if m and path.startswith("/api/policies"):
                self._handle_policies(method, m, q, store, admin, conn)
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
        return (
            f"kg_session={token}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={auth.SESSION_LIFETIME_SECONDS}"
        )

    @staticmethod
    def _clear_cookie() -> str:
        return "kg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

    def _handle_login(self, conn) -> None:
        data = self._body()
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise StoreError("username and password must be strings", 400)
        key = (username, self.client_address[0])
        if self.server.limiter.is_locked(key):
            raise StoreError("too many failed attempts; try again later", 429)
        row = conn.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()
        if row is None or not auth.verify_password(password, row["password_hash"]):
            self.server.limiter.record_failure(key)
            raise auth.AuthError("invalid username or password")
        self.server.limiter.record_success(key)
        token = auth.create_session(conn, row["id"])
        store = self.server.store
        store.audit(conn, username, "auth.login", "signed in")
        conn.commit()
        self._json(200, {"username": username}, {"Set-Cookie": self._session_cookie(token)})

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
        if len(new) < 8:
            raise StoreError("new password must be at least 8 characters", 400)
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
        policy_id, sub = m.group(1), m.group(2)
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
                admin_password: str | None = None, limiter=None) -> DashboardServer:
    return DashboardServer(
        (host, port), db_path, admin_username, admin_password, limiter=limiter
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="KosherGuard admin dashboard (development)")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default=str(Path(__file__).resolve().parents[1] / "data" / "dashboard.db"))
    args = parser.parse_args(argv)

    password = os.environ.get("KG_ADMIN_PASSWORD")
    username = os.environ.get("KG_ADMIN_USERNAME", "admin")
    server = make_server(args.host, args.port, args.db, username, password)
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
