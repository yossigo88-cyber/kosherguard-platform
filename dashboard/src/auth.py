"""Authentication for the KosherGuard admin dashboard.

Passwords are hashed with PBKDF2-HMAC-SHA256 (200,000 iterations, random
16-byte salt per password) from the Python standard library; hashes are
compared with secrets.compare_digest. No password is ever stored in
source code: the first administrator is seeded from the KG_ADMIN_PASSWORD
environment variable at startup (see server.py), and the variable is
never written to the database or logged.

Sessions are random 256-bit tokens (secrets.token_urlsafe) stored
as SHA-256 digests in the sessions table with an expiry. Existing
plaintext sessions are invalidated on upgrade; administrators sign in again. The browser receives
the token in an HttpOnly, SameSite=Strict cookie, so JavaScript cannot
read it and cross-site requests do not carry it. State-changing API
requests additionally require the X-KosherGuard-Request header (see
server.py), which a cross-site form cannot set.

A small in-memory limiter slows password guessing: repeated failed
logins for the same username from the same address lock further
attempts for a short window. The limiter is injectable so tests can
use their own thresholds.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time

from util import utcnow

PBKDF2_ITERATIONS = 200_000
SESSION_LIFETIME_SECONDS = 12 * 60 * 60  # 12 hours
MIN_PASSWORD_LENGTH = 12
MIN_STORED_ITERATIONS = 10_000
MAX_STORED_ITERATIONS = 2_000_000


class AuthError(Exception):
    """Raised when authentication or session validation fails."""


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash a password; returns 'pbkdf2$iterations$salt_hex$hash_hex'."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored hash."""
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        rounds = int(iterations)
        if not MIN_STORED_ITERATIONS <= rounds <= MAX_STORED_ITERATIONS:
            return False
        salt = bytes.fromhex(salt_hex)
        if len(salt) != 16 or len(digest_hex) != 64:
            return False
        bytes.fromhex(digest_hex)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            rounds,
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, AttributeError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """A database read must not expose a usable bearer credential.

    The prefix separates new hashes from old plaintext rows. Do not add a
    fallback to plaintext: old sessions are intentionally invalidated.
    """
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(conn: sqlite3.Connection, admin_id: int) -> str:
    """Create a session row and return its token."""
    conn.execute("DELETE FROM sessions WHERE token NOT LIKE 'sha256:%'")
    token = new_token()
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (token, admin_id, created_at, expires_at)"
        " VALUES (?, ?, ?, ?)",
        (
            hash_session_token(token),
            admin_id,
            time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now)),
            time.strftime(
                "%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now + SESSION_LIFETIME_SECONDS)
            ),
        ),
    )
    conn.commit()
    return token


def resolve_session(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row:
    """Return the admin row for a session token, or raise AuthError."""
    if not token:
        raise AuthError("not signed in")
    row = conn.execute(
        "SELECT a.id, a.username, s.expires_at FROM sessions s"
        " JOIN admins a ON a.id = s.admin_id WHERE s.token = ?",
        (hash_session_token(token),),
    ).fetchone()
    if row is None:
        raise AuthError("invalid session")
    if row["expires_at"] <= utcnow():
        conn.execute("DELETE FROM sessions WHERE token = ?", (hash_session_token(token),))
        conn.commit()
        raise AuthError("session expired")
    return row


def destroy_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM sessions WHERE token = ?", (hash_session_token(token),))
        conn.commit()


def cleanup_expired_sessions(conn: sqlite3.Connection) -> int:
    """Delete expired session rows; returns how many were removed.

    Expired sessions are invalid whether or not this cleanup has run:
    resolve_session() rejects them on use. Cleanup only reclaims
    storage. It runs at server startup (a documented safe point), so
    there is deliberately no background thread to shut down.
    """
    cur = conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (utcnow(),))
    conn.commit()
    return cur.rowcount


class LoginLimiter:
    """In-memory failed-login limiter.

    After max_failures failures for the same (username, address) pair,
    attempts are refused until lockout_seconds have passed since the
    first failure in the current streak. A successful login clears the
    streak.
    """

    def __init__(self, max_failures: int = 5, lockout_seconds: float = 60.0):
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._failures: dict = {}

    def is_locked(self, key) -> bool:
        entry = self._failures.get(key)
        if not entry:
            return False
        count, first_at = entry
        if time.monotonic() - first_at >= self.lockout_seconds:
            del self._failures[key]
            return False
        return count >= self.max_failures

    def record_failure(self, key) -> None:
        count, first_at = self._failures.get(key, (0, time.monotonic()))
        self._failures[key] = (count + 1, first_at)

    def record_success(self, key) -> None:
        self._failures.pop(key, None)
