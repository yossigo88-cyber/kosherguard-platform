"""Authentication primitives for the control plane.

Password hashing and comparison are adapted from the reviewed dashboard
auth module (PBKDF2-HMAC-SHA256, 16-byte random salt, constant-time
compare). New hashes use 600k iterations, the current OWASP
recommendation for PBKDF2-HMAC-SHA256; existing lower-iteration hashes
keep verifying (the iteration count travels inside the stored string)
and are transparently upgraded after a successful authentication.
Stored iteration counts are BOUNDED before use so a malformed or
tampered hash cannot cause unreasonable CPU consumption. Sessions are
random 256-bit tokens; only the SHA-256 hash of a token is stored, so
a database read does not expose usable session tokens. TOTP secrets
are standard RFC 6238 via pyotp - no invented cryptography.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

import pyotp

# OWASP cheat sheet (2023+) recommends 600,000 iterations for
# PBKDF2-HMAC-SHA256. KG_PBKDF2_ITERATIONS exists so automated tests
# can run fast; it can never go below the floor.
PBKDF2_ITERATIONS = 600_000
ITERATIONS_FLOOR = 50_000
# Stored hashes outside this window are rejected outright: below it
# the hash is absurdly weak, above it a tampered row would be a
# denial-of-service amplifier on every login attempt.
MIN_STORED_ITERATIONS = 10_000
MAX_STORED_ITERATIONS = 2_000_000
MIN_PASSWORD_LENGTH = 12


def _configured_iterations() -> int:
    raw = os.environ.get("KG_PBKDF2_ITERATIONS", "").strip()
    if not raw:
        return PBKDF2_ITERATIONS
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError("KG_PBKDF2_ITERATIONS must be an integer")
    if value < ITERATIONS_FLOOR:
        raise RuntimeError(
            f"KG_PBKDF2_ITERATIONS must be >= {ITERATIONS_FLOOR}")
    return value


def hash_password(password: str, salt: bytes | None = None) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    iterations = _configured_iterations()
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"


def _parse_stored(stored: str):
    """(iterations, salt, digest_hex) or None; iteration count BOUNDED."""
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
    except (ValueError, AttributeError):
        return None
    if scheme != "pbkdf2":
        return None
    try:
        rounds = int(iterations)
    except ValueError:
        return None
    if not MIN_STORED_ITERATIONS <= rounds <= MAX_STORED_ITERATIONS:
        return None
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return None
    return rounds, salt, digest_hex


def verify_password(password: str, stored: str) -> bool:
    parsed = _parse_stored(stored)
    if parsed is None:
        return False
    rounds, salt, digest_hex = parsed
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(digest.hex(), digest_hex)


def password_needs_upgrade(stored: str) -> bool:
    """True when the stored hash is valid but below the current target."""
    parsed = _parse_stored(stored)
    if parsed is None:
        return False
    return parsed[0] < _configured_iterations()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))
