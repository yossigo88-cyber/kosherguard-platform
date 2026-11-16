"""Authentication primitives for the control plane.

Password hashing and comparison are adapted from the reviewed dashboard
auth module (PBKDF2-HMAC-SHA256, 200k iterations, 16-byte random salt,
constant-time compare). Sessions are random 256-bit tokens; only the
SHA-256 hash of a token is stored, so a database read does not expose
usable session tokens. TOTP secrets are standard RFC 6238 via pyotp -
no invented cryptography.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import pyotp

PBKDF2_ITERATIONS = 200_000
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str, salt: bytes | None = None) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, AttributeError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))
