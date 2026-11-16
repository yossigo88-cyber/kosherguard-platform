"""Per-device authenticated identity for dataset distribution.

User approval (WhatsApp, 2026-11-16 02:25 EST): "Build authenticated
per-device DNS as the intended identity mechanism. Do not put
long-lived bearer credentials in DoH URLs or query strings. Evaluate
client certificates or appropriately protected scoped credentials ...
and redact credentials from logs." This module applies that approved
per-device identity requirement to dataset/prefilter distribution;
the DNS (DoH) identity binding itself lives in dns-edge.

Mechanism: short-lived HMAC-signed tokens, transported in the
Authorization header (never the URL). A token carries device_id,
tenant_id, scope, and expiry; the server verifies the signature with
the shared issuance key (KG_DEVICE_TOKEN_KEY) and checks expiry and
scope. Tokens are rotatable by re-issuance; revocation is by short
expiry (the key can also be rotated, invalidating all outstanding
tokens). Nothing here logs the token value.

Issuance lives in the control plane (guardian-authenticated); this
module is shared verification logic used by the dataset service.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid


class TokenError(Exception):
    """Bad signature, malformed, expired, or wrong scope."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_token(key: bytes, device_id: str, tenant_id: str,
                scope: str, lifetime_seconds: int = 3600,
                now: float | None = None,
                policy_id: str | None = None) -> str:
    if not key:
        raise ValueError("empty signing key")
    if lifetime_seconds <= 0 or lifetime_seconds > 86400:
        raise ValueError("lifetime must be within (0, 86400] seconds")
    now = time.time() if now is None else now
    payload = {
        "jti": uuid.uuid4().hex,
        "device_id": device_id,
        "tenant_id": tenant_id,
        "scope": scope,
        "iat": int(now),
        "exp": int(now + lifetime_seconds),
    }
    if policy_id is not None:
        payload["policy_id"] = policy_id
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(key, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_token(key: bytes, token: str, required_scope: str,
                 now: float | None = None,
                 revoked_jtis: set[str] | None = None,
                 required_policy_id: str | None = None) -> dict:
    """Return the payload or raise TokenError. Never logs the token.

    revoked_jtis: revocation store of token ids (jti). Revocation is
    immediate for listed tokens; unlisted tokens still expire on their
    short lifetime. required_policy_id: when set, the token must be
    bound to exactly that policy (authorization, not just
    authentication)."""
    if not key:
        raise TokenError("verification unavailable")
    try:
        body, sig = token.split(".", 1)
        payload = json.loads(_b64d(body))
    except Exception:
        raise TokenError("malformed token")
    expected = hmac.new(key, body.encode(), hashlib.sha256).digest()
    try:
        provided = _b64d(sig)
    except Exception:
        raise TokenError("malformed signature")
    if not hmac.compare_digest(expected, provided):
        raise TokenError("bad signature")
    now = time.time() if now is None else now
    if int(payload.get("exp", 0)) <= int(now):
        raise TokenError("token expired")
    if payload.get("scope") != required_scope:
        raise TokenError("wrong scope")
    for field in ("jti", "device_id", "tenant_id", "iat"):
        if field not in payload:
            raise TokenError(f"missing {field}")
    if revoked_jtis is not None and payload["jti"] in revoked_jtis:
        raise TokenError("token revoked")
    if required_policy_id is not None and             payload.get("policy_id") != required_policy_id:
        raise TokenError("wrong policy binding")
    return payload
