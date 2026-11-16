"""DoH per-device identity binding (approved design, dns-edge half).

The user's approved requirement (WhatsApp 2026-11-16 02:25 EST):
authenticated per-device DNS as the intended identity mechanism; no
long-lived bearer credentials in DoH URLs or query strings; scoped
protected credentials; credentials redacted from logs.

This module is the DoH front that enforces it:
- Each DNS-over-HTTPS request must carry a short-lived scoped device
  credential (scope "doh") in the Authorization header - never in the
  URL. URL-transported tokens are ignored by construction: the tenant
  is read ONLY from a verified token payload.
- The verified tenant_id selects that tenant's publication root.
  There is no client-supplied tenant parameter at all, so a
  cross-tenant query is inexpressible, not merely rejected.
- Token values are never logged; errors are deliberately generic.

Verification logic is shared with url-filter-server's device_auth
(single implementation, imported by path like the engine import in
runner.py).
"""

from __future__ import annotations

import os
import sys

_UFS_APP = os.path.join(os.path.dirname(__file__), "..",
                        "url-filter-server")
sys.path.insert(0, os.path.abspath(_UFS_APP))

from app.device_auth import TokenError, verify_token  # noqa: E402


class IdentityError(Exception):
    """Generic auth/identity failure - no oracle about which check."""


def authenticate_doh_request(authorization_header: str | None,
                             key: bytes, now: float | None = None,
                             revoked_jtis=None) -> dict:
    """Verify the DoH device credential; return the token payload.

    Raises IdentityError on any failure. The token value is never
    included in any exception message.
    """
    if not key:
        raise IdentityError("device identity is not configured")
    header = authorization_header or ""
    token = header[7:] if header.lower().startswith("bearer ") else ""
    try:
        return verify_token(key, token, "doh", now=now,
                            revoked_jtis=revoked_jtis)
    except TokenError:
        raise IdentityError("unauthorized")


def tenant_root_for_token(publications_root: str, payload: dict) -> str:
    """Map a verified token to the tenant's publication root.

    The tenant comes from the signed payload only. Path traversal is
    refused: the resolved path must stay under publications_root.
    """
    tenant_id = str(payload.get("tenant_id", ""))
    # Tenant ids are integers minted by the control plane; anything
    # with path semantics is refused before touching the filesystem.
    if not tenant_id.isdigit() or int(tenant_id) <= 0:
        raise IdentityError("bad tenant identity")
    # Same layout the publisher writes (publication_ops.tenant_root):
    # <root>/tenant-<id>, single level, no client-supplied segment.
    root = os.path.realpath(
        os.path.join(publications_root, f"tenant-{int(tenant_id)}"))
    base = os.path.realpath(publications_root)
    if not (root.startswith(base + os.sep)):
        raise IdentityError("bad tenant identity")
    return root
