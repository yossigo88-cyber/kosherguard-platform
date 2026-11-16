"""Credential artifact storage (Part 16 credential-upload screens).

Lifecycle is real - upload, list metadata, rotate, revoke - while this
build is fixture-only: artifacts are stamped with the deployment's
environment, the screen warns on any non-production build, and no
production secret may be uploaded during development. Secrets are
stored on the server filesystem (mode 0600) under the configured
credentials root, never in Git and never in the database; the DB row
is metadata only. Content is never returned by any API response and
never logged.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import uuid

KINDS = ("apns_auth_key", "mdm_push_cert", "ade_server_token",
         "urlfilter_entitlement", "other")
MAX_BYTES = 64 * 1024  # APNs keys, certs and tokens are all far smaller.


class CredentialError(ValueError):
    pass


def decode_content(content_b64: str) -> bytes:
    if not isinstance(content_b64, str) or not content_b64.strip():
        raise CredentialError("content_base64 is required")
    try:
        raw = base64.b64decode(content_b64, validate=True)
    except (binascii.Error, ValueError):
        raise CredentialError("content_base64 is not valid base64")
    if not raw:
        raise CredentialError("empty credential content")
    if len(raw) > MAX_BYTES:
        raise CredentialError(
            f"credential exceeds {MAX_BYTES} bytes; upload the file, "
            "not an archive")
    return raw


def write_secret(root: str, tenant_id: int, raw: bytes) -> str:
    """Write secret bytes 0600 under root/tenant-<id>/; returns the
    path relative to root. Directories 0700. Never logs content."""
    if not root:
        raise CredentialError("credential storage not configured")
    tdir = os.path.join(root, f"tenant-{tenant_id}")
    os.makedirs(tdir, mode=0o700, exist_ok=True)
    os.chmod(tdir, 0o700)
    name = uuid.uuid4().hex + ".bin"
    path = os.path.join(tdir, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
    return os.path.join(f"tenant-{tenant_id}", name)


def delete_secret(root: str, rel_path: str) -> None:
    """Best-effort removal of the secret bytes (revoke/rotate)."""
    try:
        os.unlink(os.path.join(root, rel_path))
    except OSError:
        pass


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def artifact_json(row) -> dict:
    """Metadata-only representation. Content is NEVER included."""
    return {
        "id": row.id, "kind": row.kind, "label": row.label,
        "sha256": row.sha256, "byte_size": row.byte_size,
        "environment": row.environment, "status": row.status,
        "version": row.version,
        "created_at": row.created_at.isoformat(),
        "rotated_at": row.rotated_at.isoformat() if row.rotated_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }
