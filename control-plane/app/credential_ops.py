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
import re
import uuid
import time

_SAFE_REL = re.compile(r"^tenant-\d+/[0-9a-f]{32}\.bin$")

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


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_secret(root: str, tenant_id: int, raw: bytes) -> str:
    """Write secret bytes under root/tenant-<id>/ and return the path
    relative to root. Crash-safe: the bytes go to a sibling tmp file
    (0600), are fsynced and size-verified, then atomically renamed into
    place and the directory is fsynced. A partial write or a crash
    mid-write never leaves a truncated secret under the final name;
    only ever a tmp file. Directories 0700. Never logs content."""
    if not root:
        raise CredentialError("credential storage not configured")
    tdir = os.path.join(root, f"tenant-{tenant_id}")
    os.makedirs(tdir, mode=0o700, exist_ok=True)
    if os.path.commonpath([os.path.realpath(root), os.path.realpath(tdir)]) != os.path.realpath(root):
        raise CredentialError("credential directory escapes storage root")
    os.chmod(tdir, 0o700)
    name = uuid.uuid4().hex + ".bin"
    path = os.path.join(tdir, name)
    tmp = os.path.join(tdir, f".{name}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.getsize(tmp) != len(raw):
            raise CredentialError("partial write detected")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(tdir)
    return os.path.join(f"tenant-{tenant_id}", name)


def delete_secret(root: str, rel_path: str) -> bool:
    """Remove secret bytes; True when they are gone (deleted or already
    absent). The stored path is validated against the tenant-directory
    pattern first, so a bad row can never delete outside the
    credentials root. OSError propagates so callers can record a
    pending cleanup instead of losing the bytes silently."""
    if not _SAFE_REL.match(rel_path or ""):
        raise CredentialError(f"unsafe credential path: {rel_path!r}")
    path = os.path.join(root, rel_path)
    # Reject a tenant directory redirected outside the configured root.
    if os.path.commonpath([os.path.realpath(root),
                          os.path.realpath(os.path.dirname(path))]) != os.path.realpath(root):
        raise CredentialError("credential directory escapes storage root")
    if os.path.abspath(os.path.dirname(path)) != os.path.abspath(
            os.path.join(root, os.path.dirname(rel_path))):
        raise CredentialError(f"unsafe credential path: {rel_path!r}")
    if os.path.exists(path):
        os.unlink(path)
        _fsync_dir(os.path.dirname(path))
    return not os.path.exists(path)


def retry_pending_cleanups(session, root: str, tenant_id=None) -> int:
    """Retry secret deletes stranded by a crash or IO error after the
    database row had already moved on (rotate/revoke). Clears
    pending_cleanup_path once the bytes are gone. Returns the number
    of rows cleaned."""
    from sqlalchemy import select
    from .models import CredentialArtifact, AuditEvent
    query = select(CredentialArtifact).where(
        CredentialArtifact.pending_cleanup_path.isnot(None))
    if tenant_id is not None:
        query = query.where(CredentialArtifact.tenant_id == tenant_id)
    rows = session.scalars(query.with_for_update()).all()
    cleaned = 0
    for row in rows:
        try:
            if delete_secret(root, row.pending_cleanup_path):
                row.pending_cleanup_path = None
                session.add(AuditEvent(tenant_id=row.tenant_id,
                    action="credential.cleanup.confirmed",
                    detail=f"artifact {row.id} obsolete secret bytes removed"))
                cleaned += 1
        except (OSError, CredentialError):
            continue
    if rows:
        session.commit()
    if tenant_id is None:
        recover_orphaned_files(session, root)
    return cleaned


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def artifact_json(row) -> dict:
    """Metadata-only representation. Content is NEVER included."""
    return {
        "id": row.id, "kind": row.kind, "label": row.label,
        "sha256": row.sha256, "byte_size": row.byte_size,
        "environment": row.environment, "status": row.status,
        "version": row.version,
        "cleanup_pending": row.pending_cleanup_path is not None,
        "created_at": row.created_at.isoformat(),
        "rotated_at": row.rotated_at.isoformat() if row.rotated_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }


def recover_orphaned_files(session, root: str, grace_seconds=86400) -> int:
    """Reap old unreferenced staged/orphan files after a 24h grace period.

    Covers process death and storage failure during rollback cleanup.
    UUID files only; never follow directory symlinks. This maintenance
    assumes credential transactions cannot stay open for 24 hours.
    """
    from sqlalchemy import select
    from .models import CredentialArtifact
    referenced = set()
    for row in session.scalars(select(CredentialArtifact)):
        referenced.add(row.storage_path)
        if row.pending_cleanup_path:
            referenced.add(row.pending_cleanup_path)
    removed = 0
    if not root or not os.path.isdir(root):
        return 0
    cutoff = time.time() - grace_seconds
    for tenant in os.scandir(root):
        if not re.fullmatch(r"tenant-[0-9]+", tenant.name) or not tenant.is_dir(follow_symlinks=False):
            continue
        for entry in os.scandir(tenant.path):
            rel = tenant.name + "/" + entry.name
            is_staged = re.fullmatch(r"\.[0-9a-f]{32}\.bin\.tmp-[0-9]+-[0-9a-f]{8}", entry.name)
            if (not entry.is_file(follow_symlinks=False) or
                    entry.stat(follow_symlinks=False).st_mtime >= cutoff or
                    rel in referenced or not (_SAFE_REL.fullmatch(rel) or is_staged)):
                continue
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                continue
    return removed
