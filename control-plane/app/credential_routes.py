"""Credential-artifact API with durable post-commit cleanup."""
from fastapi import Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from . import credential_ops
from .credential_ops import (CredentialError, KINDS, decode_content,
                             fingerprint, artifact_json)
from .models import CredentialArtifact, User, utcnow
from .db import ScopedSession


class CredentialBody(BaseModel):
    kind: str
    label: str
    content_base64: str

def register_credential_routes(app, *, settings, current_user, db_session,
                               require_csrf_header, require_owner, error):
    @app.get("/api/credentials")
    def list_credentials(user: User = Depends(current_user),
                         session: Session = Depends(db_session)):
        # Retry any secret deletes stranded by an earlier crash
        # before reporting state.
        credential_ops.retry_pending_cleanups(session, settings.credentials_root, tenant_id=user.tenant_id)
        rows = session.execute(select(CredentialArtifact).where(
            CredentialArtifact.tenant_id == user.tenant_id
        ).order_by(CredentialArtifact.id)).scalars().all()
        return {"environment": settings.environment,
                "fixture_only": settings.environment != "production",
                "credentials": [artifact_json(r) for r in rows]}

    @app.post("/api/credentials",
              dependencies=[Depends(require_csrf_header)])
    def upload_credential(body: CredentialBody,
                          user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        if body.kind not in KINDS:
            return error(400, f"kind must be one of {', '.join(KINDS)}")
        label = body.label.strip()
        if not label:
            return error(400, "label is required")
        try:
            raw = decode_content(body.content_base64)
        except CredentialError as exc:
            return error(400, str(exc))
        try:
            rel = credential_ops.write_secret(settings.credentials_root,
                               user.tenant_id, raw)
        except (CredentialError, OSError) as exc:
            return error(503, "credential storage failed; nothing "
                              "was recorded")
        row = CredentialArtifact(
            tenant_id=user.tenant_id, kind=body.kind, label=label,
            sha256=fingerprint(raw), byte_size=len(raw),
            storage_path=rel, environment=settings.environment,
            uploaded_by_user_id=user.id)
        session.add(row)
        try:
            session.flush()
            ScopedSession(session, user.tenant_id).audit(
                "credential.upload", f"{row.kind} '{row.label}' "
                f"(sha256 {row.sha256[:12]}..., {row.byte_size} "
                f"bytes, env={row.environment})",
                actor_user_id=user.id)
            session.commit()
        except Exception:
            # The database record failed: do not strand the secret
            # bytes on disk with no row pointing at them.
            session.rollback()
            try:
                credential_ops.delete_secret(
                    settings.credentials_root, rel)
            except Exception:
                pass
            raise
        return artifact_json(row)

    @app.post("/api/credentials/{credential_id}/rotate",
              dependencies=[Depends(require_csrf_header)])
    def rotate_credential(credential_id: int, body: CredentialBody,
                          user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        row = session.get(CredentialArtifact, credential_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "credential not found")
        if row.status != "active":
            return error(409, "credential is revoked")
        try:
            raw = decode_content(body.content_base64)
        except CredentialError as exc:
            return error(400, str(exc))
        # Staged lifecycle: write the NEW bytes first; only after
        # they are durably in place does the row point at them.
        try:
            rel = credential_ops.write_secret(settings.credentials_root,
                               user.tenant_id, raw)
        except (CredentialError, OSError):
            return error(503, "credential storage failed; the "
                              "existing version is unchanged")
        # Do not overwrite the durable pointer to an older cleanup.
        if row.pending_cleanup_path:
            credential_ops.delete_secret(settings.credentials_root, rel)
            return error(409, "previous secret cleanup is pending; retry later")
        old_rel = row.storage_path
        row.storage_path = rel
        row.sha256 = fingerprint(raw)
        row.byte_size = len(raw)
        row.version += 1
        row.rotated_at = utcnow()
        row.pending_cleanup_path = old_rel
        try:
            ScopedSession(session, user.tenant_id).audit(
                "credential.rotate", f"{row.kind} '{row.label}' "
                f"-> version {row.version}; old secret cleanup pending",
                actor_user_id=user.id)
            session.commit()
        except Exception:
            session.rollback()
            try:
                credential_ops.delete_secret(settings.credentials_root, rel)
            except (OSError, CredentialError):
                pass  # orphan recovery handles an unavailable filesystem
            raise
        # Metadata and the cleanup intent are durable BEFORE removal.
        credential_ops.retry_pending_cleanups(
            session, settings.credentials_root, tenant_id=user.tenant_id)
        return artifact_json(row)

    @app.delete("/api/credentials/{credential_id}",
                dependencies=[Depends(require_csrf_header)])
    def revoke_credential(credential_id: int,
                          user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        row = session.get(CredentialArtifact, credential_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "credential not found")
        if row.status != "active":
            return error(409, "credential already revoked")
        # Persist revocation and cleanup intent BEFORE deleting bytes.
        # A failed commit leaves the active secret intact; a crash
        # after commit leaves a durable cleanup pointer for maintenance.
        if row.pending_cleanup_path:
            return error(409, "previous secret cleanup is pending; retry later")
        row.status = "revoked"
        row.revoked_at = utcnow()
        row.pending_cleanup_path = row.storage_path
        ScopedSession(session, user.tenant_id).audit(
            "credential.revoke", f"{row.kind} '{row.label}' "
            "(revoked; secret cleanup pending until confirmed)",
            actor_user_id=user.id)
        session.commit()
        credential_ops.retry_pending_cleanups(
            session, settings.credentials_root, tenant_id=user.tenant_id)
        return artifact_json(row)
