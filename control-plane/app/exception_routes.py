"""Filtering exception API and narrow revocation cleanup authority."""
import json
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from .db import ScopedSession
from .models import User, utcnow


def register_exception_routes(app, *, current_user, db_session,
                              require_guardian, require_csrf_header, error):
    @app.get("/api/exceptions")
    def list_exceptions(user: User = Depends(current_user),
                        session: Session = Depends(db_session)):
        # Exception details (reason, approver, loosened domains) are
        # sensitive: visible to the same roles that may create them.
        denied = require_guardian(user, "exceptions")
        if denied is not None:
            return denied
        from . import exception_ops
        from .models import PolicyException
        rows = session.scalars(select(PolicyException).where(
            PolicyException.tenant_id == user.tenant_id).order_by(
                PolicyException.id.desc())).all()
        return {"exceptions": [exception_ops.exception_json(r) for r in rows]}

    @app.post("/api/exceptions", dependencies=[Depends(require_csrf_header)])
    def create_exception(body: dict,
                         user: User = Depends(current_user),
                         session: Session = Depends(db_session)):
        denied = require_guardian(user, "exceptions")
        if denied is not None:
            return denied
        from . import exception_ops
        from .models import PolicyException
        try:
            (kind, scope_type, device_id, group_id, domains, reason,
             starts, expires) = exception_ops.validate_new(
                session, user.tenant_id, user, body)
        except Exception as exc:
            from .policy_ops import PolicyError
            if isinstance(exc, PolicyError):
                return error(exc.status, str(exc))
            raise
        row = PolicyException(
            tenant_id=user.tenant_id, kind=kind, scope_type=scope_type,
            device_id=device_id, group_id=group_id,
            domains=json.dumps(domains), reason=reason,
            approver_user_id=user.id, starts_at=starts, expires_at=expires)
        session.add(row)
        session.flush()
        ScopedSession(session, user.tenant_id).audit(
            "exception.create",
            f"{kind} for {scope_type} {device_id or group_id} "
            f"until {expires.isoformat()}: {reason}",
            actor_user_id=user.id)
        session.commit()
        return exception_ops.exception_json(row)

    @app.delete("/api/exceptions/{exception_id}",
                dependencies=[Depends(require_csrf_header)])
    def revoke_exception(exception_id: int,
                         user: User = Depends(current_user),
                         session: Session = Depends(db_session)):
        denied = require_guardian(user, "exceptions")
        if denied is not None:
            return denied
        from .models import PolicyException
        row = session.get(PolicyException, exception_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "exception not found")
        if row.revoked_at is None:
            row.revoked_at = utcnow()
            row.revoked_by = user.id
            ScopedSession(session, user.tenant_id).audit(
                "exception.revoke",
                f"exception {row.id} ({row.kind} for {row.scope_type} "
                f"{row.device_id or row.group_id}): {row.reason}",
                actor_user_id=user.id)
            session.flush()
            # A revoked exception keeps filtering-open at the edge until a
            # new generation ships, so revocation enqueues its own
            # publication instead of waiting for a manual publish. The job
            # keeps the real revoker as its actor and carries the
            # server-set "exception-revoke" system marker: a narrow
            # cleanup authority that lets the worker run it without
            # re-checking the revoker's publish delegation or the owner's
            # availability. It fabricates no owner/MFA approval - the
            # manifest records actor "system:exception-revoke job <id>"
            # and the audit keeps the initiating user - and it grants no
            # general publish capability (the jobs API cannot set the
            # marker; ordinary jobs keep the full actor re-check).
            # Cleanup ships only the LAST PUBLISHED snapshot minus revoked
            # exceptions, not saved drafts or a new tighten-only proof.
            from .worker import enqueue
            from sqlalchemy.exc import IntegrityError
            try:
                enqueue(session, user.tenant_id, user.id, user.email,
                        f"exception-revoke-{row.id}-{int(utcnow().timestamp())}",
                        system_action="exception-revoke")
                session.commit()
            except (ValueError, IntegrityError):
                # The rollback undoes the revocation itself - the
                # exception is still ACTIVE. Say exactly that; the old
                # message ("revoked, but...") claimed a revocation that
                # never happened.
                session.rollback()
                return error(500, "exception was NOT revoked: the "
                             "required republication job could not be "
                             "queued, so the revocation was rolled back "
                             "and the exception remains active. Retry "
                             "once publication queueing is restored.")
        from . import exception_ops
        return exception_ops.exception_json(row)
