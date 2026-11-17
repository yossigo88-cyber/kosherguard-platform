"""Structured exception-request routes (spec Part 2A customer portal:
"request exceptions or policy changes").

A request is inert while pending; approving it creates a real
PolicyException through the same validation as direct creation, with
the approver recorded. Distinct from the free-text policy_change
support kind.
"""
import json
from datetime import timedelta

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ScopedSession
from .models import Role, User, utcnow


def register_exception_request_routes(app, *, error, current_user,
                                      db_session, require_csrf_header,
                                      require_guardian):

    def _exception_request_json(r, session):
        requester = session.get(User, r.requester_user_id)
        decider = (session.get(User, r.decided_by_user_id)
                   if r.decided_by_user_id else None)
        return {"id": r.id, "kind": r.kind, "scope_type": r.scope_type,
                "device_id": r.device_id, "group_id": r.group_id,
                "domains": json.loads(r.domains or "[]"),
                "reason": r.reason,
                "duration_minutes": r.duration_minutes,
                "status": r.status,
                "requested_by_email": requester.email if requester else None,
                "decided_by_email": decider.email if decider else None,
                "exception_id": r.exception_id,
                "created_at": r.created_at.isoformat()}

    @app.post("/api/exception-requests",
              dependencies=[Depends(require_csrf_header)])
    def create_exception_request(body: dict,
                                 user: User = Depends(current_user),
                                 session: Session = Depends(db_session)):
        if user.role not in (Role.owner, Role.guardian):
            return error(403, "viewers cannot request exceptions")
        from . import exception_ops
        from .models import ExceptionRequest
        from .policy_ops import PolicyError
        kind = body.get("kind")
        scope_type = body.get("scope_type")
        try:
            duration = int(body.get("duration_minutes") or 0)
        except (TypeError, ValueError):
            return error(400, "duration_minutes must be an integer")
        if not 5 <= duration <= 10080:
            return error(400, "duration must be 5 minutes to 7 days")
        try:
            (kind, scope_type, device_id, group_id, domains, reason,
             _starts, _expires) = exception_ops.validate_new(
                session, user.tenant_id, user,
                {"kind": kind, "scope_type": scope_type,
                 "device_id": body.get("device_id"),
                 "group_id": body.get("group_id"),
                 "domains": body.get("domains") or [],
                 "reason": body.get("reason") or "",
                 "starts_at": None,
                 "expires_at": (utcnow() +
                                timedelta(minutes=duration)).isoformat()})
        except PolicyError as exc:
            return error(exc.status, str(exc))
        row = ExceptionRequest(
            tenant_id=user.tenant_id, requester_user_id=user.id,
            kind=kind, scope_type=scope_type, device_id=device_id,
            group_id=group_id, domains=json.dumps(domains), reason=reason,
            duration_minutes=duration)
        session.add(row)
        session.flush()
        ScopedSession(session, user.tenant_id).audit(
            "exception.request",
            f"{kind} requested for {scope_type} {device_id or group_id} "
            f"({duration} min): {reason}", actor_user_id=user.id)
        session.commit()
        return _exception_request_json(row, session)

    @app.get("/api/exception-requests")
    def list_exception_requests(user: User = Depends(current_user),
                                session: Session = Depends(db_session)):
        # Request details (requester email, reason, device, requested
        # filtering change) are sensitive: visible to the same roles
        # that may CREATE exceptions directly - the owner and guardians
        # with the explicit "exceptions" delegation. Ordinary viewers
        # and non-delegated guardians do not see them.
        denied = require_guardian(user, "exceptions")
        if denied is not None:
            return denied
        from .models import ExceptionRequest
        rows = session.scalars(select(ExceptionRequest).where(
            ExceptionRequest.tenant_id == user.tenant_id).order_by(
                ExceptionRequest.id.desc())).all()
        return {"requests": [_exception_request_json(r, session)
                             for r in rows]}

    def _decide_exception_request(request_id, decision, user, session):
        from . import exception_ops
        from .models import ExceptionRequest, PolicyException
        from .policy_ops import PolicyError
        denied = require_guardian(user, "exceptions")
        if denied is not None:
            return denied
        # Row lock: two concurrent decisions serialize; the second sees
        # the committed status and is refused. One decision, one
        # exception, one consistent audit trail.
        r = session.scalar(select(ExceptionRequest).where(
            ExceptionRequest.id == request_id).with_for_update())
        if r is None or r.tenant_id != user.tenant_id:
            return error(404, "exception request not found")
        if r.status != "pending":
            return error(409, f"request already {r.status}")
        r.decided_by_user_id = user.id
        r.decided_at = utcnow()
        if decision == "reject":
            r.status = "rejected"
            ScopedSession(session, user.tenant_id).audit(
                "exception.request.reject", f"request {r.id}",
                actor_user_id=user.id)
            session.commit()
            return _exception_request_json(r, session)
        # Approve: create the real exception through the same
        # validation direct creation uses - the approver's own
        # authority (owner, or guardian within delegated limits) is
        # what permits it, never the request itself.
        try:
            (kind, scope_type, device_id, group_id, domains, reason,
             starts, expires) = exception_ops.validate_new(
                session, user.tenant_id, user,
                {"kind": r.kind, "scope_type": r.scope_type,
                 "device_id": r.device_id, "group_id": r.group_id,
                 "domains": json.loads(r.domains or "[]"),
                 "reason": r.reason, "starts_at": None,
                 "expires_at": (utcnow() +
                                timedelta(minutes=
                                          r.duration_minutes)).isoformat()})
        except PolicyError as exc:
            return error(exc.status, str(exc))
        exc_row = PolicyException(
            tenant_id=user.tenant_id, kind=kind, scope_type=scope_type,
            device_id=device_id, group_id=group_id,
            domains=json.dumps(domains), reason=reason,
            approver_user_id=user.id, starts_at=starts, expires_at=expires)
        session.add(exc_row)
        session.flush()
        r.status = "approved"
        r.exception_id = exc_row.id
        ScopedSession(session, user.tenant_id).audit(
            "exception.request.approve",
            f"request {r.id} -> exception {exc_row.id}",
            actor_user_id=user.id)
        session.commit()
        return _exception_request_json(r, session)

    @app.post("/api/exception-requests/{request_id}/approve",
              dependencies=[Depends(require_csrf_header)])
    def approve_exception_request(request_id: int,
                                  user: User = Depends(current_user),
                                  session: Session = Depends(db_session)):
        return _decide_exception_request(request_id, "approve",
                                         user, session)

    @app.post("/api/exception-requests/{request_id}/reject",
              dependencies=[Depends(require_csrf_header)])
    def reject_exception_request(request_id: int,
                                 user: User = Depends(current_user),
                                 session: Session = Depends(db_session)):
        return _decide_exception_request(request_id, "reject",
                                         user, session)
