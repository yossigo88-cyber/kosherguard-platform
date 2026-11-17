"""Support request routes (Answer 34).

Channels built: verified-email support (stored as channel METADATA
only - no outbound email delivery is claimed without a reviewed
integration), in-product support requests, account recovery,
enrollment assistance, device connectivity troubleshooting,
policy-change requests and escalation to an authorized administrator.

Hard rule: support workflows must not casually remove device
protection. These routes NEVER touch policies, devices, credentials,
enrollments or publications; a policy-change request is a recorded
request for the tenant's guardians to act on through the normal
gated policy flow, never a direct change. Status transitions and
escalations are audited. No support hours or 24/7 service is
promised anywhere.
"""
from pydantic import BaseModel, Field
from sqlalchemy import select
from fastapi import Depends

from .models import (Role, StaffRole, SupportRequest, utcnow)

KINDS = ("account_recovery", "enrollment_assistance",
         "connectivity_troubleshooting", "policy_change", "general")
CHANNELS = ("in_product", "email")
STATUS_FLOW = {"open": "in_progress", "in_progress": "resolved",
               "resolved": "closed"}


class CreateBody(BaseModel):
    kind: str
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1)
    channel: str = "in_product"


class StatusBody(BaseModel):
    notes: str = ""


def _request_json(r: SupportRequest) -> dict:
    return {"id": r.id, "tenant_id": r.tenant_id,
            "user_id": r.user_id, "kind": r.kind, "subject": r.subject,
            "body": r.body, "channel": r.channel, "status": r.status,
            "escalated": r.escalated,
            "resolution_notes": r.resolution_notes,
            "created_at": r.created_at.isoformat(),
            "updated_at": r.updated_at.isoformat()}


def register_support_routes(app, *, error, current_user, db_session,
                            require_csrf_header, require_staff):
    @app.post("/api/support/requests",
              dependencies=[Depends(require_csrf_header)])
    def create_request(body: CreateBody, user=Depends(current_user),
                       session=Depends(db_session)):
        if body.kind not in KINDS:
            return error(400, f"kind must be one of {list(KINDS)}")
        if body.channel not in CHANNELS:
            return error(400, f"channel must be one of {list(CHANNELS)}")
        req = SupportRequest(
            tenant_id=user.tenant_id, user_id=user.id,
            kind=body.kind, subject=body.subject.strip(),
            body=body.body, channel=body.channel)
        session.add(req)
        session.flush()
        from .db import ScopedSession
        ScopedSession(session, user.tenant_id).audit(
            "support.request.create",
            f"support request {req.id} kind={req.kind} "
            f"channel={req.channel}", actor_user_id=user.id)
        session.commit()
        return _request_json(req)

    @app.get("/api/support/requests")
    def list_requests(user=Depends(current_user),
                      session=Depends(db_session)):
        q = select(SupportRequest).where(
            SupportRequest.tenant_id == user.tenant_id)
        if user.role == Role.viewer:
            q = q.where(SupportRequest.user_id == user.id)
        rows = session.scalars(q.order_by(
            SupportRequest.id.desc())).all()
        return {"requests": [_request_json(r) for r in rows]}

    @app.get("/api/admin/support/requests")
    def admin_list(status: str | None = None,
                   user=Depends(current_user),
                   session=Depends(db_session)):
        denied = require_staff(error, user, StaffRole.owner,
                               StaffRole.security_admin,
                               StaffRole.support_admin)
        if denied is not None:
            return denied
        q = select(SupportRequest)
        if status:
            q = q.where(SupportRequest.status == status)
        rows = session.scalars(q.order_by(
            SupportRequest.id.desc())).all()
        return {"requests": [_request_json(r) for r in rows]}

    def _staff_request(error, session, user, request_id):
        denied = require_staff(error, user, StaffRole.owner,
                               StaffRole.security_admin,
                               StaffRole.support_admin)
        if denied is not None:
            return denied, None
        req = session.get(SupportRequest, request_id)
        if req is None:
            return error(404, "support request not found"), None
        return None, req

    @app.post("/api/admin/support/requests/{request_id}/advance",
              dependencies=[Depends(require_csrf_header)])
    def advance(request_id: int, body: StatusBody,
                user=Depends(current_user),
                session=Depends(db_session)):
        """Advance open -> in_progress -> resolved -> closed. Resolving
        requires notes. Bookkeeping only: no policy, device or
        protection state is touched by any support action."""
        denied, req = _staff_request(error, session, user, request_id)
        if denied is not None:
            return denied
        nxt = STATUS_FLOW.get(req.status)
        if nxt is None:
            return error(409, f"request is {req.status}; closed "
                              "requests cannot advance")
        if nxt == "resolved" and not body.notes.strip():
            return error(400, "resolving requires resolution notes")
        req.status = nxt
        if body.notes.strip():
            req.resolution_notes = body.notes
        req.updated_at = utcnow()
        from .db import ScopedSession
        ScopedSession(session, req.tenant_id).audit(
            "support.request.advance",
            f"support request {req.id} -> {nxt}",
            actor_user_id=user.id)
        session.commit()
        return _request_json(req)

    @app.post("/api/admin/support/requests/{request_id}/escalate",
              dependencies=[Depends(require_csrf_header)])
    def escalate(request_id: int, body: StatusBody,
                 user=Depends(current_user),
                 session=Depends(db_session)):
        """Escalate to an authorized administrator (staff owner). A
        recorded flag plus audit; the authorized administrator still
        acts through the normal gated flows, never through support."""
        denied, req = _staff_request(error, session, user, request_id)
        if denied is not None:
            return denied
        if req.status == "closed":
            return error(409, "closed requests cannot be escalated")
        req.escalated = True
        req.updated_at = utcnow()
        from .db import ScopedSession
        ScopedSession(session, req.tenant_id).audit(
            "support.request.escalate",
            f"support request {req.id} escalated: {body.notes!r}",
            actor_user_id=user.id)
        session.commit()
        return _request_json(req)
