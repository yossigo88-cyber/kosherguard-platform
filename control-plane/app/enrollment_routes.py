"""Enrollment ticket routes (Answer 28): staff-assisted enrollment with
short-lived, single-use tickets, tenant+device assignment validation,
and device identity certificate recording.

The redeem endpoint is unauthenticated (device-side): the ticket token
IS the authentication. Everything else requires a guardian with device
delegation or an owner.
"""
import uuid
from datetime import timedelta, timezone

from fastapi import Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from . import certificate_ops, security
from .db import ScopedSession
from .models import Device, EnrollmentTicket, MDMEnrollment, utcnow

DEFAULT_TICKET_MINUTES = 60
MAX_TICKET_MINUTES = 24 * 60


class TicketIssueBody(BaseModel):
    expires_minutes: int = Field(default=DEFAULT_TICKET_MINUTES,
                                 ge=5, le=MAX_TICKET_MINUTES)


class TicketRedeemBody(BaseModel):
    ticket: str
    device_udid: str = Field(min_length=8, max_length=120)
    certificate_pem: str | None = None


def _ticket_json(t: EnrollmentTicket) -> dict:
    return {
        "id": t.id, "device_id": t.device_id,
        "expires_at": t.expires_at.isoformat(),
        "used_at": t.used_at.isoformat() if t.used_at else None,
        "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
        "created_at": t.created_at.isoformat(),
    }


def register_enrollment_routes(app, *, error, current_user, db_session,
                               require_csrf_header, require_guardian,
                               settings):
    @app.post("/api/mdm/devices/{device_id}/enrollment-tickets",
              dependencies=[Depends(require_csrf_header)])
    def issue_ticket(device_id: int, body: TicketIssueBody,
                     user=Depends(current_user),
                     session=Depends(db_session)):
        """Issue a short-lived, single-use ticket bound to THIS tenant
        and THIS device. The raw token is returned once and never
        stored; only its hash is kept."""
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        device = session.get(Device, device_id)
        if device is None or device.tenant_id != user.tenant_id:
            return error(404, "device not found")
        if device.state != "active":
            return error(409, f"device is {device.state}; reactivate before enrolling")
        token = security.new_session_token()
        ticket = EnrollmentTicket(
            tenant_id=user.tenant_id, device_id=device_id,
            token_hash=security.hash_session_token(token),
            created_by_user_id=user.id,
            expires_at=utcnow() + timedelta(minutes=body.expires_minutes))
        session.add(ticket)
        session.flush()
        ScopedSession(session, user.tenant_id).audit(
            "mdm.enrollment_ticket.issue",
            f"ticket {ticket.id} for device {device_id} "
            f"({body.expires_minutes}m)", actor_user_id=user.id)
        session.commit()
        result = _ticket_json(ticket)
        result["ticket"] = token
        return result

    @app.get("/api/mdm/enrollment-tickets")
    def list_tickets(user=Depends(current_user),
                     session=Depends(db_session)):
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        rows = session.scalars(select(EnrollmentTicket).where(
            EnrollmentTicket.tenant_id == user.tenant_id)
            .order_by(EnrollmentTicket.id.desc()).limit(100)).all()
        return {"tickets": [_ticket_json(t) for t in rows]}

    @app.delete("/api/mdm/enrollment-tickets/{ticket_id}",
                dependencies=[Depends(require_csrf_header)])
    def revoke_ticket(ticket_id: int, user=Depends(current_user),
                      session=Depends(db_session)):
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        ticket = session.get(EnrollmentTicket, ticket_id)
        if ticket is None or ticket.tenant_id != user.tenant_id:
            return error(404, "ticket not found")
        if ticket.used_at is not None:
            return error(409, "ticket already used")
        if ticket.revoked_at is not None:
            return error(409, "ticket already revoked")
        ticket.revoked_at = utcnow()
        ScopedSession(session, user.tenant_id).audit(
            "mdm.enrollment_ticket.revoke", f"ticket {ticket_id}",
            actor_user_id=user.id)
        session.commit()
        return _ticket_json(ticket)

    @app.post("/api/mdm/enroll")
    def redeem_ticket(body: TicketRedeemBody,
                      session=Depends(db_session)):
        """Redeem an enrollment ticket. Unauthenticated by design: the
        single-use token authenticates the redemption, and the ticket's
        tenant+device binding is the assignment validation. The row is
        locked FOR UPDATE so concurrent redeems cannot both succeed
        (replay protection). A certificate, when presented, is parsed,
        expiry-checked, UDID-bound and (when a CA is configured)
        chain-verified; the result is recorded on the enrollment -
        verification never substitutes for the ticket."""
        ticket = session.scalar(select(EnrollmentTicket).where(
            EnrollmentTicket.token_hash == security.hash_session_token(
                body.ticket)).with_for_update())
        if ticket is None:
            return error(403, "invalid enrollment ticket")
        now = utcnow()
        expires = ticket.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if ticket.revoked_at is not None:
            return error(410, "ticket revoked")
        if expires <= now:
            return error(410, "ticket expired")
        if ticket.used_at is not None:
            return error(409, "ticket already used")
        device = session.get(Device, ticket.device_id)
        if device is None or device.state != "active":
            return error(409, "device not enrollable")
        cert_sha = None
        cert_status = None
        if body.certificate_pem:
            try:
                cert_sha, cert_status = certificate_ops.verify_device_certificate(
                    body.certificate_pem, body.device_udid,
                    settings.device_identity_ca_file)
            except certificate_ops.CertificateError as exc:
                return error(403, f"device identity certificate rejected: {exc}")
        # One pending/enrolled record per device: a second ticket for
        # the same device conflicts unless the earlier enrollment never
        # bound a UDID (still placeholder state) and is replaced.
        existing = session.scalars(select(MDMEnrollment).where(
            MDMEnrollment.device_id == ticket.device_id,
            MDMEnrollment.tenant_id == ticket.tenant_id,
            MDMEnrollment.state.in_(["pending", "enrolled"]))).all()
        for row in existing:
            if row.device_udid and row.device_udid != body.device_udid:
                return error(409, "device identity conflict with an existing enrollment")
        ticket.used_at = now
        if existing:
            enrollment = existing[0]
            enrollment.device_udid = body.device_udid
        else:
            enrollment = MDMEnrollment(
                tenant_id=ticket.tenant_id, device_id=ticket.device_id,
                enrollment_id=f"pending-{uuid.uuid4().hex[:16]}",
                device_udid=body.device_udid, state="pending")
        enrollment.enrollment_ticket_id = ticket.id
        enrollment.identity_cert_sha256 = cert_sha
        enrollment.identity_cert_status = cert_status
        session.add(enrollment)
        session.flush()
        ScopedSession(session, ticket.tenant_id).audit(
            "mdm.enrollment_ticket.redeem",
            f"ticket {ticket.id} device {ticket.device_id} "
            f"udid={body.device_udid} cert={cert_status or 'none'}",
            actor_user_id=ticket.created_by_user_id)
        session.commit()
        return {"enrollment_id": enrollment.enrollment_id,
                "state": enrollment.state,
                "device_udid": enrollment.device_udid,
                "identity_cert_status": cert_status}
