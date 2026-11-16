"""DDM serving routes (declarations, tokens, status reports) and the
NanoMDM enrollment check-in hook. Extracted from main.py."""
import json

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from . import ddm_ops
from .db import ScopedSession
from .models import MDMEnrollment


def register_ddm_routes(app, *, error, db_session, settings):

    # -- DDM serving (spec Part 10; NanoMDM -dm forwards device DDM
    # check-ins here; see app/ddm_ops.py docstring for the verified
    # protocol sources). No session cookie/CSRF: identity is the
    # X-Enrollment-ID header NanoMDM attaches, plus optional HMAC.
    def _ddm_enrollment(request: Request,
                        session: Session = Depends(db_session)):
        try:
            body = getattr(request.state, "_ddm_body", None)
            ddm_ops.verify_hmac(settings.ddm_hmac_key,
                                request.headers.get("x-hmac-signature"),
                                body or b"")
            enrollment, bound = ddm_ops.resolve_or_bind(
                session, request.headers.get("x-enrollment-id"))
            activated = ddm_ops.ensure_active(session, enrollment)
            if bound or activated:
                ScopedSession(session, enrollment.tenant_id).audit(
                    "mdm.enrollment_activated",
                    f"{enrollment.enrollment_id}: "
                    f"bound={bound} pending -> enrolled "
                    "(first authenticated DDM check-in)")
                session.commit()
        except ddm_ops.DDMError as exc:
            raise HTTPException(exc.status, str(exc))
        return enrollment

    @app.post("/api/mdm/enrollment-checkin")
    async def mdm_enrollment_checkin(request: Request,
                                     session: Session = Depends(db_session)):
        """NanoMDM enrollment-confirmation sync hook (see ddm_ops).

        The deployment syncs NanoMDM's enrollment confirmation to POST
        here when a device checks in; the HMAC authenticates the
        NanoMDM peer, and confirm_checkin records what NanoMDM
        authenticated through the MDM protocol: the device is enrolled
        (state pending -> enrolled). It records ENROLLMENT ONLY -
        supervision is device-reported state and is never accepted
        from this route. No session cookie/CSRF: identity is the HMAC
        peer, the enrollment ID in the body is a lookup key only."""
        body = await request.body()
        try:
            ddm_ops.verify_hmac(settings.ddm_hmac_key,
                                request.headers.get("x-hmac-signature"),
                                body)
            payload = json.loads(body.decode() or "{}")
            enrollment = ddm_ops.confirm_checkin(
                session, payload.get("enrollment_id"),
                nanomdm_id=payload.get("nanomdm_id"))
        except ddm_ops.DDMError as exc:
            return error(exc.status, str(exc))
        except (ValueError, UnicodeDecodeError):
            return error(400, "invalid JSON body")
        ScopedSession(session, enrollment.tenant_id).audit(
            "mdm.enrollment_checkin",
            f"{enrollment.enrollment_id}: state={enrollment.state}")
        session.commit()
        return {"enrollment_id": enrollment.enrollment_id,
                "state": enrollment.state}

    @app.get("/api/ddm/tokens")
    def ddm_tokens(enrollment: MDMEnrollment = Depends(_ddm_enrollment),
                   session: Session = Depends(db_session)):
        return ddm_ops.tokens(session, enrollment)

    @app.get("/api/ddm/declaration-items")
    def ddm_declaration_items(
            enrollment: MDMEnrollment = Depends(_ddm_enrollment),
            session: Session = Depends(db_session)):
        return ddm_ops.declaration_items(session, enrollment)

    @app.get("/api/ddm/declaration/{dtype}/{identifier}")
    def ddm_declaration(dtype: str, identifier: str,
                        enrollment: MDMEnrollment = Depends(_ddm_enrollment),
                        session: Session = Depends(db_session)):
        try:
            return ddm_ops.get_declaration(session, enrollment, dtype,
                                           identifier)
        except ddm_ops.DDMError as exc:
            return error(exc.status, str(exc))

    @app.put("/api/ddm/status")
    async def ddm_status(request: Request,
                         session: Session = Depends(db_session)):
        body = await request.body()
        request.state._ddm_body = body
        try:
            ddm_ops.verify_hmac(settings.ddm_hmac_key,
                                request.headers.get("x-hmac-signature"), body)
            enrollment, bound = ddm_ops.resolve_or_bind(
                session, request.headers.get("x-enrollment-id"))
            activated = ddm_ops.ensure_active(session, enrollment)
            if bound or activated:
                ScopedSession(session, enrollment.tenant_id).audit(
                    "mdm.enrollment_activated",
                    f"{enrollment.enrollment_id}: "
                    f"bound={bound} pending -> enrolled "
                    "(first authenticated DDM check-in)")
            ddm_ops.record_status(session, enrollment, body)
        except ddm_ops.DDMError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return {"received": True}
