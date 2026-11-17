"""Guardian-authorized native enrollment issuance, metadata and local revoke.

Private profiles are delivered ONLY by dedicated TLS listener. Disabled unless
create_app receives an explicit configured EnrollmentRuntime. This route does
not accept CA/signing/APNs keys or change Apple accounts/settings.
"""
from datetime import datetime

from fastapi import Depends
from pydantic import BaseModel, Field, StrictBool
from sqlalchemy.exc import IntegrityError

from mdm.identity import ProvisioningError
from mdm.profiles import ManualSupervisionDeclaration
from . import native_mdm
from .models import MDMProvision
from sqlalchemy import select


class DeclarationBody(BaseModel):
    serial_number: str
    supervised: StrictBool
    recorded_by: str
    recorded_at: datetime
    evidence: set[str]


class NativeIssueBody(BaseModel):
    udid: str = Field(min_length=8, max_length=120)
    serial: str = Field(min_length=1, max_length=120)
    mode: str = "ordinary"
    declaration: DeclarationBody | None = None


def register_native_mdm_routes(app, *, runtime, error, current_user,
        db_session, require_csrf_header, require_guardian):
    @app.post("/api/mdm/devices/{device_id}/native-enrollment",
              dependencies=[Depends(require_csrf_header)])
    def issue(device_id: int, body: NativeIssueBody,
              user=Depends(current_user), session=Depends(db_session)):
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        if body.mode == "ade":
            return error(409,"ADE requires fresh attended enrollment through configuration_web_url")
        declaration = None
        if body.declaration:
            d = body.declaration.model_dump()
            d["evidence"] = frozenset(d["evidence"])
            declaration = ManualSupervisionDeclaration(**d)
        try:
            token, pk = native_mdm.issue(session, runtime,
                tenant_id=user.tenant_id, device_id=device_id, udid=body.udid,
                serial=body.serial, mode=body.mode, declaration=declaration,
                actor_user_id=user.id)
            session.commit()
        except native_mdm.TransportError as exc:
            session.rollback()
            return error(exc.status, str(exc))
        except (IntegrityError, ProvisioningError):
            session.rollback()
            return error(409, "enrollment identity or configuration conflict")
        # ADE URL is assigned separately through Apple's Define Profile API.
        path = "/ade/" if body.mode == "ade" else "/enroll/"
        return {"enrollment_pk": pk, "profile_url": runtime.base_url+path+token,
                "expires_minutes": 10, "one_use": True,
                "strategy": body.mode, "device_behavior": "unverified"}

    @app.get("/api/mdm/native-enrollments")
    def listing(user=Depends(current_user), session=Depends(db_session)):
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        rows = session.scalars(select(MDMProvision).where(MDMProvision.tenant_id == user.tenant_id).order_by(MDMProvision.id.desc()).limit(100))
        return {"enrollments": [{"enrollment_pk": p.enrollment_pk,
            "mode": p.mode, "stage": p.stage,
            "revoked": p.revoked_at is not None,
            "profile_served": p.served_at is not None,
            "identity_expires_at": p.cert_expires_at.isoformat() if p.cert_expires_at else None,
            "identity_health": p.identity_health,
            "push_state": p.push_state,
            "identity_renewal": "controlled-overlap implementation; iPhone acceptance UNVERIFIED"} for p in rows]}

    @app.delete("/api/mdm/native-enrollments/{enrollment_pk}",
                dependencies=[Depends(require_csrf_header)])
    def revoke(enrollment_pk: int, user=Depends(current_user), session=Depends(db_session)):
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        try:
            native_mdm.revoke(session, tenant_id=user.tenant_id,
                enrollment_pk=enrollment_pk, actor_user_id=user.id)
            session.commit()
        except native_mdm.TransportError as exc:
            session.rollback()
            return error(exc.status, str(exc))
        return {"locally_revoked": True, "removed_from_device": False}

    @app.post("/api/mdm/native-enrollments/{enrollment_pk}/renew-identity",
              dependencies=[Depends(require_csrf_header)])
    def renew_identity(enrollment_pk: int, body: DeclarationBody | None = None,
                       user=Depends(current_user), session=Depends(db_session)):
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        declaration = None
        if body:
            d=body.model_dump();d["evidence"]=frozenset(d["evidence"])
            declaration=ManualSupervisionDeclaration(**d)
        try:
            cid=native_mdm.renew_identity(session,runtime,tenant_id=user.tenant_id,
                enrollment_pk=enrollment_pk,actor_user_id=user.id,declaration=declaration)
            session.commit()
        except native_mdm.TransportError as exc:
            session.rollback()
            return error(exc.status,str(exc))
        except (ValueError, IntegrityError):
            session.rollback()
            return error(409,"identity renewal configuration/crypto error")
        return {"command_id":cid,"state":"queued","device_result":"UNVERIFIED"}

    @app.delete("/api/mdm/native-enrollments/{enrollment_pk}/pending-identity",
                dependencies=[Depends(require_csrf_header)])
    def cancel_pending_identity(enrollment_pk:int,user=Depends(current_user),session=Depends(db_session)):
        denied=require_guardian(user,"devices")
        if denied is not None:return denied
        if runtime is None:return error(503,"native enrollment not configured")
        try:
            native_mdm.cancel_undelivered_renewal(session,runtime,tenant_id=user.tenant_id,
                enrollment_pk=enrollment_pk,actor_user_id=user.id)
            session.commit()
        except native_mdm.TransportError as exc:
            session.rollback();return error(exc.status,str(exc))
        return {"undelivered_identity_canceled":True}
