"""Staff-role permission gates and routes (Answer 29 five roles;
Answer 25 two-person approval for destructive operations).

Extracted from main.py so the control plane's route module stays
reviewable and the sensitive surface gets its own audited home.

NOTE: no `from __future__ import annotations` here - FastAPI must
resolve the injected mdm_command_body annotation object at route
registration time.
"""
import json
from datetime import timedelta, timezone

from fastapi import Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select

from pydantic import BaseModel

from . import mdm_ops, security
from .db import ScopedSession
from .models import (Device, MDMEnrollment, Role,
                     SensitiveCommandApproval, StaffRole, User,
                     utcnow)
from mdm.adapter import DESTRUCTIVE_COMMANDS  # noqa: F401 (re-exported)


def require_staff(error, user: User, *roles: StaffRole) -> JSONResponse | None:
    """Least-privilege staff gate: the user's staff_role must be one of
    roles. Staff without a matching role get 403."""
    if user.staff_role is None:
        return error(403, "platform staff account required")
    try:
        have = StaffRole(user.staff_role)
    except ValueError:
        return error(403, "platform staff account required")
    if have not in roles:
        return error(403, f"requires staff role: {', '.join(r.value for r in roles)}")
    return None


ALL_STAFF = (StaffRole.owner, StaffRole.security_admin,
             StaffRole.support_admin, StaffRole.read_only)

LIMITED_STAFF = (StaffRole.support_admin.value, StaffRole.read_only.value)


class SensitiveDecisionBody(BaseModel):
    totp_code: str | None = None
    confirm: str | None = None
    reason: str | None = None


class StaffRoleBody(BaseModel):
    staff_role: str | None = None  # null revokes staff status


def fresh_check(error, user: User, totp_code: str | None,
                confirm: str | None, expected: str) -> JSONResponse | None:
    """Fresh verification + explicit confirmation for sensitive
    operations (Answer 25): a current TOTP code from the user's own
    authenticator (independent of the session) and a confirmation
    string equal to the operation name."""
    if not user.totp_secret:
        return error(403, "MFA enrollment required before sensitive operations")
    if not totp_code or not security.verify_totp(user.totp_secret, totp_code):
        return error(403, "fresh verification failed: current MFA code required")
    if confirm != expected:
        return error(400, f"explicit confirmation required: repeat '{expected}'")
    return None


def approval_json(a: SensitiveCommandApproval, session=None) -> dict:
    body = {
        "id": a.id, "operation": a.operation, "status": a.status,
        "reason": a.reason, "tenant_id": a.tenant_id,
        "enrollment_pk": a.enrollment_pk,
        "requested_by_user_id": a.requested_by_user_id,
        "decided_by_user_id": a.decided_by_user_id,
        "expires_at": a.expires_at.isoformat(),
        "decided_at": a.decided_at.isoformat() if a.decided_at else None,
        "decision_detail": a.decision_detail,
    }
    if session is not None:
        # An approver must see WHO asked and WHICH device is targeted
        # before approving - not just a request id and free text. Both
        # are same-tenant rows: the approval list is already scoped to
        # the caller's tenant, so this adds no cross-tenant disclosure.
        requester = session.get(User, a.requested_by_user_id)
        body["requested_by_email"] = requester.email if requester else None
        device_label = None
        if a.enrollment_pk is not None:
            enrollment = session.get(MDMEnrollment, a.enrollment_pk)
            if enrollment is not None:
                device = session.get(Device, enrollment.device_id)
                name = device.name if device else None
                udid = enrollment.device_udid or enrollment.enrollment_id
                device_label = f"{name} ({udid})" if name else udid
        body["device"] = device_label
    return body


def sensitive_privileged(user: User) -> bool:
    """May request/approve destructive operations. Support/read-only
    staff stay out even when the account also holds a tenant owner role
    (Answer 25: support is limited troubleshooting only)."""
    if user.staff_role in LIMITED_STAFF:
        return False
    return (user.role == Role.owner or user.staff_role in (
        StaffRole.owner.value, StaffRole.security_admin.value))


def register_staff_routes(app, *, error, current_user, db_session,
                          require_csrf_header, make_adapter, command_json,
                          require_guardian, mdm_command_body):
    """Register staff management, support troubleshooting and the
    sensitive-command two-person approval endpoints."""

    @app.get("/api/mdm/sensitive-approvals")
    def sensitive_list(user: User = Depends(current_user),
                       session=Depends(db_session)):
        denied = require_guardian(user)
        if denied is not None:
            return denied
        rows = session.scalars(select(SensitiveCommandApproval).where(
            SensitiveCommandApproval.tenant_id == user.tenant_id)
            .order_by(SensitiveCommandApproval.id.desc()).limit(100)).all()
        return {"approvals": [approval_json(a, session) for a in rows]}

    @app.post("/api/mdm/sensitive-approvals/{approval_id}/approve",
              dependencies=[Depends(require_csrf_header)])
    def sensitive_approve(approval_id: int, body: SensitiveDecisionBody,
                          user: User = Depends(current_user),
                          session=Depends(db_session)):
        """Second-person approval (Answer 25). Authority is re-validated
        at approval time, not inherited from request time: the approver
        must currently be privileged (live check), must be a DIFFERENT
        user than the requester, and the requester's authority is
        re-checked too - a requester demoted while the request was
        pending voids it. Execution is bound to the exact operation,
        target enrollment, tenant and payload recorded on the request;
        nothing from the approval request body can redirect it. The
        row is locked FOR UPDATE so a pending approval is single-use
        even under concurrent approvers."""
        if not sensitive_privileged(user):
            return error(403, "destructive operations are not available to this role")
        a = session.scalar(select(SensitiveCommandApproval).where(
            SensitiveCommandApproval.id == approval_id)
            .with_for_update())
        if a is None or a.tenant_id != user.tenant_id:
            return error(404, "approval not found")
        if a.status != "pending":
            return error(409, f"approval already {a.status}")
        exp = a.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= utcnow():
            a.status = "expired"
            session.commit()
            return error(410, "approval expired; request it again")
        if a.requested_by_user_id == user.id:
            return error(403, "two-person approval: a different privileged user must approve")
        requester = session.get(User, a.requested_by_user_id)
        if requester is None or not sensitive_privileged(requester):
            a.status = "void"
            a.decision_detail = "requester's authority changed while pending"
            session.commit()
            return error(409, "requester's authority changed; the request must be re-made")
        bad = fresh_check(error, user, body.totp_code, body.confirm, a.operation)
        if bad is not None:
            return bad
        a.status = "approved"
        a.decided_by_user_id = user.id
        a.decided_at = utcnow()
        if a.operation == "EraseDevice":
            try:
                row = mdm_ops.issue_command(
                    session, a.tenant_id, a.enrollment_pk, a.operation,
                    json.loads(a.payload or "{}"), user.id,
                    adapter=make_adapter(), allow_destructive=True)
                a.status = "executed"
                a.decision_detail = f"device command {row.id} queued ({row.status})"
            except mdm_ops.MDMError as exc:
                a.decision_detail = f"approved; queueing failed: {exc}"
        else:
            # ABM release / protection removal / certificate operation:
            # no live integration in this build. The approval is the
            # audited authorization record; an operator performs the
            # external step per the runbook. This is NOT implemented
            # functionality - the decision detail says so explicitly.
            a.status = "executed"
            a.decision_detail = ("approved; platform-level operation recorded - "
                                 "operator runbook required (no live ABM/certificate integration)")
        ScopedSession(session, a.tenant_id).audit(
            "mdm.sensitive.approve",
            f"{a.operation} approved by user {user.id}: {a.decision_detail}",
            actor_user_id=user.id)
        session.commit()
        return approval_json(a, session) | {"decision_detail": a.decision_detail}

    @app.post("/api/mdm/sensitive-approvals/{approval_id}/reject",
              dependencies=[Depends(require_csrf_header)])
    def sensitive_reject(approval_id: int, body: SensitiveDecisionBody,
                         user: User = Depends(current_user),
                         session=Depends(db_session)):
        if not sensitive_privileged(user):
            return error(403, "destructive operations are not available to this role")
        a = session.get(SensitiveCommandApproval, approval_id)
        if a is None or a.tenant_id != user.tenant_id:
            return error(404, "approval not found")
        if a.status != "pending":
            return error(409, f"approval already {a.status}")
        a.status = "rejected"
        a.decided_by_user_id = user.id
        a.decided_at = utcnow()
        a.decision_detail = (body.reason or "").strip() or "rejected"
        ScopedSession(session, a.tenant_id).audit(
            "mdm.sensitive.reject", f"{a.operation}: {a.decision_detail}",
            actor_user_id=user.id)
        session.commit()
        return approval_json(a, session)

    @app.get("/api/staff")
    def staff_list(user: User = Depends(current_user),
                   session=Depends(db_session)):
        denied = require_staff(error, user, StaffRole.owner)
        if denied is not None:
            return denied
        rows = session.scalars(select(User).where(
            User.staff_role.is_not(None)).order_by(User.id)).all()
        return {"staff": [{
            "id": u.id, "email": u.email, "staff_role": u.staff_role,
            "mfa_enrolled": u.totp_secret is not None,
        } for u in rows]}

    @app.post("/api/staff/{user_id}/role",
              dependencies=[Depends(require_csrf_header)])
    def staff_set_role(user_id: int, body: StaffRoleBody,
                       user: User = Depends(current_user),
                       session=Depends(db_session)):
        """Configure an authorized contact as staff (Answer 29: staff
        are configured later, not assumed to exist). Owner only. The
        last remaining staff owner cannot be demoted or revoked."""
        denied = require_staff(error, user, StaffRole.owner)
        if denied is not None:
            return denied
        target = session.get(User, user_id)
        if target is None:
            return error(404, "user not found")
        new_role = body.staff_role
        if new_role is not None:
            try:
                new_role = StaffRole(new_role).value
            except ValueError:
                return error(400, "unknown staff role")
        owners = [u for u in session.scalars(select(User).where(
            User.staff_role == StaffRole.owner.value)).all()]
        if (target.staff_role == StaffRole.owner.value
                and new_role != StaffRole.owner.value and len(owners) <= 1):
            return error(409, "cannot demote or revoke the last staff owner")
        old = target.staff_role
        target.staff_role = new_role
        ScopedSession(session, target.tenant_id).audit(
            "staff.role.change",
            f"{target.email}: {old} -> {new_role} (by {user.email})",
            actor_user_id=user.id)
        session.commit()
        return {"id": target.id, "email": target.email, "staff_role": target.staff_role}

    @app.post("/api/staff/tenants/{tenant_id}/enrollments/{enrollment_pk}/query",
              dependencies=[Depends(require_csrf_header)])
    def staff_support_query(tenant_id: int, enrollment_pk: int,
                            body: mdm_command_body,
                            user: User = Depends(current_user),
                            session=Depends(db_session)):
        """Support administrator troubleshooting (Answer 25/29): only
        the four read-only query commands, on the named tenant. Policy,
        profile and system changes stay out of support's reach; the
        read-only operator cannot issue commands at all."""
        denied = require_staff(error, user, StaffRole.owner,
                               StaffRole.security_admin,
                               StaffRole.support_admin)
        if denied is not None:
            return denied
        if body.command not in {"DeviceInformation", "ProfileList",
                                "InstalledApplicationList", "ManagedApplicationList"}:
            return error(403, "support troubleshooting is limited to read-only query commands")
        try:
            row = mdm_ops.issue_command(
                session, tenant_id, enrollment_pk, body.command,
                body.payload, user.id, adapter=make_adapter())
        except mdm_ops.MDMError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return command_json(row)
