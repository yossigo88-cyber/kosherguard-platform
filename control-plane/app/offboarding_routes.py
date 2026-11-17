"""Offboarding case routes (Answer 24): documented, verified offboarding
for customer cancellation, device sale/transfer, loss of authority and
ownership disputes.

Hard rules (from the user's answer): nonpayment must never permanently
lock a device, and nothing here automatically erases a device or
releases it from Apple Business. Cases therefore NEVER issue MDM
commands. Completion performs the environment-feasible orchestration
itself (deactivate assignments, offboard enrollment records, delete the
departing device's filter-decision rows, stamp the tenant retention
date); Apple-side steps (Activation Lock cleared on the device, ABM
release) are recorded as attestations of manual steps, never executed
by this build.
"""
from datetime import timedelta

from fastapi import Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from .db import ScopedSession
from .models import (Device, DeviceAssignment, FilterDecision,
                     IssuedCredential, MDMEnrollment, OffboardingCase,
                     Tenant, utcnow)

KINDS = ("cancellation", "transfer", "loss_of_authority", "dispute")
DEVICE_KINDS = ("transfer", "loss_of_authority")
ATTEST_STEPS = ("activation_lock", "abm_release")


class CaseCreateBody(BaseModel):
    kind: str
    device_id: int | None = None
    notes: str = ""


class VerifyBody(BaseModel):
    totp_code: str | None = None
    confirm: str | None = None


class AttestBody(BaseModel):
    step: str
    totp_code: str | None = None
    confirm: str | None = None


class CompleteBody(BaseModel):
    notes: str = ""
    totp_code: str | None = None
    confirm: str | None = None


def _json(c: OffboardingCase) -> dict:
    def ts(v):
        return v.isoformat() if v else None
    return {
        "id": c.id, "tenant_id": c.tenant_id, "device_id": c.device_id,
        "kind": c.kind, "status": c.status,
        "created_by_user_id": c.created_by_user_id,
        "verified_by_user_id": c.verified_by_user_id,
        "verified_at": ts(c.verified_at),
        "activation_lock_attested_at": ts(c.activation_lock_attested_at),
        "abm_release_attested_at": ts(c.abm_release_attested_at),
        "data_retention_until": ts(c.data_retention_until),
        "notes": c.notes, "created_at": ts(c.created_at),
        "completed_at": ts(c.completed_at),
    }


def register_offboarding_routes(app, *, error, current_user, db_session,
                                require_csrf_header, require_guardian,
                                require_owner, fresh_check):
    def _case(session, user, case_id):
        # Row lock: verify/attest/complete/cancel transitions serialize
        # on the case row, and each one re-checks the committed status
        # before changing it - no double-complete, no verify-after-
        # cancel interleavings.
        case = session.scalar(select(OffboardingCase).where(
            OffboardingCase.id == case_id).with_for_update())
        if case is None or case.tenant_id != user.tenant_id:
            return None
        return case

    @app.post("/api/offboarding/cases",
              dependencies=[Depends(require_csrf_header)])
    def create_case(body: CaseCreateBody, user=Depends(current_user),
                    session=Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        if body.kind not in KINDS:
            return error(400, f"kind must be one of {', '.join(KINDS)}")
        if body.kind in DEVICE_KINDS and body.device_id is None:
            return error(400, f"{body.kind} requires a device_id")
        if body.device_id is not None:
            device = session.get(Device, body.device_id)
            if device is None or device.tenant_id != user.tenant_id:
                return error(404, "device not found")
        case = OffboardingCase(
            tenant_id=user.tenant_id, device_id=body.device_id,
            kind=body.kind, status="open", created_by_user_id=user.id,
            notes=body.notes)
        session.add(case)
        session.flush()
        ScopedSession(session, user.tenant_id).audit(
            "offboarding.case.create",
            f"case {case.id} kind={body.kind} device={body.device_id}",
            actor_user_id=user.id)
        session.commit()
        return _json(case)

    @app.get("/api/offboarding/cases")
    def list_cases(user=Depends(current_user), session=Depends(db_session)):
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        rows = session.scalars(select(OffboardingCase).where(
            OffboardingCase.tenant_id == user.tenant_id)
            .order_by(OffboardingCase.id.desc()).limit(100)).all()
        return {"cases": [_json(c) for c in rows]}

    @app.post("/api/offboarding/cases/{case_id}/verify",
              dependencies=[Depends(require_csrf_header)])
    def verify_case(case_id: int, body: VerifyBody,
                    user=Depends(current_user), session=Depends(db_session)):
        """Customer identity and ownership verification: the tenant
        OWNER re-verifies with a current MFA code and explicit
        confirmation. Nothing proceeds to completion without it."""
        denied = require_owner(user)
        if denied is not None:
            return denied
        case = _case(session, user, case_id)
        if case is None:
            return error(404, "case not found")
        if case.status != "open":
            return error(409, f"case is {case.status}")
        denied = fresh_check(error, user, body.totp_code, body.confirm,
                             "verify-offboarding")
        if denied is not None:
            return denied
        case.status = "verified"
        case.verified_by_user_id = user.id
        case.verified_at = utcnow()
        ScopedSession(session, user.tenant_id).audit(
            "offboarding.case.verify", f"case {case.id}",
            actor_user_id=user.id)
        session.commit()
        return _json(case)

    @app.post("/api/offboarding/cases/{case_id}/attest",
              dependencies=[Depends(require_csrf_header)])
    def attest_step(case_id: int, body: AttestBody,
                    user=Depends(current_user), session=Depends(db_session)):
        """Record a manual Apple-side step as attested (Activation Lock
        cleared on the device, ABM release performed). This build never
        executes those steps itself; the attestation is the record that
        the owner did them, confirmed with a fresh MFA code."""
        denied = require_owner(user)
        if denied is not None:
            return denied
        case = _case(session, user, case_id)
        if case is None:
            return error(404, "case not found")
        if case.status not in ("open", "verified"):
            return error(409, f"case is {case.status}")
        if body.step not in ATTEST_STEPS:
            return error(400, f"step must be one of {', '.join(ATTEST_STEPS)}")
        denied = fresh_check(error, user, body.totp_code, body.confirm,
                             f"attest-{body.step}")
        if denied is not None:
            return denied
        if body.step == "activation_lock":
            if case.activation_lock_attested_at is not None:
                return error(409, "activation lock already attested")
            case.activation_lock_attested_at = utcnow()
        else:
            if case.abm_release_attested_at is not None:
                return error(409, "ABM release already attested")
            case.abm_release_attested_at = utcnow()
        ScopedSession(session, user.tenant_id).audit(
            "offboarding.case.attest", f"case {case.id} step={body.step}",
            actor_user_id=user.id)
        session.commit()
        return _json(case)

    @app.post("/api/offboarding/cases/{case_id}/complete",
              dependencies=[Depends(require_csrf_header)])
    def complete_case(case_id: int, body: CompleteBody,
                      user=Depends(current_user), session=Depends(db_session)):
        """Complete a verified case with the environment-feasible
        orchestration done HERE (not just attestations), for device
        kinds (transfer / loss_of_authority): deactivate the device's
        policy assignments, mark its enrollment records offboarded
        (the authenticated DDM path refuses offboarded state - no
        silent reactivation), revoke its outstanding issued
        credentials (edge verifiers refuse revoked jtis via the
        revocation feed), and delete the departing device's
        filter-decision rows. `data_retention_until` is stamped from
        tenant policy. CANCELLATION touches no device: nonpayment must
        never revoke protection, lock, erase or release anything, and
        the case flow NEVER issues MDM commands. Protection changes
        propagate only through the existing separately gated publish
        flow, which ships published policy state plus the current
        device map - never unrelated drafts."""
        denied = require_owner(user)
        if denied is not None:
            return denied
        case = _case(session, user, case_id)
        if case is None:
            return error(404, "case not found")
        if case.status == "completed":
            return error(409, "case already completed")
        if case.status == "canceled":
            return error(409, "case canceled")
        if case.status != "verified":
            return error(409, "ownership verification required first")
        if case.kind == "dispute" and not (body.notes or case.notes):
            return error(400, "dispute completion requires resolution notes")
        if case.kind == "transfer" and (
                case.activation_lock_attested_at is None
                or case.abm_release_attested_at is None):
            return error(409, "transfer requires activation-lock and "
                              "ABM-release attestations")
        if case.kind == "loss_of_authority" and (
                case.abm_release_attested_at is None):
            return error(409, "loss of authority requires the "
                              "ABM-release attestation")
        # Completion retires devices, revokes credentials and purges
        # filter-decision rows: a sensitive, hard-to-undo transition
        # that requires fresh MFA verification and confirmation, the
        # same as verify and the Apple-side attestations.
        denied = fresh_check(error, user, body.totp_code, body.confirm,
                             "complete-offboarding")
        if denied is not None:
            return denied
        if body.notes:
            case.notes = (case.notes + "\n" + body.notes).strip()
        tenant = session.get(Tenant, case.tenant_id)
        case.data_retention_until = utcnow() + timedelta(
            days=tenant.blocked_log_retention_days)
        deleted_logs = 0
        revoked_creds = 0
        if case.device_id is not None and case.kind in DEVICE_KINDS:
            # Lock the device row before mutating its enrollments and
            # state so completion never interleaves with a concurrent
            # enrollment redemption or command issuance.
            session.scalar(select(Device).where(
                Device.id == case.device_id).with_for_update())
            for assignment in session.scalars(select(DeviceAssignment).where(
                    DeviceAssignment.device_id == case.device_id,
                    DeviceAssignment.tenant_id == case.tenant_id,
                    DeviceAssignment.active.is_(True))).all():
                assignment.active = False
            for enrollment in session.scalars(select(MDMEnrollment).where(
                    MDMEnrollment.device_id == case.device_id,
                    MDMEnrollment.tenant_id == case.tenant_id,
                    MDMEnrollment.state.in_(["pending", "enrolled"]))).all():
                from .native_mdm import cleanup_enrollment
                cleanup_enrollment(session, tenant_id=case.tenant_id,
                    enrollment_pk=enrollment.id, reason="offboarded")
                enrollment.state = "offboarded"
            for cred in session.scalars(select(IssuedCredential).where(
                    IssuedCredential.device_id == case.device_id,
                    IssuedCredential.tenant_id == case.tenant_id,
                    IssuedCredential.revoked_at.is_(None))).all():
                cred.revoked_at = utcnow()
                revoked_creds += 1
            deleted_logs = session.query(FilterDecision).filter(
                FilterDecision.device_id == case.device_id,
                FilterDecision.tenant_id == case.tenant_id).delete()
            device = session.get(Device, case.device_id)
            if device is not None:
                device.state = "offboarded"
            else:
                return error(404, "device not found")
        case.status = "completed"
        case.completed_at = utcnow()
        ScopedSession(session, user.tenant_id).audit(
            "offboarding.case.complete",
            f"case {case.id} kind={case.kind} device={case.device_id} "
            f"purged_logs={deleted_logs} revoked_creds={revoked_creds} "
            f"retention_until={case.data_retention_until.isoformat()}",
            actor_user_id=user.id)
        session.commit()
        return _json(case)

    @app.post("/api/offboarding/cases/{case_id}/cancel",
              dependencies=[Depends(require_csrf_header)])
    def cancel_case(case_id: int, user=Depends(current_user),
                    session=Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        case = _case(session, user, case_id)
        if case is None:
            return error(404, "case not found")
        if case.status == "completed":
            return error(409, "case already completed")
        if case.status == "canceled":
            return error(409, "case already canceled")
        case.status = "canceled"
        ScopedSession(session, user.tenant_id).audit(
            "offboarding.case.cancel", f"case {case.id}",
            actor_user_id=user.id)
        session.commit()
        return _json(case)
