"""Restore/re-enrollment readiness (Answer 26).

The recovery model: a computer-based restore may erase the device; the
device stays assigned to the correct Apple Business/ADE organization
(attested manually - no Apple credentials here); during Setup
Assistant the device must re-enroll; baseline management and filtering
configuration are restored; setup is released only after the required
checks succeed. The readiness endpoint computes the live checks from
real state; the ABM assignment step is a recorded guardian
attestation. Setup release is a report, never a device action.
"""
from fastapi import Depends
from pydantic import BaseModel
from sqlalchemy import select

from .models import (Device, DeviceAssignment, IssuedCredential,
                     MDMEnrollment, RestoreAttestation, utcnow)


class AttestBody(BaseModel):
    confirm: str | None = None


def register_restore_routes(app, *, error, current_user, db_session,
                            require_csrf_header, require_guardian):
    @app.post("/api/mdm/devices/{device_id}/restore-attest",
              dependencies=[Depends(require_csrf_header)])
    def attest(device_id: int, body: AttestBody,
               user=Depends(current_user), session=Depends(db_session)):
        """Record that the device remains assigned to the correct
        Apple Business/ADE organization after a restore. Attested,
        never executed by this build."""
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        device = session.get(Device, device_id)
        if device is None or device.tenant_id != user.tenant_id:
            return error(404, "device not found")
        if body.confirm != "attest-abm-assignment":
            return error(400, "explicit confirmation required: repeat "
                              "'attest-abm-assignment'")
        row = RestoreAttestation(
            tenant_id=user.tenant_id, device_id=device_id,
            attested_by_user_id=user.id)
        session.add(row)
        session.flush()
        from .db import ScopedSession
        ScopedSession(session, user.tenant_id).audit(
            "restore.attest_abm_assignment",
            f"device {device_id} attestation {row.id}",
            actor_user_id=user.id)
        session.commit()
        return {"id": row.id, "device_id": row.device_id,
                "attested_at": row.attested_at.isoformat()}

    @app.get("/api/mdm/devices/{device_id}/restore-readiness")
    def readiness(device_id: int, user=Depends(current_user),
                  session=Depends(db_session)):
        """Live restore checklist. Setup release requires every check
        green; the answer is computed from real state, and the ABM
        step is the recorded attestation. Nothing here touches the
        device."""
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        device = session.get(Device, device_id)
        if device is None or device.tenant_id != user.tenant_id:
            return error(404, "device not found")
        enrolled = session.scalars(select(MDMEnrollment).where(
            MDMEnrollment.device_id == device_id,
            MDMEnrollment.tenant_id == user.tenant_id,
            MDMEnrollment.state.in_(["enrolled", "active"]))).all()
        assignment = session.scalars(select(DeviceAssignment).where(
            DeviceAssignment.device_id == device_id,
            DeviceAssignment.tenant_id == user.tenant_id,
            DeviceAssignment.active.is_(True))).all()
        creds = session.scalars(select(IssuedCredential).where(
            IssuedCredential.device_id == device_id,
            IssuedCredential.tenant_id == user.tenant_id,
            IssuedCredential.revoked_at.is_(None))).all()
        attested = session.scalars(select(RestoreAttestation).where(
            RestoreAttestation.device_id == device_id,
            RestoreAttestation.tenant_id == user.tenant_id)).all()
        checks = {
            "abm_assignment_attested": len(attested) > 0,
            "device_reenrolled": len(enrolled) > 0,
            "baseline_assignment_active": len(assignment) > 0,
            "filtering_credential_issued": len(creds) > 0,
        }
        return {"device_id": device_id, "checks": checks,
                "setup_release_ready": all(checks.values())}
