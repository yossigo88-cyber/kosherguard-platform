"""Restore/re-enrollment readiness (Answer 26).

The recovery model: a computer-based restore may erase the device; the
device stays assigned to the correct Apple Business/ADE organization
(attested manually - no Apple credentials here); during Setup
Assistant the device must re-enroll; baseline management and filtering
configuration are restored; setup is released only after the required
checks succeed. The readiness endpoint computes the live checks from
real state; the ABM assignment step is a recorded guardian attestation
with FRESH MFA verification. Setup release is a report, never a device
action.

Freshness rules (a stale proof must never satisfy a new restore):

- An ABM attestation is bound to the device's CURRENT enrollment cycle
  (restore_attestations.enrollment_pk). An attestation recorded for a
  previous enrollment does not count after re-enrollment.
- The filtering credential must be unrevoked AND unexpired, bound to
  this device and tenant.
- The effective filtering policy must actually be assigned, enabled
  and at least as restrictive as the protected baseline - and the
  configuration must have been PUBLISHED (a real generation on disk),
  not merely saved in the database.
"""
import json
from datetime import timezone

from fastapi import Depends
from pydantic import BaseModel
from sqlalchemy import select

from .models import (Device, IssuedCredential, MDMEnrollment,
                     RestoreAttestation, utcnow)


class AttestBody(BaseModel):
    totp_code: str | None = None
    confirm: str | None = None


def _current_enrollment(session, tenant_id, device_id):
    """The device's current enrollment cycle: the newest non-terminal
    (pending/enrolled) record, if one exists."""
    return session.scalars(select(MDMEnrollment).where(
        MDMEnrollment.device_id == device_id,
        MDMEnrollment.tenant_id == tenant_id,
        MDMEnrollment.state.in_(["pending", "enrolled"])).order_by(
            MDMEnrollment.id.desc())).first()


def register_restore_routes(app, *, error, current_user, db_session,
                            require_csrf_header, require_guardian,
                            fresh_check, settings):
    @app.post("/api/mdm/devices/{device_id}/restore-attest",
              dependencies=[Depends(require_csrf_header)])
    def attest(device_id: int, body: AttestBody,
               user=Depends(current_user), session=Depends(db_session)):
        """Record that the device remains assigned to the correct
        Apple Business/ADE organization after a restore. This is a
        sensitive attestation: it requires fresh MFA verification and
        explicit confirmation, and it is bound to the device's CURRENT
        enrollment cycle so it can never satisfy a later restore.
        Attested, never executed or Apple-verified by this build."""
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        device = session.get(Device, device_id)
        if device is None or device.tenant_id != user.tenant_id:
            return error(404, "device not found")
        bad = fresh_check(error, user, body.totp_code, body.confirm,
                          "attest-abm-assignment")
        if bad is not None:
            return bad
        enrollment = _current_enrollment(session, user.tenant_id,
                                         device_id)
        if enrollment is None:
            return error(409, "no current enrollment cycle to bind the "
                              "attestation to; enroll the device first")
        row = RestoreAttestation(
            tenant_id=user.tenant_id, device_id=device_id,
            attested_by_user_id=user.id,
            enrollment_pk=enrollment.id,
            attestation_kind="manual_guardian")
        session.add(row)
        session.flush()
        from .db import ScopedSession
        ScopedSession(session, user.tenant_id).audit(
            "restore.attest_abm_assignment",
            f"device {device_id} attestation {row.id} "
            f"(enrollment {enrollment.id}, manual guardian attestation)",
            actor_user_id=user.id)
        session.commit()
        return {"id": row.id, "device_id": row.device_id,
                "enrollment_pk": enrollment.id,
                "attestation_kind": row.attestation_kind,
                "attested_at": row.attested_at.isoformat()}

    @app.get("/api/mdm/devices/{device_id}/restore-readiness")
    def readiness(device_id: int, user=Depends(current_user),
                  session=Depends(db_session)):
        """Live restore checklist computed from real state. Setup
        release requires every check green. This is a READINESS REPORT
        only - nothing here touches the device or releases Setup
        Assistant, and the ABM check is a manual guardian attestation,
        not an independently verified Apple-side state."""
        denied = require_guardian(user, "devices")
        if denied is not None:
            return denied
        device = session.get(Device, device_id)
        if device is None or device.tenant_id != user.tenant_id:
            return error(404, "device not found")
        enrollment = _current_enrollment(session, user.tenant_id,
                                         device_id)
        now = utcnow()
        device_active = device.state != "offboarded"

        # 1. ABM assignment attested FOR THIS enrollment cycle.
        attestation = None
        if enrollment is not None:
            attestation = session.scalars(select(RestoreAttestation).where(
                RestoreAttestation.device_id == device_id,
                RestoreAttestation.tenant_id == user.tenant_id,
                RestoreAttestation.enrollment_pk == enrollment.id
            ).order_by(RestoreAttestation.id.desc())).first()

        # 2. Re-enrolled: the CURRENT enrollment is live.
        reenrolled = device_active and enrollment is not None and enrollment.state == "enrolled"

        # 3. Filtering credential: unrevoked AND unexpired, bound to
        # this device and tenant.
        creds = [c for c in session.scalars(select(IssuedCredential).where(
            IssuedCredential.device_id == device_id,
            IssuedCredential.tenant_id == user.tenant_id,
            IssuedCredential.revoked_at.is_(None))).all()
            if (enrollment is not None and device_active and
                c.scope == "dataset" and _aware(c.expires_at) > now and
                _aware(c.created_at) >= _aware(enrollment.created_at))]

        # 4. Effective policy assigned, enabled and at least as
        # restrictive as the protected baseline.
        from . import group_ops, policy_ops
        from .models import Policy
        baseline = policy_ops.selected_default(session, user.tenant_id)
        policy_ok = False
        policy = None
        policy_detail = "no protected baseline selected"
        if baseline is not None and baseline.enabled:
            try:
                assignments = group_ops.effective_assignments(
                    session, user.tenant_id)
            except policy_ops.PolicyError as exc:
                assignments = {}
                policy_detail = f"invalid assignment state: {exc}"
            else:
                policy_id = assignments.get(device_id, baseline.id)
                policy = session.get(Policy, policy_id)
                if policy is None or policy.tenant_id != user.tenant_id:
                    policy_detail = "assigned policy not found"
                elif not policy.enabled:
                    policy_detail = "assigned policy is disabled"
                else:
                    try:
                        policy_ops.prove_tighten_only(
                            json.loads(policy.engine_doc),
                            baseline)
                        policy_ok = True
                        policy_detail = None
                    except policy_ops.PolicyError as exc:
                        policy_detail = str(exc)

        # 5. The required configuration is actually PUBLISHED (a real
        # generation on disk), not merely saved in the database.
        from .publisher import Publisher
        from .publication_ops import tenant_root
        from .publisher import PublicationError, canonical_json
        publisher = Publisher(tenant_root(
            settings.publications_root, user.tenant_id))
        published_ok = False
        try:
            published = publisher.current()
            if (published and reenrolled and policy_ok and
                    published.get("enrollment_cycles", {}).get(
                        str(device_id)) == enrollment.id):
                generation_dir = publisher.generations_dir / published["generation"]
                mapping_path = generation_dir / "device-map.json"
                mapping = json.loads(mapping_path.read_bytes()) if mapping_path.exists() else {}
                entry = mapping.get("devices", {}).get(str(device_id))
                if entry:
                    policy_name = entry["policy"]
                    mapped_id = entry["policy_id"]
                else:
                    policy_name = "policy.json"
                    mapped_id = baseline.id
                published_ok = (
                    mapped_id == policy.id and
                    (generation_dir / policy_name).read_bytes() ==
                        canonical_json(json.loads(policy.engine_doc)) and
                    (generation_dir / "policy.json").read_bytes() ==
                        canonical_json(json.loads(baseline.engine_doc)))
        except (PublicationError, OSError, ValueError, KeyError):
            # Missing/corrupt/old evidence is a failed check, never readiness.
            published_ok = False

        checks = {
            "abm_assignment_attested": device_active and attestation is not None,
            "device_reenrolled": reenrolled,
            "baseline_assignment_valid": policy_ok,
            "filtering_credential_active": len(creds) > 0,
            "filtering_configuration_published": published_ok,
        }
        return {
            "device_id": device_id,
            "enrollment_pk": enrollment.id if enrollment else None,
            "enrollment_state": enrollment.state if enrollment else None,
            "checks": checks,
            "basis": {
                "abm_assignment_attested": (
                    "manual guardian attestation bound to the CURRENT "
                    "enrollment cycle (fresh MFA verified); this build "
                    "has no Apple credentials, so it is not an "
                    "independently verified Apple-side state"),
                "device_reenrolled":
                    "current enrollment record is live (state enrolled)",
                "baseline_assignment_valid": (policy_detail or
                    "effective policy is assigned, enabled and proven "
                    "at least as restrictive as the protected baseline"),
                "filtering_credential_active":
                    "an unrevoked AND unexpired dataset credential issued "
                    "to this device and tenant during this enrollment cycle exists",
                "filtering_configuration_published":
                    "a verified published generation matches the current "
                    "enrollment cycle, effective policy and protected baseline",
            },
            "attestation_kind": (attestation.attestation_kind
                                 if attestation else None),
            "setup_release_ready": all(checks.values()),
            "note": ("readiness report only; Setup Assistant release is "
                     "a manual operator step, never automatic"),
        }


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
