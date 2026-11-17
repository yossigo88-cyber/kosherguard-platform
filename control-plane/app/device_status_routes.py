"""Device status routes (Answer 23): GET /api/devices with the
update-state chain, honestly layered - server intent, server command
ledger records, and stored device receipts are labeled as such; actual
on-device enforcement is never claimed.
"""
import json
from datetime import timedelta, timezone

from fastapi import Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (DDMStatusReport, Device, MDMCommand, MDMEnrollment,
                     PublicationState, User, utcnow)


def register_device_status_routes(app, *, error, current_user,
                                  db_session):
    def _connectivity_class(last_seen):
        """Receipt-based classification, NOT live presence: the server
        only knows when a device last reported. recently_reporting <
        1h; stale 1-24h; offline > 24h; never_reported when the
        enrollment has never contacted us."""
        if last_seen is None:
            return "never_reported"
        seen = last_seen
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        age = utcnow() - seen
        if age < timedelta(hours=1):
            return "recently_reporting"
        if age < timedelta(hours=24):
            return "stale"
        return "offline"

    @app.get("/api/devices")
    def list_devices(user: User = Depends(current_user),
                     session: Session = Depends(db_session)):
        """Devices with the Answer-23 update-state chain, honestly
        layered: desired state (assignments/publication) is server
        intent; command ledger states (queued/delivered/acknowledged)
        are server push records; last_seen/DDM reports are STORED
        DEVICE RECEIPTS. None of these proves actual on-device
        enforcement - the response says so per device."""
        from sqlalchemy import func
        from .models import (DDMStatusReport, DeviceAssignment,
                             MDMCommand, PublicationState)
        rows = session.scalars(select(Device).where(
            Device.tenant_id == user.tenant_id).order_by(Device.id))
        pub = session.get(PublicationState, user.tenant_id)
        published_revision = pub.revision if pub else 0
        devices = []
        for d in rows:
            enrollment = session.scalars(select(MDMEnrollment).where(
                MDMEnrollment.device_id == d.id).order_by(
                    MDMEnrollment.id.desc())).first()
            last_seen = enrollment.last_seen_at if enrollment else None
            ack = session.scalar(select(func.max(MDMCommand.updated_at))
                .where(MDMCommand.tenant_id == user.tenant_id,
                       MDMCommand.status == "acknowledged")
                .join(MDMEnrollment,
                      MDMCommand.enrollment_pk == MDMEnrollment.id)
                .where(MDMEnrollment.device_id == d.id))
            receipt = (session.scalar(select(func.max(
                DDMStatusReport.received_at)).where(
                    DDMStatusReport.tenant_id == user.tenant_id,
                    DDMStatusReport.enrollment_id ==
                    enrollment.enrollment_id))
                if enrollment else None)
            confirmed = [t for t in (ack, receipt) if t is not None]
            pending = session.scalar(select(func.count())
                .select_from(MDMCommand)
                .where(MDMCommand.tenant_id == user.tenant_id,
                       MDMCommand.status.in_(
                           ("queued", "delivered", "not_now")))
                .join(MDMEnrollment,
                      MDMCommand.enrollment_pk == MDMEnrollment.id)
                .where(MDMEnrollment.device_id == d.id))
            assignment = session.scalars(select(DeviceAssignment).where(
                DeviceAssignment.device_id == d.id,
                DeviceAssignment.active.is_(True))).first()
            # Command-ledger channel states (server records only):
            # counts per ledger status plus the most recent command.
            # queued = written to the server queue, no delivery
            # recorded (or the adapter call failed); delivered /
            # not_now = accepted by the MDM server's queue, awaiting
            # device check-in; acknowledged / error = device answers
            # from reconciliation. The actual APNs lifecycle is never
            # observed by this server (NanoMDM owns push in a real
            # deployment), so apns is reported as unavailable, never
            # inferred from ledger states.
            status_counts = {r[0]: r[1] for r in session.execute(
                select(MDMCommand.status, func.count())
                .where(MDMCommand.tenant_id == user.tenant_id)
                .join(MDMEnrollment,
                      MDMCommand.enrollment_pk == MDMEnrollment.id)
                .where(MDMEnrollment.device_id == d.id)
                .group_by(MDMCommand.status)).all()}
            latest_cmd = session.scalars(select(MDMCommand)
                .where(MDMCommand.tenant_id == user.tenant_id)
                .join(MDMEnrollment,
                      MDMCommand.enrollment_pk == MDMEnrollment.id)
                .where(MDMEnrollment.device_id == d.id)
                .order_by(MDMCommand.id.desc())).first()
            # Reported-vs-published comparison: the latest stored DDM
            # receipt's declaration states matched against what the
            # server currently serves this enrollment. Only an
            # identifier+server-token match with active+valid counts
            # as "reported applied" - still a receipt, not proof.
            latest_report = (session.scalars(select(DDMStatusReport)
                .where(DDMStatusReport.tenant_id == user.tenant_id,
                       DDMStatusReport.enrollment_id ==
                       enrollment.enrollment_id)
                .order_by(DDMStatusReport.id.desc())).first()
                if enrollment else None)
            if enrollment is None:
                reported = "no_enrollment"
            elif latest_report is None:
                reported = "no_report_received"
            else:
                from . import ddm_ops
                states = json.loads(latest_report.declaration_states
                                    or "{}")
                try:
                    served = {c["Identifier"]: c["ServerToken"]
                              for c in ddm_ops.configurations(
                                  session, enrollment)}
                except Exception:
                    served = None
                if served is None:
                    # the comparison itself could not run - never
                    # collapse this into "nothing served"
                    reported = "comparison_unavailable"
                else:
                    applied = sum(
                        1 for ident, tok in served.items()
                        if states.get(ident, {}).get("server_token") == tok
                        and states.get(ident, {}).get("active") is True
                        and states.get(ident, {}).get("valid") == "valid")
                    reported = ("no_declarations_served" if not served
                                else "all_served_reported_applied"
                                if applied == len(served)
                                else "served_not_fully_reported")
            devices.append({
                "id": d.id, "name": d.name, "state": d.state,
                "assigned_policy_id":
                    assignment.policy_id if assignment else None,
                "published_revision": published_revision,
                "enrollment": ({
                    "state": enrollment.state,
                    "supervision_requested":
                        enrollment.supervision_requested,
                    "supervision_verified":
                        enrollment.supervision_verified,
                    "last_seen_at": (enrollment.last_seen_at.isoformat()
                                     if enrollment.last_seen_at else None),
                } if enrollment else None),
                "connectivity": _connectivity_class(last_seen),
                "connectivity_basis":
                    "device check-in receipts only; not live presence",
                "push_chain": {
                    "by_status": status_counts,
                    "pending": pending,
                    "latest_command": ({
                        "command": latest_cmd.command,
                        "status": latest_cmd.status,
                        "applied": latest_cmd.applied,
                        "updated_at": latest_cmd.updated_at.isoformat(),
                    } if latest_cmd else None),
                    "apns": "unavailable",
                    "basis":
                        "server command ledger only: queued = written "
                        "to the server queue (no delivery recorded), "
                        "delivered/not_now = accepted by the MDM "
                        "server's queue awaiting device check-in, "
                        "acknowledged/error = device answers; none "
                        "proves application",
                    "apns_basis":
                        "the actual APNs push lifecycle is not observed "
                        "or recorded by this server (the MDM server "
                        "owns push in a real deployment); it is "
                        "reported as unavailable, never inferred"},
                "reported_vs_published": reported,
                "reported_vs_published_basis":
                    "latest stored DDM receipt's declaration states "
                    "matched against currently served declarations; a "
                    "stored receipt, not verified enforcement",
                "last_device_receipt": (max(confirmed).isoformat()
                                        if confirmed else None),
                "last_device_receipt_basis":
                    "latest stored device receipt (acknowledged command "
                    "or DDM status report); not a confirmed policy "
                    "application",
                "enforcement_note":
                    "server state and stored receipts only; actual "
                    "on-device enforcement is not verified by this "
                    "server"})
        return {"devices": devices}
