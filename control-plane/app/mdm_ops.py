"""MDM operations: enrollment records and the command lifecycle.

Tenant scoping is mandatory on every query; cross-tenant access is a
bug, and negative tests prove it. The status ledger follows spec Part
5/6: queued -> delivered -> acknowledged | error | not_now, and
``applied`` is set only from a positive device Acknowledged status -
never from a successful enqueue or send.
"""

from __future__ import annotations

import json
import sys
import os
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEvent, Device, MDMCommand, MDMEnrollment

_MDM_SRC = os.path.join(os.path.dirname(__file__), "..", "..")
if _MDM_SRC not in sys.path:
    sys.path.insert(0, os.path.abspath(_MDM_SRC))

from mdm.adapter import DESTRUCTIVE_COMMANDS, SUPPORTED_COMMANDS  # noqa: E402


class MDMError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


# States a command may be queued against. 'pending' is the local
# placeholder before the first device check-in (the command waits in
# the server queue, honestly); 'enrolled' is live. Offboarded or
# otherwise terminal/unknown states NEVER accept commands, and neither
# does an enrollment whose device was offboarded.
COMMANDABLE_STATES = ("pending", "enrolled")


def get_enrollment(session: Session, tenant_id: int,
                   enrollment_pk: int,
                   *, for_command: bool = False) -> MDMEnrollment:
    row = session.get(MDMEnrollment, enrollment_pk)
    if row is None or row.tenant_id != tenant_id:
        raise MDMError("enrollment not found", 404)
    if for_command:
        if row.state not in COMMANDABLE_STATES:
            raise MDMError(
                f"enrollment is {row.state}; commands require a current, "
                "non-terminal enrollment", 409)
        device = session.get(Device, row.device_id)
        if device is None or device.tenant_id != tenant_id or device.state != "active":
            raise MDMError(
                "device is offboarded; commands are no longer accepted "
                "for it", 409)
    return row


def create_enrollment(session: Session, tenant_id: int, device_id: int,
                      supervision_requested: bool = False,
                      device_udid: str | None = None) -> MDMEnrollment:
    """Legacy enrollment creation, under the SAME one-current-
    enrollment invariant as ticket redemption: the device row is locked
    FOR UPDATE (serializing against concurrent ticket redemptions and
    creations), an offboarded device is refused, a current enrollment
    with a bound identity conflicts, and an unbound placeholder is
    reused rather than duplicated."""
    device = session.scalar(select(Device).where(
        Device.id == device_id).with_for_update())
    if device is None or device.tenant_id != tenant_id:
        raise MDMError("device not found", 404)
    if device.state != "active":
        raise MDMError(
            f"device is {device.state}; reactivate before enrolling", 409)
    current = list(session.scalars(select(MDMEnrollment).where(
        MDMEnrollment.device_id == device_id,
        MDMEnrollment.tenant_id == tenant_id,
        MDMEnrollment.state.in_(["pending", "enrolled"]))))
    if current:
        bound = [r for r in current if r.device_udid]
        if bound or (device_udid and any(
                r.device_udid and r.device_udid != device_udid
                for r in current)):
            raise MDMError(
                "device already has a current enrollment", 409)
        # Unbound placeholder: reuse it instead of creating a second
        # current enrollment.
        row = current[0]
        if device_udid:
            row.device_udid = device_udid
        row.supervision_requested = (
            supervision_requested or row.supervision_requested)
        session.flush()
        session.add(AuditEvent(
            tenant_id=tenant_id, actor_user_id=None,
            action="mdm.enroll.create",
            detail=f"enrollment {row.id} for device {device_id} "
                   "(existing placeholder reused)"))
        return row
    row = MDMEnrollment(
        tenant_id=tenant_id,
        device_id=device_id,
        enrollment_id=f"pending-{uuid.uuid4().hex[:16]}",
        device_udid=device_udid,
        state="pending",
        supervision_requested=supervision_requested,
        supervision_verified=False,
    )
    session.add(row)
    session.flush()
    session.add(AuditEvent(tenant_id=tenant_id, actor_user_id=None,
                           action="mdm.enroll.create",
                           detail=f"enrollment {row.id} for device {device_id}"))
    return row


def list_enrollments(session: Session, tenant_id: int) -> list[MDMEnrollment]:
    return list(session.scalars(
        select(MDMEnrollment).where(MDMEnrollment.tenant_id == tenant_id)
        .order_by(MDMEnrollment.id)))


def issue_command(session: Session, tenant_id: int, enrollment_pk: int,
                  command: str, payload: dict | None,
                  actor_user_id: int | None,
                  adapter=None, allow_destructive: bool = False) -> MDMCommand:
    """Queue one supported command and optionally attempt delivery.

    With an adapter, delivery is attempted immediately and the device
    status recorded. Without one (no MDM server configured) the command
    stays queued - which is the honest state: nothing was delivered.

    Destructive commands (EraseDevice etc.) are refused unless
    allow_destructive=True, which only the two-person approval flow may
    pass after a second privileged user approves (Answer 25).
    """
    if command in DESTRUCTIVE_COMMANDS:
        if not allow_destructive:
            raise MDMError(
                f"{command} requires two-person approval; direct issuance refused")
    elif command not in SUPPORTED_COMMANDS:
        raise MDMError(f"unsupported command: {command}")
    # Validity is checked NOW (tenant ownership, non-terminal
    # enrollment state, device not offboarded) - including when an
    # approved destructive command is finally queued, which can be long
    # after the request was made.
    enrollment = get_enrollment(session, tenant_id, enrollment_pk,
                                for_command=True)
    row = MDMCommand(
        tenant_id=tenant_id,
        enrollment_pk=enrollment.id,
        command=command,
        payload=json.dumps(payload or {}),
        status="queued",
        actor_user_id=actor_user_id,
    )
    session.add(row)
    session.flush()
    # Native device-channel enrollments consume this same ledger directly.
    # Never hand native credentials/commands to the independent NanoMDM path.
    from .models import MDMProvision
    native = session.scalar(select(MDMProvision).where(
        MDMProvision.enrollment_pk == enrollment_pk,
        MDMProvision.tenant_id == tenant_id))
    if native is not None:
        from mdm.command_codec import encode_command
        try:
            encode_command(command, payload or {})
        except ValueError as exc:
            session.delete(row)
            raise MDMError("command is not implemented by native device transport", 409) from exc
        from .native_mdm import schedule_push
        schedule_push(session, tenant_id=tenant_id, enrollment_pk=enrollment_pk)
    if adapter is not None and native is None:
        row.status = "delivered"
        try:
            result = adapter.deliver_command(
                enrollment.enrollment_id, command, payload or {})
        except Exception as exc:  # adapter failure is not a device answer
            row.status = "queued"
            row.result_detail = (
                f"delivery failed: {sanitize_adapter_error(exc)}")
            session.flush()
            return row
        row.status = result.status
        row.result_detail = ("adapter response recorded: " + str(result.status))
        if result.status == "acknowledged":
            row.applied = True
        session.flush()
    session.add(AuditEvent(tenant_id=tenant_id, actor_user_id=actor_user_id,
                           action="mdm.command.issue",
                           detail=f"{command} -> enrollment {enrollment.id}"))
    return row


def sanitize_adapter_error(exc: Exception) -> str:
    """Adapter exception text can carry credentials (API keys in URLs
    or headers, bearer tokens). What is stored in the command ledger is
    the exception class plus an allowlisted failure category. Raw
    exception text is withheld, never stored or displayed."""
    # Free-form adapter messages can embed PEMs, URLs or unknown secret
    # formats. Deny by default rather than guessing every secret syntax.
    message = str(exc).lower()
    category = next((word for word in ("unreachable", "timeout", "refused", "tls")
                     if word in message), "unclassified")
    return (f"{exc.__class__.__name__}: adapter delivery failed "
            f"({category}; details withheld)")



def list_commands(session: Session, tenant_id: int,
                  enrollment_pk: int | None = None) -> list[MDMCommand]:
    stmt = select(MDMCommand).where(MDMCommand.tenant_id == tenant_id)
    if enrollment_pk is not None:
        get_enrollment(session, tenant_id, enrollment_pk)
        stmt = stmt.where(MDMCommand.enrollment_pk == enrollment_pk)
    return list(session.scalars(stmt.order_by(MDMCommand.id)))


def get_command(session: Session, tenant_id: int,
                command_id: int) -> MDMCommand:
    row = session.get(MDMCommand, command_id)
    if row is None or row.tenant_id != tenant_id:
        raise MDMError("command not found", 404)
    return row

def mark_supervision_verified(session: Session, tenant_id: int,
                              enrollment_pk: int,
                              supervised: bool) -> MDMEnrollment:
    """Set device-REPORTED supervision. This is the only path that may
    set supervision_verified, and it is for device check-in data (via a
    NanoMDM enrollment-info sync), never for API input. A pending
    enrollment has never reported anything, so verifying one is an
    error."""
    row = get_enrollment(session, tenant_id, enrollment_pk)
    if row.state == "pending":
        raise MDMError(
            "cannot verify supervision on a pending enrollment: "
            "the device has never checked in", 409)
    row.supervision_verified = supervised
    session.flush()
    return row
