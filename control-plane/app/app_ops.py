"""Application-management operations (spec Part 10: Applications).

Wires the stored per-device app policy to the MDM command lifecycle:
applying a policy queues an InstallProfile command carrying the
com.apple.applicationaccess profile, un-applying queues RemoveProfile
against the recorded identifier; install/remove/query actions queue
the matching MDM command. Everything goes through mdm_ops.issue_command
so tenant scoping, the supported-command allowlist, audit and the
no-destructive-commands rule all apply unchanged.
"""

from __future__ import annotations

import json
import sys
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (AuditEvent, Device, DeviceAppPolicy,
                     MDMEnrollment)

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from mdm import app_management  # noqa: E402

from . import mdm_ops  # noqa: E402


class AppOpsError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _device(session: Session, tenant_id: int, device_id: int) -> Device:
    row = session.get(Device, device_id)
    if row is None or row.tenant_id != tenant_id:
        raise AppOpsError("device not found", 404)
    return row


def _active_enrollment(session: Session, tenant_id: int,
                       device_id: int) -> MDMEnrollment:
    row = session.scalars(
        select(MDMEnrollment).where(
            MDMEnrollment.tenant_id == tenant_id,
            MDMEnrollment.device_id == device_id,
            MDMEnrollment.state != "removed")
        .order_by(MDMEnrollment.id.desc())).first()
    if row is None:
        raise AppOpsError(
            "device has no active MDM enrollment; enroll it before "
            "application commands can be delivered", 409)
    return row


def _policy_row(session: Session, tenant_id: int,
                device_id: int) -> DeviceAppPolicy | None:
    return session.scalars(
        select(DeviceAppPolicy).where(
            DeviceAppPolicy.tenant_id == tenant_id,
            DeviceAppPolicy.device_id == device_id)).first()


def get_policy(session: Session, tenant_id: int,
               device_id: int) -> dict:
    _device(session, tenant_id, device_id)
    row = _policy_row(session, tenant_id, device_id)
    if row is None:
        return {"mode": "blocklist", "bundle_ids": [], "saved": False,
                "applied": False, "shield_active": False}
    return {"mode": row.mode, "bundle_ids": json.loads(row.bundle_ids),
            "saved": True, "applied": row.profile_identifier is not None,
            "shield_active": bool(row.shield_active),
            "updated_at": row.updated_at.isoformat()}


def put_policy(session: Session, tenant_id: int, device_id: int,
               mode: str, bundle_ids, actor_user_id: int,
               adapter=None) -> dict:
    """Save the policy intent; if it is APPLIED, re-apply immediately.

    Consistency rule (review finding): while a policy is applied
    (profile_identifier set), the DDM declaration follows the stored
    contents at the device's next sync - so a plain save would leave
    the classic InstallProfile channel serving the OLD contents until
    someone pressed Apply again, with nothing in the API admitting
    the split. Instead, saving on an applied policy immediately
    queues a replacement InstallProfile carrying the NEW contents
    under the same stable identifier. Enforcement never gaps: the
    on-device profile is replaced in place, never removed first, and
    removal stays exclusive to Unapply. If the device has no active
    enrollment the save still succeeds and reports reapplied=False -
    nothing can be queued, and the API says so instead of silently
    claiming "saved" while the device keeps the old profile.
    """
    _device(session, tenant_id, device_id)
    try:
        ids = app_management.validate_bundle_ids(bundle_ids)
        if mode not in app_management.APP_MODES:
            raise AppOpsError(
                f"mode must be one of {app_management.APP_MODES}", 400)
    except app_management.AppManagementError as exc:
        raise AppOpsError(str(exc), 400) from exc
    row = _policy_row(session, tenant_id, device_id)
    if row is None:
        row = DeviceAppPolicy(tenant_id=tenant_id, device_id=device_id,
                              mode=mode, bundle_ids=json.dumps(ids),
                              actor_user_id=actor_user_id)
        session.add(row)
    else:
        row.mode = mode
        row.bundle_ids = json.dumps(ids)
        row.actor_user_id = actor_user_id
    session.flush()
    session.add(AuditEvent(
        tenant_id=tenant_id, actor_user_id=actor_user_id,
        action="app_policy.update",
        detail=f"device {device_id} mode={mode} apps={len(ids)}"))
    result = {"mode": mode, "bundle_ids": ids, "saved": True,
              "reapplied": False}
    if row.profile_identifier:
        try:
            command = apply_policy(session, tenant_id, device_id,
                                   actor_user_id, adapter=adapter)
        except AppOpsError as exc:
            if exc.status != 409:
                raise
            result["reapply_reason"] = str(exc)
        else:
            result["reapplied"] = True
            result["command_id"] = command.id
    return result


def set_shield_active(session: Session, tenant_id: int, device_id: int,
                      active: bool, actor_id: int) -> dict:
    """Remote activation gate for the PERSONAL (unsupervised) shield.

    Gates only whether the device's own locally consented Screen Time
    selection is activated. It cannot choose, add or widen which apps
    are shielded - that selection is opaque and device-local
    (FamilyControls), and the device-side code ignores this flag for
    anything except activating/pausing the stored selection. Local
    consent and revocation always win: a device with no stored
    selection shows nothing, and removing the selection locally makes
    this flag inert until the user picks again.
    """
    _device(session, tenant_id, device_id)
    row = _policy_row(session, tenant_id, device_id)
    if row is None:
        row = DeviceAppPolicy(tenant_id=tenant_id, device_id=device_id,
                              mode="blocklist", bundle_ids="[]")
        session.add(row)
        session.flush()
    row.shield_active = active
    session.flush()
    session.add(AuditEvent(
        tenant_id=tenant_id, actor_user_id=actor_id,
        action="app_policy.shield_gate",
        detail=f"device {device_id} active={active}"))
    return {"shield_active": active}


def apply_policy(session: Session, tenant_id: int, device_id: int,
                 actor_user_id: int, adapter=None):
    """Queue an InstallProfile command carrying the current policy.

    The profile uses the stable PROFILE_IDENTIFIER, so re-applying
    (including a blocklist<->allowlist mode switch) replaces the
    on-device profile instead of stacking a second one. If this policy
    was last queued under a different identifier (the legacy per-mode
    identifiers), a RemoveProfile for the old identifier is queued
    first so the stale restrictions are actually lifted (review
    finding A1). The identifier last queued is recorded on the policy
    row only after the install command is queued; a queueing failure
    leaves the record unchanged. Recording it also starts DDM serving
    of the app-settings declaration to syncing devices.
    """
    _device(session, tenant_id, device_id)
    row = _policy_row(session, tenant_id, device_id)
    if row is None:
        raise AppOpsError(
            "no saved application policy for this device", 409)
    enrollment = _active_enrollment(session, tenant_id, device_id)
    stable = app_management.PROFILE_IDENTIFIER
    try:
        if row.profile_identifier and row.profile_identifier != stable:
            mdm_ops.issue_command(
                session, tenant_id, enrollment.id, "RemoveProfile",
                {"Identifier": row.profile_identifier},
                actor_user_id, adapter=adapter)
        profile = app_management.application_access_profile(
            row.mode, json.loads(row.bundle_ids))
        result = mdm_ops.issue_command(
            session, tenant_id, enrollment.id, "InstallProfile",
            {"profile": profile}, actor_user_id, adapter=adapter)
    except mdm_ops.MDMError as exc:
        raise AppOpsError(str(exc), exc.status) from exc
    row.profile_identifier = stable
    session.flush()
    return result


def unapply_policy(session: Session, tenant_id: int, device_id: int,
                   actor_user_id: int, adapter=None):
    """Queue a RemoveProfile command lifting the applied policy.

    This is the only path that removes the on-device applicationaccess
    restrictions; without it a saved policy can never be taken off the
    device (review finding A1). The removal targets the exact
    identifier recorded when the policy was last applied. The stored
    policy intent (mode and bundle ids) is kept so it can be
    re-applied; profile_identifier is cleared to mark it not applied.
    Clearing it also stops DDM serving of the app-settings declaration
    (ddm_ops.configurations), so declaratively managed devices withdraw
    that configuration at their next sync. Neither the RemoveProfile
    result nor the declaration withdrawal is confirmed until the
    device acts: this queues removal, it does not prove it.
    """
    _device(session, tenant_id, device_id)
    row = _policy_row(session, tenant_id, device_id)
    if row is None or not row.profile_identifier:
        raise AppOpsError(
            "no applied application policy for this device", 409)
    enrollment = _active_enrollment(session, tenant_id, device_id)
    try:
        result = mdm_ops.issue_command(
            session, tenant_id, enrollment.id, "RemoveProfile",
            {"Identifier": row.profile_identifier},
            actor_user_id, adapter=adapter)
    except mdm_ops.MDMError as exc:
        raise AppOpsError(str(exc), exc.status) from exc
    row.profile_identifier = None
    session.flush()
    session.add(AuditEvent(
        tenant_id=tenant_id, actor_user_id=actor_user_id,
        action="app_policy.unapply",
        detail=f"device {device_id} profile removed"))
    return result


_APP_COMMANDS = {
    "install": "InstallApplication",
    "remove": "RemoveApplication",
    "list": "InstalledApplicationList",
    "managed-list": "ManagedApplicationList",
}


def queue_app_command(session: Session, tenant_id: int, device_id: int,
                      action: str, actor_user_id: int,
                      itunes_store_id=None, bundle_id=None,
                      configuration=None, adapter=None):
    device = _device(session, tenant_id, device_id)
    if action not in _APP_COMMANDS:
        raise AppOpsError(
            f"action must be one of {sorted(_APP_COMMANDS)}", 400)
    enrollment = _active_enrollment(session, tenant_id, device_id)
    try:
        if action == "install":
            # The KosherGuard app's managed configuration
            # (com.apple.configuration.managed) needs the device record
            # id, which only this server knows: fill it when the
            # operator did not. controlPlaneBaseURL is never invented -
            # no live value is baked in; the operator supplies it.
            if configuration is not None:
                configuration = dict(configuration)
                configuration.setdefault("deviceID", device.id)
            payload = app_management.install_application_command(
                itunes_store_id=itunes_store_id, configuration=configuration)
        elif action == "remove":
            if not bundle_id:
                raise AppOpsError("remove requires bundle_id", 400)
            payload = app_management.remove_application_command(bundle_id)
        elif action == "managed-list":
            payload = app_management.managed_application_list_command()
        else:
            payload = {}
    except app_management.AppManagementError as exc:
        raise AppOpsError(str(exc), 400) from exc
    try:
        return mdm_ops.issue_command(
            session, tenant_id, enrollment.id, _APP_COMMANDS[action],
            payload, actor_user_id, adapter=adapter)
    except mdm_ops.MDMError as exc:
        raise AppOpsError(str(exc), exc.status) from exc
