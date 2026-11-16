"""Application-management operations (spec Part 10: Applications).

Wires the stored per-device app policy to the MDM command lifecycle:
applying a policy queues an InstallProfile command carrying the
com.apple.applicationaccess profile; install/remove/query actions queue
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


def get_policy(session: Session, tenant_id: int,
               device_id: int) -> dict:
    _device(session, tenant_id, device_id)
    row = session.scalars(
        select(DeviceAppPolicy).where(
            DeviceAppPolicy.tenant_id == tenant_id,
            DeviceAppPolicy.device_id == device_id)).first()
    if row is None:
        return {"mode": "blocklist", "bundle_ids": [], "saved": False}
    return {"mode": row.mode, "bundle_ids": json.loads(row.bundle_ids),
            "saved": True, "updated_at": row.updated_at.isoformat()}


def put_policy(session: Session, tenant_id: int, device_id: int,
               mode: str, bundle_ids, actor_user_id: int) -> dict:
    _device(session, tenant_id, device_id)
    try:
        ids = app_management.validate_bundle_ids(bundle_ids)
        if mode not in app_management.APP_MODES:
            raise AppOpsError(
                f"mode must be one of {app_management.APP_MODES}", 400)
    except app_management.AppManagementError as exc:
        raise AppOpsError(str(exc), 400) from exc
    row = session.scalars(
        select(DeviceAppPolicy).where(
            DeviceAppPolicy.tenant_id == tenant_id,
            DeviceAppPolicy.device_id == device_id)).first()
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
    return {"mode": mode, "bundle_ids": ids, "saved": True}


def apply_policy(session: Session, tenant_id: int, device_id: int,
                 actor_user_id: int, adapter=None):
    """Queue an InstallProfile command carrying the current policy."""
    policy = get_policy(session, tenant_id, device_id)
    if not policy["saved"]:
        raise AppOpsError(
            "no saved application policy for this device", 409)
    enrollment = _active_enrollment(session, tenant_id, device_id)
    profile = app_management.application_access_profile(
        policy["mode"], policy["bundle_ids"])
    try:
        return mdm_ops.issue_command(
            session, tenant_id, enrollment.id, "InstallProfile",
            {"profile": profile}, actor_user_id, adapter=adapter)
    except mdm_ops.MDMError as exc:
        raise AppOpsError(str(exc), exc.status) from exc


_APP_COMMANDS = {
    "install": "InstallApplication",
    "remove": "RemoveApplication",
    "list": "InstalledApplicationList",
    "managed-list": "ManagedApplicationList",
}


def queue_app_command(session: Session, tenant_id: int, device_id: int,
                      action: str, actor_user_id: int,
                      itunes_store_id=None, bundle_id=None, adapter=None):
    _device(session, tenant_id, device_id)
    if action not in _APP_COMMANDS:
        raise AppOpsError(
            f"action must be one of {sorted(_APP_COMMANDS)}", 400)
    enrollment = _active_enrollment(session, tenant_id, device_id)
    try:
        if action == "install":
            payload = app_management.install_application_command(
                itunes_store_id=itunes_store_id)
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
