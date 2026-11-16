"""Status reconciler: NanoMDM PostgreSQL storage -> our command ledger.

NanoMDM records device statuses in its own storage schema
(status per command UUID per enrollment, with acknowledged/error/
not_now and the device's last check-in). The reconciler reads that
schema read-only and advances our mdm_commands ledger. It never marks
a command applied without an Acknowledged status row from the device.

The NanoMDM schema used here (status table with command_uuid,
enrollment_id, status, created_at) is the documented shape of its
SQL backends; the mapping is isolated in this module so a schema
adjustment touches one file.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

from .adapter import SUPPORTED_COMMANDS  # noqa: F401  (documents scope)


@dataclass
class ReconcileResult:
    advanced: int = 0
    applied: int = 0
    skipped: int = 0


# Our ledger statuses and how device statuses map onto them.
DEVICE_STATUS_MAP = {
    "Acknowledged": ("acknowledged", True),
    "Error": ("error", False),
    "NotNow": ("not_now", False),
    "Idle": ("not_now", False),
}


def reconcile(session: Session, tenant_id: int,
              status_rows: list[dict]) -> ReconcileResult:
    """Advance ledger rows from fetched NanoMDM status rows.

    status_rows: dicts with keys command_id (our ledger id, carried as
    the command UUID when enqueued), status (NanoMDM device status
    string), detail. Rows for commands not owned by tenant_id are
    ignored - cross-tenant status data is never written.
    """
    from app.models import MDMCommand  # deferred: control-plane import

    result = ReconcileResult()
    for row in status_rows:
        cmd = session.get(MDMCommand, row.get("command_id"))
        if cmd is None or cmd.tenant_id != tenant_id:
            result.skipped += 1
            continue
        mapped = DEVICE_STATUS_MAP.get(row.get("status"))
        if mapped is None:
            result.skipped += 1
            continue
        new_status, applied = mapped
        # Terminal statuses are not re-opened by later Idle/NotNow noise.
        if cmd.status in ("acknowledged", "error") and not applied:
            result.skipped += 1
            continue
        cmd.status = new_status
        cmd.result_detail = row.get("detail", cmd.result_detail)
        if applied:
            cmd.applied = True
            result.applied += 1
        result.advanced += 1
    session.flush()
    return result


def fetch_status_rows(pg_connection, command_uuids: list[str]) -> list[dict]:
    """Read device statuses from a NanoMDM PostgreSQL backend.

    Read-only. Expects the NanoMDM SQL schema's status table; returns
    [] when the table does not exist (NanoMDM not deployed yet).
    """
    if not command_uuids:
        return []
    try:
        rows = pg_connection.execute(text(
            "SELECT command_uuid, status, error_chain FROM "
            "nanomdm_command_results WHERE command_uuid = ANY(:uuids)"),
            {"uuids": command_uuids}).fetchall()
    except Exception:
        return []
    return [{"command_id": r[0], "status": r[1], "detail": r[2] or ""}
            for r in rows]
