"""Declarative Device Management (DDM) serving (spec Part 10 gap closure).

The verified delivery route, from primary sources fetched 2026-11-16:

- NanoMDM operations guide (main branch, docs/operations-guide.md,
  "-dm" flag): NanoMDM v0.3.0+ forwards a device's DeclarativeManagement
  check-in to an external HTTP "DM server" - it appends the endpoint
  name ("tokens", "declaration-items", "declaration/<type>/<id>",
  "status") to the -dm base URL and adds the enrollment ID as the
  X-Enrollment-ID header. Optional HMAC: -dm-send-hmac-key makes NanoMDM
  sign each request body with SHA-256 HMAC in the X-Hmac-Signature
  header (Base64); -dm-recv-hmac-key verifies ours.
- KMFDDM (github.com/jessepeterson/kmfddm, cloned 2026-11-16) is the
  reference implementation of that DM server; its ddm/ package cites
  the matching Apple documentation URLs for each message shape:
  DeclarationItems (declarationitemsresponse), SynchronizationTokens
  (tokensresponse), Declaration (declarationbase.yaml), StatusReport.
  Endpoint registration in cmd/kmfddm/main.go: GET /declaration-items,
  GET /tokens, GET /declaration/:type/:id, PUT /status.

So THIS control plane is the DM server: NanoMDM is started with
-dm https://<control-plane>/api/ddm/ and the device's DDM traffic
reaches the routes below directly. No adapter delivery step exists for
declarations; the adapter's role is only to enqueue the classic
DeclarativeManagement command that activates DDM on the device.

Trust model: X-Enrollment-ID is an IDENTIFIER, not authentication -
any caller who learns an enrollment ID could otherwise read that
device's declarations or forge status reports. The authenticated
boundary is the shared HMAC key, matching NanoMDM's -dm-send-hmac-key:
it authenticates the forwarding NanoMDM peer (the device itself
authenticates to NanoMDM through the MDM protocol). Therefore
KG_DDM_HMAC_KEY is REQUIRED: without it every /api/ddm/* route answers
503 "not configured", fail-closed, exactly like scoped-credential
issuance without KG_DEVICE_TOKEN_KEY. No protection is inferred from
network topology or intended deployment.
Device behavior remains BUILT-UNVERIFIED until the Part 17
device-testing phase; a served declaration is not an applied
declaration, and receipt of a status report is not proof of
application either - see record_status for what a report can show.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (DDMStatusReport, DeviceAppPolicy, MDMEnrollment,
                     utcnow)


class DDMError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def verify_hmac(key: str | None, header: str | None, body: bytes) -> None:
    """Fail-closed HMAC, matching NanoMDM -dm-send-hmac-key semantics.

    No key configured -> serving is off (503), because the HMAC is the
    only authentication on these endpoints. Key configured -> every
    request must carry a valid X-Hmac-Signature (GETs sign an empty
    body, which is what NanoMDM sends)."""
    if not key:
        raise DDMError("DDM serving not configured", 503)
    expected = base64.b64encode(
        hmac.new(key.encode(), body, hashlib.sha256).digest()).decode()
    if not header or not hmac.compare_digest(expected, header):
        raise DDMError("missing or invalid X-Hmac-Signature", 401)


def resolve_enrollment(session: Session, enrollment_id: str | None,
                       ) -> MDMEnrollment:
    if not enrollment_id:
        raise DDMError("missing X-Enrollment-ID", 400)
    row = session.scalar(select(MDMEnrollment).where(
        MDMEnrollment.enrollment_id == enrollment_id))
    if row is None:
        raise DDMError("unknown enrollment", 404)
    return row


def _app_policy(session: Session, enrollment: MDMEnrollment,
                ) -> DeviceAppPolicy | None:
    return session.scalar(select(DeviceAppPolicy).where(
        DeviceAppPolicy.tenant_id == enrollment.tenant_id,
        DeviceAppPolicy.device_id == enrollment.device_id))


def configurations(session: Session, enrollment: MDMEnrollment) -> list[dict]:
    """The configuration declarations this enrollment should sync."""
    import os
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..", "mdm")))
    import app_management  # noqa: E402

    policy = _app_policy(session, enrollment)
    if policy is None:
        return []
    token = hashlib.sha256(
        f"{policy.id}:{policy.mode}:{policy.bundle_ids}:{policy.updated_at}"
        .encode()).hexdigest()[:16]
    return [app_management.app_settings_declaration(
        policy.mode, json.loads(policy.bundle_ids), server_token=token)]


def declaration_items(session: Session, enrollment: MDMEnrollment) -> dict:
    """DeclarationItemsResponse shape (KMFDDM ddm/items.go)."""
    configs = configurations(session, enrollment)
    manifest = [{"Identifier": c["Identifier"],
                 "ServerToken": c["ServerToken"]} for c in configs]
    token = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    return {
        "Declarations": {
            "Activations": [],
            "Assets": [],
            "Configurations": manifest,
            "Management": [],
        },
        "DeclarationsToken": token,
    }


def tokens(session: Session, enrollment: MDMEnrollment) -> dict:
    """TokensResponse shape (KMFDDM ddm/token.go)."""
    items = declaration_items(session, enrollment)
    return {"SyncTokens": {
        "DeclarationsToken": items["DeclarationsToken"],
        "Timestamp": utcnow().isoformat()}}


def get_declaration(session: Session, enrollment: MDMEnrollment,
                    dtype: str, identifier: str) -> dict:
    if dtype != "configuration":
        raise DDMError("unsupported declaration type", 404)
    for c in configurations(session, enrollment):
        if c["Identifier"] == identifier:
            return c
    raise DDMError("declaration not found", 404)


def declaration_states(parsed: dict) -> dict:
    """Per-declaration application state from a status report.

    Verified shape (apple/device-management declarative/status +
    statusreport.yaml, as generated in KMFDDM ddm/status/status.go,
    cloned 2026-11-16): StatusItems.management.declarations.
    configurations[] entries carry identifier, server-token, active
    (bool), valid ("unknown"|"invalid"|"valid") and optional reasons
    (code/description/details). Only an entry matching a SERVED
    declaration's identifier AND server-token with active=true and
    valid="valid" evidences that declaration applied. Anything else -
    including a report with no declarations section at all - is
    receipt of a report, not application."""
    items = (parsed.get("StatusItems") or {}).get("management") or {}
    decls = (items.get("declarations") or {}).get("configurations") or []
    out = {}
    for d in decls:
        if not isinstance(d, dict) or "identifier" not in d:
            continue
        out[d["identifier"]] = {
            "server_token": d.get("server-token"),
            "active": d.get("active") is True,
            "valid": d.get("valid"),
            "reasons": d.get("reasons"),
        }
    return out


def record_status(session: Session, enrollment: MDMEnrollment,
                  body: bytes) -> None:
    """Store a device status report verbatim plus the extracted
    per-declaration states. RECEIPT ONLY: a stored report proves the
    enrollment sent a well-formed report, never that any declaration
    applied - that conclusion needs declaration_states to match a
    served declaration's identifier + server-token with active and
    valid, checked against what we actually served."""
    try:
        parsed = json.loads(body.decode())
    except (ValueError, UnicodeDecodeError):
        raise DDMError("status report must be JSON", 400)
    if not isinstance(parsed, dict):
        raise DDMError("status report must be a JSON object", 400)
    session.add(DDMStatusReport(
        tenant_id=enrollment.tenant_id,
        enrollment_id=enrollment.enrollment_id,
        body=json.dumps(parsed, sort_keys=True),
        declaration_states=json.dumps(
            declaration_states(parsed), sort_keys=True)))
    enrollment.last_seen_at = utcnow()
