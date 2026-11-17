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

Trust model - the actual trusted chain, link by link:

1. Device -> NanoMDM: the device authenticates to NanoMDM through the
   MDM protocol (client identity from the enrollment profile). Only a
   device that completed MDM enrollment can send DeclarativeManagement
   check-ins at all, so NanoMDM only forwards DDM traffic for devices
   it has authenticated. This link is NanoMDM's responsibility; the
   control plane never talks to the device directly.
2. NanoMDM -> control plane: the shared HMAC key
   (-dm-send-hmac-key / KG_DDM_HMAC_KEY) authenticates the FORWARDING
   PEER on every request. It proves the request came through the
   trusted NanoMDM, nothing more.
3. Authorization: X-Enrollment-ID is an IDENTIFIER, never an
   authenticator. A request is only authorized when it comes through
   the HMAC-authenticated peer: under the operations guide NanoMDM
   forwards device check-in traffic only for enrollments it
   authenticated via the MDM protocol, so an authenticated DDM
   request is itself the device check-in evidence. A 'pending'
   placeholder (created by a guardian before any device checked in)
   is ACTIVATED by that first authenticated contact (audited) -
   enrollment ID alone, without the peer's HMAC, authorizes NOTHING.
   The explicit sync route POST /api/mdm/enrollment-checkin (same
   HMAC peer auth) is the equivalent out-of-band activation path
   (e.g. a deployment sync of NanoMDM's stored Authenticate data).
   NOTE on supervision: the check-in sync records enrollment only.
   Supervision is device-reported state (Apple: the Authenticate /
   DeviceInformation data NanoMDM stores); no caller-claimed flag on
   any route may set supervision_verified - only
   mdm_ops.mark_supervision_verified from device check-in data, and
   that sync is not yet wired to a verified device channel, so
   supervision_verified stays false until one exists.

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

from .models import (DDMStatusReport, Device, DeviceAppPolicy, MDMEnrollment,
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


def resolve_or_bind(session: Session, enrollment_id: str | None,
                    ) -> tuple[MDMEnrollment, bool]:
    """Resolve X-Enrollment-ID to an enrollment record.

    NanoMDM's device-channel enrollment ID IS the device UDID
    (operations guide), and local records start as 'pending-*'
    placeholders, so a real first check-in never matches by ID. The
    association path: when no record has this ID, look for a pending
    enrollment whose device_udid (recorded at enrollment creation from
    the device record, never from this caller) equals it. A unique
    match is bound to the real ID and returned with bound=True;
    ambiguity or no match is a refusal. Callers must have
    authenticated the peer via verify_hmac first, so the UDID arrives
    only from a device NanoMDM authenticated via the MDM protocol."""
    if not enrollment_id:
        raise DDMError("missing X-Enrollment-ID", 400)
    enrollment = session.scalar(select(MDMEnrollment).where(
        MDMEnrollment.enrollment_id == enrollment_id))
    if enrollment is not None:
        return enrollment, False
    candidates = session.scalars(select(MDMEnrollment).where(
        MDMEnrollment.device_udid == enrollment_id,
        MDMEnrollment.state == "pending")).all()
    if len(candidates) > 1:
        raise DDMError(
            "multiple pending enrollments match this device; "
            "bind explicitly via the enrollment-checkin sync", 409)
    if not candidates:
        raise DDMError("unknown enrollment", 404)
    enrollment = candidates[0]
    from .db import lock_tenant
    lock_tenant(session, enrollment.tenant_id)
    session.refresh(enrollment)
    if enrollment.state != "pending":
        raise DDMError("enrollment no longer pending", 409)
    enrollment.enrollment_id = enrollment_id
    return enrollment, True


# States that authorize DDM serving. 'pending' is a local placeholder
# created before any device check-in; it must never authorize.
DDM_AUTHORIZED_STATES = ("enrolled", "active")


def ensure_active(session: Session, enrollment: MDMEnrollment) -> bool:
    """Authorize DDM serving for this enrollment.

    The HMAC check (callers run verify_hmac first) authenticates the
    forwarding peer; NanoMDM only forwards check-in traffic for
    enrollments it authenticated via the MDM protocol, so this first
    authenticated contact IS the check-in evidence: a 'pending'
    placeholder is activated here (returns True when it was). Any
    other non-active state (e.g. revoked) is refused. Enrollment ID
    alone, without the peer's HMAC, never reaches this point."""
    from .db import lock_tenant
    lock_tenant(session, enrollment.tenant_id)
    session.refresh(enrollment)
    device = session.get(Device, enrollment.device_id)
    if device is None or device.tenant_id != enrollment.tenant_id or device.state != "active":
        raise DDMError(
            "device is offboarded; offboarding is terminal for DDM "
            "serving and is never silently reactivated", 403)
    if enrollment.state == "pending":
        enrollment.state = "enrolled"
        enrollment.last_seen_at = utcnow()
        session.flush()
        return True
    if enrollment.state not in DDM_AUTHORIZED_STATES:
        raise DDMError(
            f"enrollment is not active (state {enrollment.state!r}); "
            "only a device NanoMDM has confirmed via check-in may "
            "sync declarations or report status", 403)
    return False


def confirm_checkin(session: Session, enrollment_id: str | None,
                    *, nanomdm_id: str | None = None) -> MDMEnrollment:
    """Record that the NanoMDM peer confirmed a real device check-in.

    Transitions a pending placeholder to 'enrolled'. When nanomdm_id
    is given it BINDS the record to NanoMDM's actual enrollment
    identifier (the operations guide: NanoMDM normalizes the device
    channel's UDID / User Enrollment's EnrollmentID into its
    enrollment ID, which is what it forwards as X-Enrollment-ID).
    Without binding, DDM traffic carrying the real ID can never match
    the local 'pending-*' placeholder. Binding to an ID already used
    by another enrollment is refused. Idempotent: an already-active
    enrollment keeps its state and its ID.

    Callers must have authenticated the NanoMDM peer via verify_hmac
    first - this route is the control plane's record of the
    device->NanoMDM MDM authentication, not a substitute for it. It
    records ENROLLMENT ONLY: supervision is never accepted from this
    caller (see the module docstring)."""
    enrollment = resolve_enrollment(session, enrollment_id)
    from .db import lock_tenant
    lock_tenant(session, enrollment.tenant_id)
    session.refresh(enrollment)
    device = session.get(Device, enrollment.device_id)
    if device is None or device.tenant_id != enrollment.tenant_id or device.state != "active":
        raise DDMError(
            "device is offboarded; a check-in can never reactivate it",
            409)
    if enrollment.state == "pending":
        if nanomdm_id:
            clash = session.scalar(select(MDMEnrollment).where(
                MDMEnrollment.enrollment_id == nanomdm_id,
                MDMEnrollment.id != enrollment.id))
            if clash is not None:
                raise DDMError(
                    "nanomdm_id already bound to another enrollment",
                    409)
            enrollment.enrollment_id = nanomdm_id
        enrollment.state = "enrolled"
    if enrollment.state not in DDM_AUTHORIZED_STATES:
        raise DDMError(
            f"cannot confirm check-in for enrollment in state "
            f"{enrollment.state!r}", 409)
    enrollment.last_seen_at = utcnow()
    session.flush()
    return enrollment


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


_DECL_FIELDS = ("identifier", "server-token", "active", "valid",
                "reasons")


def sanitize_status_report(parsed: dict) -> dict:
    """Minimize a status report to the receipt the platform actually
    needs (Answer 31): the per-declaration application states. Every
    other key - including any UNSOLICITED location, personal-app or
    other sensitive content a device or impersonator puts in the
    payload - is dropped BEFORE persistence, so the inventory never
    stores data it must not collect."""
    out: dict = {}
    items = parsed.get("StatusItems")
    mgmt = items.get("management") if isinstance(items, dict) else None
    decls = (mgmt or {}).get("declarations") if isinstance(
        mgmt, dict) else None
    configs = decls.get("configurations") if isinstance(
        decls, dict) else None
    if isinstance(configs, list):
        kept = []
        for d in configs:
            if isinstance(d, dict):
                kept.append({k: d[k] for k in _DECL_FIELDS if k in d})
        out = {"StatusItems": {"management": {"declarations":
                                              {"configurations": kept}}}}
    return out


def record_status(session: Session, enrollment: MDMEnrollment,
                  body: bytes) -> None:
    """Store a MINIMIZED device status receipt plus the extracted
    per-declaration states. RECEIPT ONLY: a stored report proves the
    enrollment sent a well-formed report, never that any declaration
    applied - that conclusion needs declaration_states to match a
    served declaration's identifier + server-token with active and
    valid, checked against what we actually served. Unsolicited
    payload fields (location, personal-app data, anything outside the
    declaration receipt) are dropped before persistence."""
    try:
        parsed = json.loads(body.decode())
    except (ValueError, UnicodeDecodeError):
        raise DDMError("status report must be JSON", 400)
    if not isinstance(parsed, dict):
        raise DDMError("status report must be a JSON object", 400)
    minimized = sanitize_status_report(parsed)
    session.add(DDMStatusReport(
        tenant_id=enrollment.tenant_id,
        enrollment_id=enrollment.enrollment_id,
        body=json.dumps(minimized, sort_keys=True),
        declaration_states=json.dumps(
            declaration_states(minimized), sort_keys=True)))
    enrollment.last_seen_at = utcnow()
