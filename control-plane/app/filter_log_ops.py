"""Filtering-decision ingestion (spec Part 10: Filtering logs).

Edge services (proxy-edge today) POST the decisions they actually made,
authenticated with the device's scoped credential (scope "proxy"; the
control plane mints these and owns the HMAC key, so verification here
uses the same verifier the edges use). The tenant and device binding
come from the verified token - never from the request body - so an edge
can only write into its own tenant's log.
"""

from __future__ import annotations

import importlib.util
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Device, FilterDecision

MAX_BATCH = 100
ALLOWED_ACTIONS = {"allow", "block"}
ALLOWED_SOURCES = {"proxy"}


class FilterLogError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _device_auth():
    """Load url-filter-server's device_auth by file path (the control
    plane's own package is also named "app")."""
    path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..",
        "url-filter-server", "app", "device_auth.py"))
    spec = importlib.util.spec_from_file_location(
        "kg_device_auth_logs", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def verify_edge_token(settings, authorization: str | None) -> dict:
    if not settings.device_token_key:
        raise FilterLogError(
            "device credentials are not configured on this server", 503)
    if not authorization or not authorization.startswith("Bearer "):
        raise FilterLogError("missing bearer token", 401)
    da = _device_auth()
    try:
        return da.verify_token(settings.device_token_key.encode(),
                               authorization[len("Bearer "):],
                               required_scope="proxy")
    except da.TokenError as exc:
        raise FilterLogError(f"invalid credential: {exc}", 401) from exc


def record_decisions(session: Session, claims: dict,
                     decisions) -> int:
    if not isinstance(decisions, list) or not decisions:
        raise FilterLogError("decisions must be a non-empty list")
    if len(decisions) > MAX_BATCH:
        raise FilterLogError(
            f"batch too large (max {MAX_BATCH})", 400)
    tenant_id = int(claims["tenant_id"])
    device_pk = None
    if claims.get("device_id") is not None:
        dev = session.get(Device, int(claims["device_id"]))
        if dev is None or dev.tenant_id != tenant_id:
            raise FilterLogError("credential binds an unknown device", 403)
        device_pk = dev.id
    accepted = 0
    for raw in decisions:
        if not isinstance(raw, dict):
            raise FilterLogError("each decision must be an object")
        domain = str(raw.get("domain") or raw.get("host") or "")[:255]
        action = str(raw.get("action") or "")
        source = str(raw.get("source") or "proxy")
        if not domain:
            raise FilterLogError("decision missing domain")
        if action not in ALLOWED_ACTIONS:
            raise FilterLogError(f"unsupported action: {action!r}")
        if source not in ALLOWED_SOURCES:
            raise FilterLogError(f"unsupported source: {source!r}")
        session.add(FilterDecision(
            tenant_id=tenant_id, device_id=device_pk, source=source,
            domain=domain, action=action,
            rule=str(raw.get("rule") or "")[:120],
            reason=str(raw.get("reason") or "")[:300]))
        accepted += 1
    session.flush()
    return accepted


def recent_decisions(session: Session, tenant_id: int,
                     limit: int = 200) -> list[FilterDecision]:
    return list(session.scalars(
        select(FilterDecision)
        .where(FilterDecision.tenant_id == tenant_id)
        .order_by(FilterDecision.id.desc())
        .limit(limit)))
