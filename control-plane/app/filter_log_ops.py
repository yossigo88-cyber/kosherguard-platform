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

from sqlalchemy import select, delete, or_
from sqlalchemy.orm import Session

from .db import lock_tenant
from .models import Device, FilterDecision, IssuedCredential, Tenant
from datetime import datetime, timedelta, timezone
import re

MAX_BATCH = 100
ALLOWED_ACTIONS = {"allow", "block"}
ALLOWED_SOURCES = {"proxy", "dns"}
# A scoped credential may only report decisions for its own source:
# proxy tokens write "proxy", doh tokens write "dns".
SCOPE_SOURCES = {"proxy": "proxy", "doh": "dns"}


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
    last_exc = None
    for scope in SCOPE_SOURCES:
        try:
            return da.verify_token(settings.device_token_key.encode(),
                                   authorization[len("Bearer "):],
                                   required_scope=scope)
        except da.TokenError as exc:
            last_exc = exc
    raise FilterLogError(f"invalid credential: {last_exc}", 401)


def record_decisions(session: Session, claims: dict,
                     decisions) -> int:
    expected_source = SCOPE_SOURCES.get(claims.get("scope"))
    if not isinstance(decisions, list) or not decisions:
        raise FilterLogError("decisions must be a non-empty list")
    if len(decisions) > MAX_BATCH:
        raise FilterLogError(
            f"batch too large (max {MAX_BATCH})", 400)
    # Signature verification can precede a long lock wait. Authorization must
    # be re-read AFTER serialization, never trusted from a pre-lock ORM cache.
    # All device lifecycle writers use tenant -> device -> credential order.
    # Hold these locks through the caller's commit, including every log insert.
    try:
        tenant_id = int(claims["tenant_id"])
        device_id = int(claims["device_id"])
        token_exp = int(claims["exp"])
    except (KeyError, TypeError, ValueError, OverflowError):
        raise FilterLogError("credential requires tenant/device/expiry binding", 403)
    if expected_source is None:
        raise FilterLogError("unsupported credential scope", 403)
    lock_tenant(session, tenant_id)
    dev = session.scalar(select(Device).where(
        Device.id == device_id, Device.tenant_id == tenant_id)
        .with_for_update().execution_options(populate_existing=True))
    if dev is None or dev.state != "active":
        raise FilterLogError("credential device is not active", 403)
    jti = claims.get("jti")
    cred = (session.scalar(select(IssuedCredential).where(
        IssuedCredential.jti == jti).with_for_update()
        .execution_options(populate_existing=True)) if jti else None)
    now = datetime.now(timezone.utc)
    if cred is None or cred.tenant_id != tenant_id:
        raise FilterLogError("credential is not in the issuance registry", 403)
    if cred.device_id != dev.id:
        raise FilterLogError("credential is bound to a different device", 403)
    if cred.revoked_at is not None:
        raise FilterLogError("credential has been revoked", 403)
    exp = cred.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp <= now or token_exp <= now.timestamp():
        raise FilterLogError("credential has expired", 403)
    if cred.scope != claims.get("scope"):
        raise FilterLogError("credential scope mismatch", 403)
    if int(exp.timestamp()) != token_exp:
        raise FilterLogError("credential expiry mismatch", 403)
    if cred.policy_id != claims.get("policy_id"):
        raise FilterLogError("credential policy binding mismatch", 403)
    device_pk = dev.id
    purge_expired(session, tenant_id=tenant_id)
    accepted = 0
    for raw in decisions:
        if not isinstance(raw, dict):
            raise FilterLogError("each decision must be an object")
        domain = str(raw.get("domain") or raw.get("host") or "")
        action = str(raw.get("action") or "")
        source = str(raw.get("source") or expected_source or "proxy")
        domain = domain.strip().lower().rstrip('.')
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain):
            raise FilterLogError("decision requires a domain, never a URL/path")
        if action not in ALLOWED_ACTIONS:
            raise FilterLogError(f"unsupported action: {action!r}")
        if source not in ALLOWED_SOURCES:
            raise FilterLogError(f"unsupported source: {source!r}")
        if expected_source is not None and source != expected_source:
            raise FilterLogError(
                "credential scope cannot report this source", 403)
        # Allowed browsing history is never persisted, even when a client
        # submits it or includes extra metadata. Reason/rule strings are
        # untrusted and may contain URL paths, so retain no arbitrary text.
        if action == "allow":
            continue
        session.add(FilterDecision(
            tenant_id=tenant_id, device_id=device_pk, source=source,
            domain=domain, action=action,
            rule="blocked", reason="policy blocked domain"))
        accepted += 1
    session.flush()
    return accepted


def recent_decisions(session: Session, tenant_id: int,
                     limit: int = 200) -> list[FilterDecision]:
    purge_expired(session, tenant_id=tenant_id)
    return list(session.scalars(
        select(FilterDecision)
        .where(FilterDecision.tenant_id == tenant_id)
        .order_by(FilterDecision.id.desc())
        .limit(limit)))


def edge_status(session: Session, tenant_id: int) -> dict:
    """Truthful proxy/DNS edge status (spec Part 10 status panels).

    Reports only what the control-plane can EVIDENCE: whether a policy
    is selected/published for the tenant (configuration) and what
    decisions the edge actually reported (receipts). There is no
    health, liveness, or delivery-confirmation signal from the edge,
    so health is always "unknown" and said so explicitly. Credential
    issuance is NOT reported here as status: a minted token proves only
    that issuance happened, never that the proxy is configured,
    connected, or serving.
    """
    from sqlalchemy import func

    from app.models import FilterDecision, PublicationState

    purge_expired(session, tenant_id=tenant_id)
    count, latest = session.execute(
        select(func.count(FilterDecision.id),
               func.max(FilterDecision.received_at))
        .where(FilterDecision.tenant_id == tenant_id)).one()
    sources = sorted(r[0] for r in session.execute(
        select(FilterDecision.source)
        .where(FilterDecision.tenant_id == tenant_id).distinct()))
    pub = session.get(PublicationState, tenant_id)
    return {
        "configured": {
            "policy_selected": bool(pub and pub.selected_policy_id),
            "publication_revision": pub.revision if pub else 0,
        },
        "reported": {
            "decision_count": count,
            "sources": sources,
            "latest_received_at": latest.isoformat() if latest else None,
        },
        "health": "unknown",
        "health_note": (
            "No health, liveness, or delivery signal from the proxy/DNS "
            "edge exists yet. A selected policy and reported decisions "
            "are separate facts; neither proves the edge is currently "
            "serving, and credential issuance is not shown as status "
            "because issuance proves nothing about operation."),
        "dns_reporting": (
            "dns decisions received (receipts only; receipt is not a "
            "liveness or connectivity signal)"
            if "dns" in sources else
            "no dns decisions reported yet (the ingestion route accepts "
            "reports; that is all the control plane can evidence)"),
    }


def purge_expired(session: Session, tenant_id=None, now=None) -> int:
    """Physical DELETE, including legacy allowed/invalid rows. Not hiding.

    Called by ingestion, reads and the standalone maintenance loop. Offline
    time stops a loop, but the next start/read deletes before serving data.
    """
    now = now or datetime.now(timezone.utc)
    tenants = select(Tenant)
    if tenant_id is not None:
        tenants = tenants.where(Tenant.id == tenant_id)
    removed = 0
    for tenant in session.scalars(tenants.order_by(Tenant.id)).all():
        lock_tenant(session, tenant.id)
        session.refresh(tenant)
        days = tenant.blocked_log_retention_days
        if not isinstance(days, int) or not 1 <= days <= 30:
            days = 7
        result = session.execute(delete(FilterDecision).where(
            FilterDecision.tenant_id == tenant.id,
            or_(FilterDecision.action != "block",
                FilterDecision.domain.like("%/%"),
                FilterDecision.domain.like("%?%"),
                FilterDecision.domain.like("%#%"),
                FilterDecision.domain.like("%@%"),
                FilterDecision.domain.like("%:%"),
                FilterDecision.received_at <= now - timedelta(days=days))))
        removed += result.rowcount
    return removed
