"""Publication trigger: export the tenant's selected default policy as
engine configuration and publish it as a new generation.

The revision counter lives in the database (publication_states.revision),
which serializes concurrent publishes and doubles as the audit trail.
The on-disk layout comes from app.publisher, adapted from the reviewed
dashboard publisher.
"""

from __future__ import annotations

import json
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (CategoryRule, CategorySource, CategorySourceUpdate,
                     Device, DeviceAssignment, MDMEnrollment, Policy,
                     PolicyVersion, PublicationState)
from .policy_ops import PolicyError
from .publisher import Publisher, PublicationError, canonical_json

import os as _os, sys as _sys
_ENG = _os.path.join(_os.path.dirname(__file__), "..", "..", "filtering-engine", "src")
if _os.path.abspath(_ENG) not in _sys.path:
    _sys.path.insert(0, _os.path.abspath(_ENG))
import category_db  # noqa: E402
import policy_engine  # noqa: E402


def build_categories_doc(session: Session) -> dict:
    """Render the categories document from the active category_rules
    (the source of truth) and prove it loads with the filtering
    engine's own CategoryDB. Shared by the registry's file sync and
    the publish-time divergence check so both mean the same bytes."""
    rows = session.scalars(select(CategoryRule).where(
        CategoryRule.active.is_(True))).all()
    doc = {"_meta": {"source": "kosherguard-control-plane",
                     "note": "registry-managed dataset"},
           "domains": {}}
    for row in rows:
        doc["domains"].setdefault(row.domain, [])
        if row.category not in doc["domains"][row.domain]:
            doc["domains"][row.domain].append(row.category)
    for domain in doc["domains"]:
        doc["domains"][domain] = sorted(doc["domains"][domain])
    category_db.CategoryDB(doc["domains"], meta=doc["_meta"])
    return doc


def _assert_categories_file_matches_db(session: Session,
                                       categories_path: str) -> None:
    """Publication must never ship a categories document that diverged
    from the committed registry-managed rules (e.g. after a failed file
    sync or a manual edit). Refuse with a repair hint instead. When no
    registry-managed rules are active the file is operator-provided
    (category-pipeline build) and there is nothing committed to diverge
    from, so the check does not apply."""
    managed = session.scalars(select(CategoryRule).where(
        CategoryRule.source_update_id.is_not(None)).limit(1)).first()
    active_update = session.scalars(select(CategorySourceUpdate).where(
        CategorySourceUpdate.status == "active").limit(1)).first()
    if managed is None and active_update is None:
        return
    # Provenance, not row count: once the registry has managed any
    # rules (even if all were later deactivated), the file must match
    # the committed registry state - zero active rules must NOT
    # silently downgrade to the operator-file carve-out with a stale
    # registry file still on disk.
    expected = canonical_json(build_categories_doc(session))
    with open(categories_path, "rb") as fh:
        on_disk = fh.read()
    try:
        parsed = json.loads(on_disk.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise PolicyError(
            "categories file is unreadable; resync the category "
            "sources dataset before publishing", 500)
    if canonical_json(parsed) != expected:
        raise PolicyError(
            "categories file diverged from the committed category "
            "rules; resync the category sources dataset before "
            "publishing", 500)


def export_policy_documents(version: PolicyVersion,
                            categories_path: str | None = None,
                            session: Session | None = None) -> tuple[bytes, bytes]:
    """Render one policy version as engine policy.json + categories.json.

    categories_path points at the category-pipeline's built
    categories.json; when unset (or missing) the published document is
    structurally valid with no domains, so category rules resolve to no
    matches rather than failing to load. When a session is supplied the
    file is verified against the committed active rules first."""
    # The stored engine_doc is already normalized (nested category_rules);
    # re-running the API-shaped normalize_engine_doc would drop them.
    # Validate with the engine's own validator instead.
    stored = json.loads(version.engine_doc)
    try:
        policy_engine.validate_policy(stored)
    except policy_engine.PolicyConfigError as exc:
        raise PolicyError(f"stored policy failed engine validation: {exc}", 500)
    policy_json = canonical_json(stored)
    if categories_path and os.path.isfile(categories_path):
        if session is not None:
            _assert_categories_file_matches_db(session, categories_path)
        with open(categories_path, "rb") as fh:
            categories_json = fh.read()
        # Prove it is a real pipeline product before shipping it.
        parsed = json.loads(categories_json.decode("utf-8"))
        if not isinstance(parsed, dict) or not isinstance(
                parsed.get("domains"), dict):
            raise PolicyError("categories file is not a valid category document", 500)
    else:
        categories_json = canonical_json({
            "_meta": {"source": "kosherguard-control-plane",
                      "note": "no category dataset configured"},
            "domains": {},
        })
    return policy_json, categories_json


def tenant_root(root: str, tenant_id: int) -> str:
    """Per-tenant publication root.

    Built from the configured root and the integer tenant id only - no
    user-controlled path segment can appear. Tenants can never see,
    overwrite, or delete each other's generations.
    """
    if not isinstance(tenant_id, int) or tenant_id <= 0:
        raise PolicyError("invalid tenant id", 500)
    return os.path.join(root, f"tenant-{tenant_id}")


def publish_selected(session: Session, tenant_id: int, root: str,
                     actor_email: str,
                     categories_path: str | None = None,
                     publication_job_id: int | None = None) -> dict:
    """Publish the tenant's selected default policy as a new generation."""
    # Tenant row lock first (the same lock the request path takes in
    # current_user), then the publication-state row: one lock order
    # everywhere, so a publish can never interleave with a concurrent
    # policy/device/group/exception write.
    from .db import lock_tenant
    lock_tenant(session, tenant_id)
    state = session.scalar(select(PublicationState).where(
        PublicationState.tenant_id == tenant_id).with_for_update())
    if state is None or state.selected_policy_id is None:
        raise PolicyError("no default policy selected for this tenant", 409)
    policy = session.get(Policy, state.selected_policy_id)
    if policy is None or policy.tenant_id != tenant_id:
        raise PolicyError("selected default policy not found", 409)
    version = session.scalar(
        select(PolicyVersion)
        .where(PolicyVersion.policy_id == policy.id)
        .order_by(PolicyVersion.version.desc())
        .limit(1))
    if version is None:
        raise PolicyError("selected policy has no versions", 409)

    policy_json, categories_json = export_policy_documents(
        version, categories_path, session=session)

    # Emit assigned policies and the authenticated device map in the SAME
    # immutable generation. No IP/device identity inference is made.
    from .policy_ops import prove_tighten_only
    extras = {}
    from .exception_ops import export_exceptions
    overlay = export_exceptions(session, tenant_id)
    if overlay:
        extras['exceptions.json'] = canonical_json(overlay)
    mapping = {}
    from .group_ops import effective_assignments
    assignments = effective_assignments(session, tenant_id)
    for device_id, policy_id in assignments.items():
        device = session.get(Device, device_id)
        assigned = session.get(Policy, policy_id)
        if (device is None or device.tenant_id != tenant_id or
                assigned is None or assigned.tenant_id != tenant_id or
                not assigned.enabled):
            raise PolicyError("invalid active device assignment", 409)
        if str(device.id) in mapping:
            raise PolicyError("ambiguous active device assignments", 409)
        prove_tighten_only(json.loads(assigned.engine_doc), policy)
        name = f"assigned-policy-{assigned.id}.json"
        extras[name] = canonical_json(json.loads(assigned.engine_doc))
        mapping[str(device.id)] = {"policy": name, "policy_id": assigned.id}
    if mapping or overlay:
        # The publisher cross-checks supplemental documents against the
        # authenticated device map; exceptions alone still need the map
        # (possibly empty) to ship.
        extras["device-map.json"] = canonical_json({
            "default_policy_id": policy.id, "devices": mapping})
    enrollment_cycles = {str(row.device_id): row.id for row in
        session.scalars(select(MDMEnrollment).where(
            MDMEnrollment.tenant_id == tenant_id,
            MDMEnrollment.state == "enrolled"))}
    state.revision = (state.revision or 0) + 1
    revision = state.revision
    publisher = Publisher(tenant_root(root, tenant_id))
    try:
        with publisher.locked():
            generation = publisher.publish(
                revision, policy_json, categories_json,
                {"tenant_id": tenant_id, "policy": policy.name,
                 "policy_version": version.version,
                 "published_by": actor_email,
                 "publication_job_id": publication_job_id,
                 "enrollment_cycles": enrollment_cycles},
                extra_documents=extras)
    except PublicationError as exc:
        raise PolicyError(f"publication failed: {exc}", 500)
    session.flush()
    return {"revision": revision, "generation": generation,
            "policy": policy.name, "policy_version": version.version}


def publish_revocation_cleanup(session: Session, tenant_id: int, root: str,
                               actor_email: str,
                               publication_job_id: int | None = None) -> dict:
    """Republish the LAST PUBLISHED snapshot minus revoked exceptions.

    Narrow system cleanup for exception revocation: it never exports the
    tenant's current saved state, so pending policy, assignment or
    exception changes stay pending. The only mutation is removing
    exception entries whose revocation is recorded in the database.
    """
    from .db import lock_tenant
    from .models import PolicyException
    lock_tenant(session, tenant_id)
    state = session.scalar(select(PublicationState).where(
        PublicationState.tenant_id == tenant_id).with_for_update())
    if state is None:
        raise PolicyError("publication state missing", 500)
    revoked = {row.id for row in session.scalars(
        select(PolicyException).where(
            PolicyException.tenant_id == tenant_id,
            PolicyException.revoked_at.isnot(None)))}
    publisher = Publisher(tenant_root(root, tenant_id))
    with publisher.locked():
        manifest = publisher.current()
        if manifest is None:
            # Never published: a revoked exception never shipped.
            return {"revision": state.revision or 0,
                    "cleanup": "nothing-published"}
        generation_dir = os.path.join(tenant_root(root, tenant_id),
                                      "generations", manifest["generation"])
        with open(os.path.join(generation_dir, "policy.json"),
                  "rb") as fh:
            policy_json = fh.read()
        with open(os.path.join(generation_dir, "categories.json"),
                  "rb") as fh:
            categories_json = fh.read()
        extras = {}
        old_overlay = {}
        for name in manifest.get("files", []):
            if name in ("policy.json", "categories.json", "manifest.json"):
                continue
            with open(os.path.join(generation_dir, name), "rb") as fh:
                data = fh.read()
            if name == "exceptions.json":
                old_overlay = json.loads(data.decode("utf-8"))
            else:
                extras[name] = data
        new_overlay = {}
        removed = 0
        for device_id, entries in old_overlay.items():
            kept = [e for e in entries
                    if e.get("exception_id") not in revoked]
            removed += len(entries) - len(kept)
            if kept:
                new_overlay[device_id] = kept
        if new_overlay == old_overlay:
            return {"revision": manifest["revision"], "cleanup": "no-op"}
        if new_overlay:
            extras["exceptions.json"] = canonical_json(new_overlay)
        state.revision = (state.revision or 0) + 1
        generation = publisher.publish(
            state.revision, policy_json, categories_json,
            {"tenant_id": tenant_id,
             "published_by": actor_email,
             "publication_job_id": publication_job_id,
             "cleanup": f"removed {removed} revoked exception entrant(s)",
             "enrollment_cycles": manifest.get("enrollment_cycles", {})},
            extra_documents=extras)
        session.flush()
        return {"revision": state.revision, "generation": generation,
                "cleanup": f"removed {removed} revoked exception entrant(s)"}
