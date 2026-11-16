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

from .models import Policy, PolicyVersion, PublicationState
from .policy_ops import PolicyError
from .publisher import Publisher, PublicationError, canonical_json

import os as _os, sys as _sys
_ENG = _os.path.join(_os.path.dirname(__file__), "..", "..", "filtering-engine", "src")
if _os.path.abspath(_ENG) not in _sys.path:
    _sys.path.insert(0, _os.path.abspath(_ENG))
import policy_engine  # noqa: E402


def export_policy_documents(version: PolicyVersion,
                            categories_path: str | None = None) -> tuple[bytes, bytes]:
    """Render one policy version as engine policy.json + categories.json.

    categories_path points at the category-pipeline's built
    categories.json; when unset (or missing) the published document is
    structurally valid with no domains, so category rules resolve to no
    matches rather than failing to load.
    """
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
                     categories_path: str | None = None) -> dict:
    """Publish the tenant's selected default policy as a new generation."""
    state = session.get(PublicationState, tenant_id)
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
        version, categories_path)

    state.revision = (state.revision or 0) + 1
    revision = state.revision
    publisher = Publisher(tenant_root(root, tenant_id))
    try:
        with publisher.locked():
            generation = publisher.publish(
                revision, policy_json, categories_json,
                {"tenant_id": tenant_id, "policy": policy.name,
                 "policy_version": version.version,
                 "published_by": actor_email})
    except PublicationError as exc:
        raise PolicyError(f"publication failed: {exc}", 500)
    session.flush()
    return {
        "revision": revision,
        "generation": generation,
        "policy": policy.name,
        "policy_version": version.version,
    }
