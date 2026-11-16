"""Publication trigger: export the tenant's selected default policy as
engine configuration and publish it as a new generation.

The revision counter lives in the database (publication_states.revision),
which serializes concurrent publishes and doubles as the audit trail.
The on-disk layout comes from app.publisher, adapted from the reviewed
dashboard publisher.
"""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Policy, PolicyVersion, PublicationState
from .policy_ops import PolicyError, normalize_engine_doc
from .publisher import Publisher, PublicationError, canonical_json


def export_policy_documents(version: PolicyVersion) -> tuple[bytes, bytes]:
    """Render one policy version as engine policy.json + categories.json.

    The category database itself is Milestone 3 work; until then the
    published categories document is structurally valid with no domains,
    so category rules resolve to no matches rather than failing to load.
    """
    doc = normalize_engine_doc(json.loads(version.engine_doc))
    policy_json = canonical_json(doc)
    categories_json = canonical_json({
        "_meta": {"source": "kosherguard-control-plane",
                  "note": "category dataset ships in Milestone 3"},
        "domains": {},
    })
    return policy_json, categories_json


def publish_selected(session: Session, tenant_id: int, root: str,
                     actor_email: str) -> dict:
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

    policy_json, categories_json = export_policy_documents(version)

    state.revision = (state.revision or 0) + 1
    revision = state.revision
    publisher = Publisher(root)
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
