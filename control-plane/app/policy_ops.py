"""Policy operations with the mandatory tighten-only invariant.

Semantics adapted from the reviewed dashboard store (Stage 11A): every
active device assignment must be proven at least as restrictive as the
tenant's selected default policy, and policy-content mutations must not
weaken that proof. The proof itself comes from the reviewed filtering
engine's policy_comparison.at_least_as_restrictive - the same function
the engine uses - not a re-implementation.
"""

from __future__ import annotations

import json
import os
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import DeviceAssignment, Policy, PolicyVersion, PublicationState

_ENGINE_SRC = os.path.join(os.path.dirname(__file__), "..", "..",
                           "filtering-engine", "src")
if _ENGINE_SRC not in sys.path:
    sys.path.insert(0, os.path.abspath(_ENGINE_SRC))

import policy_comparison  # noqa: E402
import policy_engine  # noqa: E402


class PolicyError(RuntimeError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def normalize_engine_doc(payload: dict) -> dict:
    """Validate and normalize a policy payload through the engine."""
    raw = {
        "default_policy": payload.get("default_policy"),
        "allowlist": payload.get("allowlist", []),
        "blocklist": payload.get("blocklist", []),
        "category_rules": {
            "allow": payload.get("category_allow", []),
            "block": payload.get("category_block", []),
        },
    }
    if raw["default_policy"] not in ("allow", "block"):
        raise PolicyError("default_policy must be 'allow' or 'block'")
    try:
        normalized = policy_engine.validate_policy(raw)
    except policy_engine.PolicyConfigError as exc:
        raise PolicyError(f"invalid policy rules: {exc}")
    doc = {
        "default_policy": normalized["default_policy"],
        "allowlist": sorted(set(normalized["allowlist"])),
        "blocklist": sorted(set(normalized["blocklist"])),
        "category_rules": {
            "allow": sorted(set(normalized["category_allow"])),
            "block": sorted(set(normalized["category_block"])),
        },
    }
    # Filtering schedules travel as engine-tolerated _schedules
    # metadata. Validation errors surface as PolicyError 400s.
    if payload.get("schedules") is not None:
        from . import schedule_ops
        try:
            doc = schedule_ops.with_schedules(
                doc, schedule_ops.validate_schedules(payload["schedules"]))
        except schedule_ops.ScheduleError as exc:
            raise PolicyError(f"invalid schedules: {exc}")
    return doc


def selected_default(session: Session, tenant_id: int) -> Policy | None:
    state = session.get(PublicationState, tenant_id)
    if state is None or state.selected_policy_id is None:
        return None
    return session.get(Policy, state.selected_policy_id)


def active_assignments(session: Session, tenant_id: int,
                       exclude_policy_id: int | None = None):
    rows = session.scalars(
        select(DeviceAssignment).where(
            DeviceAssignment.tenant_id == tenant_id,
            DeviceAssignment.active.is_(True)))
    return [r for r in rows if r.policy_id != exclude_policy_id]


def prove_tighten_only(candidate_doc: dict, baseline: Policy) -> None:
    verdict = policy_comparison.at_least_as_restrictive(
        candidate_doc, json.loads(baseline.engine_doc))
    if not verdict.allowed:
        raise PolicyError(
            f"policy must be at least as restrictive as the default "
            f"policy {baseline.name!r}: {verdict.reason}", 409)


def enforce_on_content_mutation(session: Session, tenant_id: int,
                                policy: Policy, proposed_doc: dict) -> None:
    """A policy-content change with active assignments must keep every
    one of them at least as restrictive as the selected default."""
    default = selected_default(session, tenant_id)
    if default is None:
        return
    if not active_assignments(session, tenant_id,
                              exclude_policy_id=None):
        return
    if any(a.policy_id == policy.id
           for a in active_assignments(session, tenant_id)):
        prove_tighten_only(proposed_doc, default)


def enforce_on_new_assignment(session: Session, tenant_id: int,
                              policy: Policy) -> None:
    default = selected_default(session, tenant_id)
    if default is None or default.id == policy.id:
        return
    prove_tighten_only(json.loads(policy.engine_doc), default)


def enforce_on_default_selection(session: Session, tenant_id: int,
                                 new_default: Policy) -> None:
    """Re-prove every active assignment against the proposed new default."""
    new_doc = json.loads(new_default.engine_doc)
    violations = []
    for assignment in active_assignments(session, tenant_id,
                                         exclude_policy_id=new_default.id):
        policy = session.get(Policy, assignment.policy_id)
        verdict = policy_comparison.at_least_as_restrictive(
            json.loads(policy.engine_doc), new_doc)
        if not verdict.allowed:
            violations.append(
                f"policy {policy.name!r}: {verdict.reason}")
    if violations:
        raise PolicyError(
            f"cannot select {new_default.name!r} as the default: it "
            "would make existing assignments less restrictive than the "
            "default (tighten-only rule). " + " | ".join(violations), 409)


def snapshot_version(session: Session, policy: Policy,
                     actor_user_id: int | None) -> int:
    count = len(session.scalars(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id)).all())
    version = count + 1
    session.add(PolicyVersion(policy_id=policy.id, version=version,
                              engine_doc=policy.engine_doc,
                              actor_user_id=actor_user_id))
    session.flush()
    return version
