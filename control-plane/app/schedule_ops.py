"""Filtering schedules (spec 8F) for the control plane.

The canonical validator and the edge evaluator live in
dns-edge/schedules.py (single source of truth: the same code validates
a schedule at authoring time that will evaluate it at the edge). This
module only makes that code importable here and shapes the errors for
the API layer.
"""

from __future__ import annotations

import os
import sys

_DNS_EDGE = os.path.join(os.path.dirname(__file__), "..", "..", "dns-edge")
if os.path.abspath(_DNS_EDGE) not in sys.path:
    sys.path.insert(0, os.path.abspath(_DNS_EDGE))

import schedules as _schedules  # noqa: E402

ScheduleError = _schedules.ScheduleError


def validate_schedules(raw) -> list[dict]:
    return _schedules.validate_schedules(raw)


def with_schedules(doc: dict, normalized: list[dict]) -> dict:
    """Return a copy of the engine doc carrying the schedule list."""
    out = dict(doc)
    if normalized:
        out["_schedules"] = normalized
    else:
        out.pop("_schedules", None)
    return out


def doc_schedules(doc: dict) -> list[dict]:
    """The validated schedule list of a stored engine doc (or [])."""
    return _schedules.validate_schedules(doc.get("_schedules"))
