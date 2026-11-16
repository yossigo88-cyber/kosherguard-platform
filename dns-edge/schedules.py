"""Time-windowed filtering schedules (spec 8F: filtering schedules).

A schedule adds EXTRA blocks to a policy during a weekly time window -
for example "block games and social media after 21:00 on school
nights". Schedules only ever make filtering MORE restrictive than the
base policy; they cannot allow anything the base policy blocks.

Storage: schedules travel inside the published policy document under
the ``_schedules`` key. The reviewed engine's validate_policy()
explicitly tolerates underscore-prefixed metadata keys and drops them
from its normalized output, so the reviewed engine's behavior is
byte-identical whether or not schedules are present; the wrapper in
this module applies the time-varying part at the edge.

Semantics:
- During an active window the schedule's block_categories are merged
  into category_rules.block and its block_domains into the blocklist.
- The explicit ALLOWLIST still wins over a schedule (a guardian's
  surgical override is never silently undone by a clock). This matches
  the reviewed engine's precedence: allowlist > blocklist > category
  block > category allow > default.
- A schedule blocking a category the base policy explicitly allows
  OVERRIDES the category-allow during the window (more restrictive);
  the merged document would otherwise fail the engine's allow/block
  overlap check.
- Windows are weekly, wall-clock, in the schedule's IANA timezone.
  start == end means "never active"; a window with start > end wraps
  past midnight (e.g. 21:00-06:30).

Fail-closed: any malformed schedule entry raises ScheduleError at load
time. The edge runner's reload path keeps the previous validated
configuration on any load failure, so a bad schedule can never weaken
or crash live filtering.
"""

from __future__ import annotations

import os
import sys
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_ENGINE_SRC = os.path.join(os.path.dirname(__file__), "..",
                           "filtering-engine", "src")
if _ENGINE_SRC not in sys.path:
    sys.path.insert(0, os.path.abspath(_ENGINE_SRC))

import policy_engine  # noqa: E402


class ScheduleError(ValueError):
    pass


_NAME_RE = policy_engine.CATEGORY_RE  # same slug shape as category names
MAX_SCHEDULES = 50
MAX_BLOCK_ENTRIES = 500


def _parse_hhmm(value: object, where: str) -> int:
    # Accepts the public 'HH:MM' form and the stored normalized form
    # (minutes after midnight), so validation is idempotent on documents
    # read back from the database or a published generation.
    if isinstance(value, int) and not isinstance(value, bool):
        if not 0 <= value <= 1439:
            raise ScheduleError(f"{where}: minutes out of range: {value!r}")
        return value
    if not isinstance(value, str) or len(value) != 5 or value[2] != ":":
        raise ScheduleError(f"{where}: expected 'HH:MM', got {value!r}")
    try:
        hours = int(value[:2])
        minutes = int(value[3:])
    except ValueError:
        raise ScheduleError(f"{where}: expected 'HH:MM', got {value!r}")
    if not (0 <= hours <= 23 and 0 <= minutes <= 59):
        raise ScheduleError(f"{where}: time out of range: {value!r}")
    return hours * 60 + minutes


def validate_schedules(raw: object) -> list[dict]:
    """Validate a schedule list; returns the normalized list.

    Raises ScheduleError on the first problem, naming the exact field -
    the same fail-clearly philosophy as the reviewed engine's
    validate_policy()."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ScheduleError(
            f"_schedules must be a list, got {type(raw).__name__}")
    if len(raw) > MAX_SCHEDULES:
        raise ScheduleError(f"at most {MAX_SCHEDULES} schedules allowed")
    normalized = []
    seen_names = set()
    for index, entry in enumerate(raw):
        where = f"_schedules[{index}]"
        if not isinstance(entry, dict):
            raise ScheduleError(f"{where}: must be an object")
        unknown = set(entry) - {"name", "days", "start", "end",
                                "timezone", "block_categories",
                                "block_domains", "enabled",
                                "start_date", "end_date"}
        if unknown:
            raise ScheduleError(f"{where}: unknown keys {sorted(unknown)}")
        name = entry.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name or ""):
            raise ScheduleError(f"{where}.name: invalid schedule name")
        if name in seen_names:
            raise ScheduleError(f"{where}.name: duplicate {name!r}")
        seen_names.add(name)
        days = entry.get("days")
        if not isinstance(days, list) or not days or \
                any(isinstance(d, bool) or not isinstance(d, int) or
                    not 0 <= d <= 6 for d in days):
            raise ScheduleError(
                f"{where}.days: must be a non-empty list of weekday "
                "numbers 0 (Monday) to 6 (Sunday)")
        days = sorted(set(days))
        start = _parse_hhmm(entry.get("start"), f"{where}.start")
        end = _parse_hhmm(entry.get("end"), f"{where}.end")
        tz_name = entry.get("timezone")
        if not isinstance(tz_name, str) or not tz_name:
            raise ScheduleError(f"{where}.timezone: expected IANA name")
        try:
            ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            raise ScheduleError(
                f"{where}.timezone: unknown IANA timezone {tz_name!r}")
        dates = {}
        for field in ("start_date", "end_date"):
            value = entry.get(field)
            if value is not None:
                try:
                    if not isinstance(value, str):
                        raise ValueError()
                    parsed = date.fromisoformat(value)
                    if parsed.isoformat() != value:
                        raise ValueError()
                except ValueError:
                    raise ScheduleError(f"{where}.{field}: expected YYYY-MM-DD")
                dates[field] = value
        if len(dates) == 2 and dates["end_date"] < dates["start_date"]:
            raise ScheduleError(f"{where}: end_date precedes start_date")
        # Reuse the reviewed engine's own list validators on a synthetic
        # policy so domains and categories are checked by the same code
        # that will enforce them.
        try:
            checked = policy_engine.validate_policy({
                "default_policy": "allow",
                "allowlist": [],
                "blocklist": entry.get("block_domains", []),
                "category_rules": {"allow": [],
                                   "block": entry.get("block_categories",
                                                      [])},
            })
        except policy_engine.PolicyConfigError as exc:
            raise ScheduleError(f"{where}: {exc}")
        enabled = entry.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ScheduleError(f"{where}.enabled: must be true or false")
        normalized.append({
            "name": name,
            "days": days,
            "start": start,
            "end": end,
            "timezone": tz_name,
            "block_categories": checked["category_block"],
            "block_domains": checked["blocklist"],
            "enabled": enabled,
            **dates,
        })
    return normalized


def is_active(schedule: dict, moment: datetime) -> bool:
    """True when the schedule's window covers ``moment`` (UTC-aware)."""
    if not schedule["enabled"]:
        return False
    local = moment.astimezone(ZoneInfo(schedule["timezone"]))
    minute = local.hour * 60 + local.minute
    weekday = local.weekday()
    start, end = schedule["start"], schedule["end"]
    # Dates constrain the START DAY of a window, including overnight
    # windows whose after-midnight portion belongs to yesterday.
    anchor_day = local.date()
    if start > end and minute < end:
        anchor_day -= timedelta(days=1)
    if schedule.get("start_date") and anchor_day < date.fromisoformat(schedule["start_date"]):
        return False
    if schedule.get("end_date") and anchor_day > date.fromisoformat(schedule["end_date"]):
        return False
    if start == end:
        return False
    if start < end:
        return weekday in schedule["days"] and start <= minute < end
    # Overnight window: today's leg (weekday listed, minute >= start) or
    # yesterday's leg (yesterday listed, minute < end).
    if minute >= start:
        return weekday in schedule["days"]
    if minute < end:
        yesterday = (weekday - 1) % 7
        return yesterday in schedule["days"]
    return False


def active_signature(schedules: list[dict], moment: datetime) -> tuple:
    """The set of schedule names active at ``moment`` (order-stable)."""
    return tuple(s["name"] for s in schedules if is_active(s, moment))


def merge_doc(base_doc: dict, schedules: list[dict],
              moment: datetime) -> dict:
    """The effective engine document at ``moment``.

    Active schedules merge their blocks in; a schedule-blocked category
    is removed from category_allow (schedule wins the overlap, the more
    restrictive direction). The explicit allowlist is untouched."""
    active = [s for s in schedules if is_active(s, moment)]
    if not active:
        return base_doc
    merged = dict(base_doc)
    block_categories = set(base_doc.get("category_rules", {})
                           .get("block", []))
    block_domains = set(base_doc.get("blocklist", []))
    for sched in active:
        block_categories.update(sched["block_categories"])
        block_domains.update(sched["block_domains"])
    allow_categories = [c for c in base_doc.get("category_rules", {})
                        .get("allow", []) if c not in block_categories]
    merged["blocklist"] = sorted(block_domains)
    merged["category_rules"] = {
        "allow": sorted(allow_categories),
        "block": sorted(block_categories),
    }
    return merged


class ScheduledPolicyEngine(policy_engine.PolicyEngine):
    """A policy engine whose effective rules vary with the clock.

    Subclasses the reviewed PolicyEngine so it passes the EngineSet
    isinstance contracts, but deliberately does NOT call
    super().__init__: no single validated snapshot can represent a
    document whose effective content changes with the clock. Every
    per-window engine is built through the reviewed PolicyEngine
    constructor, so validation is identical to a static policy.

    The merged engine is rebuilt only when the set of active schedules
    changes (at most a handful of rebuilds per day); between window
    boundaries every query reuses the cached engine.

    The clock is injectable (``now`` callable returning a UTC-aware
    datetime) so tests control time exactly.
    """

    def __init__(self, base_doc: dict, category_db, now=None) -> None:
        schedules = validate_schedules(base_doc.get("_schedules"))
        self._base_doc = base_doc
        self._schedules = schedules
        self._db = category_db
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._signature = None
        self._engine = None

    def _current_engine(self):
        moment = self._now()
        if moment.tzinfo is None:
            raise ScheduleError("clock returned a naive datetime")
        signature = active_signature(self._schedules, moment)
        if signature != self._signature:
            doc = merge_doc(self._base_doc, self._schedules, moment)
            self._engine = policy_engine.PolicyEngine(doc, self._db)
            self._signature = signature
        return self._engine

    def decide(self, domain: str):
        return self._current_engine().decide(domain)

    @property
    def schedules(self) -> list[dict]:
        return list(self._schedules)


def wrap_engine(base_doc: dict, category_db, engine, now=None):
    """Return a schedule-aware engine when the document has schedules,
    otherwise the already-built reviewed engine unchanged."""
    if validate_schedules(base_doc.get("_schedules")):
        return ScheduledPolicyEngine(base_doc, category_db, now=now)
    return engine


def wrap_default_engine(engine_set, policy_path: str,
                        categories_path: str, now=None):
    """Apply schedules of the default policy doc to a loaded engine set.

    The reviewed loader builds one immutable EngineSet from files. When
    the default policy document carries _schedules, its engine is
    replaced by a ScheduledPolicyEngine built from that same document;
    bindings and per-policy engines pass through untouched. Without
    schedules the original set is returned unchanged - zero behavior
    difference for unscheduled policies.

    Fail-clearly rule: a multi-policy generation (per-policy engines or
    client bindings) with schedules on the default raises instead of
    silently applying schedules to some clients and not others. The
    multi-policy layout's per-policy schedule wiring lands with the
    per-device generation layout (devices.json) that publishes it.
    """
    import engine_set as _engine_set
    import json as _json

    if not isinstance(engine_set, _engine_set.EngineSet):
        return engine_set
    with open(policy_path, encoding="utf-8") as fh:
        base_doc = _json.load(fh)
    if not validate_schedules(base_doc.get("_schedules")):
        return engine_set
    if engine_set.per_policy or engine_set.bindings:
        raise ScheduleError(
            "default policy has schedules but the generation is "
            "multi-policy: per-policy schedule wiring is not yet "
            "implemented; refusing to filter some clients on a schedule "
            "and others not")
    import category_db as _category_db
    db = _category_db.CategoryDB.load(categories_path)
    wrapped = ScheduledPolicyEngine(base_doc, db, now=now)
    return _engine_set.EngineSet(
        default=wrapped,
        per_policy=dict(engine_set.per_policy),
        bindings=dict(engine_set.bindings),
        default_policy_id=engine_set.default_policy_id)
