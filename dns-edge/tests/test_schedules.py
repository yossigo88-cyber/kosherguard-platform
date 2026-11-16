"""Filtering schedule tests: validation, window logic, engine wrapping."""

import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "filtering-engine", "src"))

import category_db  # noqa: E402
import engine_set  # noqa: E402
import policy_engine  # noqa: E402
import schedules  # noqa: E402

UTC = timezone.utc


def at(iso):
    return datetime.fromisoformat(iso).replace(tzinfo=UTC)


BEDTIME = {"name": "bedtime", "days": [0, 1, 2, 3, 4], "start": "21:00",
           "end": "06:30", "timezone": "America/New_York",
           "block_categories": ["games"], "block_domains": ["fun.example"],
           "enabled": True}


class TestValidation:
    def test_valid_normalizes(self):
        out = schedules.validate_schedules([BEDTIME])
        assert out[0]["start"] == 21 * 60 and out[0]["end"] == 6 * 60 + 30
        assert out[0]["days"] == [0, 1, 2, 3, 4]

    def test_idempotent_on_normalized(self):
        once = schedules.validate_schedules([BEDTIME])
        assert schedules.validate_schedules(once) == once

    def test_none_is_empty(self):
        assert schedules.validate_schedules(None) == []

    @pytest.mark.parametrize("bad,frag", [
        (dict(BEDTIME, name="bad name!"), "name"),
        (dict(BEDTIME, days=[]), "days"),
        (dict(BEDTIME, days=[7]), "days"),
        (dict(BEDTIME, days=[True]), "days"),
        (dict(BEDTIME, start="9pm"), "start"),
        (dict(BEDTIME, start="24:00"), "start"),
        (dict(BEDTIME, end="6:30"), "end"),
        (dict(BEDTIME, timezone="Monsey"), "timezone"),
        (dict(BEDTIME, enabled="yes"), "enabled"),
        (dict(BEDTIME, extra=1), "unknown keys"),
        (dict(BEDTIME, block_domains=["bad domain"]), "block"),
        (dict(BEDTIME, block_categories=["Games!"]), "block"),
    ])
    def test_invalid_rejected(self, bad, frag):
        with pytest.raises(schedules.ScheduleError) as exc:
            schedules.validate_schedules([bad])
        assert frag in str(exc.value)

    def test_duplicate_names_rejected(self):
        with pytest.raises(schedules.ScheduleError):
            schedules.validate_schedules([BEDTIME, BEDTIME])

    def test_not_a_list_rejected(self):
        with pytest.raises(schedules.ScheduleError):
            schedules.validate_schedules({"name": "x"})


class TestWindows:
    # 2026-11-16 is a Monday. America/New_York is UTC-5 in November.
    def test_inside_window(self):
        # Tuesday 22:30 EST = Wednesday 03:30 UTC
        s = schedules.validate_schedules([BEDTIME])[0]
        assert schedules.is_active(s, at("2026-11-18T03:30:00"))

    def test_outside_window(self):
        # Tuesday 12:00 EST = 17:00 UTC
        s = schedules.validate_schedules([BEDTIME])[0]
        assert not schedules.is_active(s, at("2026-11-17T17:00:00"))

    def test_overnight_morning_leg(self):
        # Tuesday 05:00 EST (before 06:30 end) = 10:00 UTC; Monday listed
        s = schedules.validate_schedules([BEDTIME])[0]
        assert schedules.is_active(s, at("2026-11-17T10:00:00"))

    def test_overnight_morning_leg_day_not_listed(self):
        # Sunday 05:00 EST: yesterday Saturday is not in the Mon-Fri list
        s = schedules.validate_schedules([BEDTIME])[0]
        assert not schedules.is_active(s, at("2026-11-22T10:00:00"))

    def test_overnight_saturday_morning_active(self):
        # Saturday 05:00 EST: yesterday Friday IS listed (school night)
        s = schedules.validate_schedules([BEDTIME])[0]
        assert schedules.is_active(s, at("2026-11-21T10:00:00"))

    def test_disabled_never_active(self):
        s = schedules.validate_schedules(
            [dict(BEDTIME, enabled=False)])[0]
        assert not schedules.is_active(s, at("2026-11-18T03:30:00"))

    def test_same_day_window(self):
        s = schedules.validate_schedules(
            [dict(BEDTIME, start="12:00", end="13:00")])[0]
        # Monday 12:30 EST = 17:30 UTC
        assert schedules.is_active(s, at("2026-11-16T17:30:00"))
        assert not schedules.is_active(s, at("2026-11-16T18:30:00"))


BASE_DOC = {"default_policy": "allow", "allowlist": ["fun.example"],
            "blocklist": ["bad.example"],
            "category_rules": {"allow": [], "block": []}}


def mdb(tmp_path):
    path = tmp_path / "categories.json"
    path.write_text('{"domains": {"games.example": ["games"]}}')
    return category_db.CategoryDB.load(path)


class TestEngine:
    def doc(self, **kw):
        d = dict(BASE_DOC)
        d["_schedules"] = kw.pop("schedules", [BEDTIME])
        return d

    def test_blocks_during_window(self, tmp_path):
        eng = schedules.ScheduledPolicyEngine(
            self.doc(), mdb(tmp_path),
            now=lambda: at("2026-11-18T03:30:00"))
        assert eng.decide("games.example").action == "block"
        assert eng.decide("fun.example").action == "allow"  # allowlist wins

    def test_no_extra_blocks_outside_window(self, tmp_path):
        eng = schedules.ScheduledPolicyEngine(
            self.doc(), mdb(tmp_path),
            now=lambda: at("2026-11-17T17:00:00"))
        assert eng.decide("games.example").action == "allow"

    def test_allowlist_survives_domain_schedule(self, tmp_path):
        # fun.example is both allowlisted and schedule-blocked: the
        # explicit guardian allow must win even during the window.
        eng = schedules.ScheduledPolicyEngine(
            self.doc(), mdb(tmp_path),
            now=lambda: at("2026-11-18T03:30:00"))
        assert eng.decide("fun.example").action == "allow"

    def test_base_blocks_always_apply(self, tmp_path):
        eng = schedules.ScheduledPolicyEngine(
            self.doc(), mdb(tmp_path),
            now=lambda: at("2026-11-17T17:00:00"))
        assert eng.decide("bad.example").action == "block"

    def test_schedule_block_overrides_category_allow(self, tmp_path):
        doc = self.doc()
        doc["category_rules"] = {"allow": ["games"], "block": []}
        eng = schedules.ScheduledPolicyEngine(
            doc, mdb(tmp_path), now=lambda: at("2026-11-18T03:30:00"))
        assert eng.decide("games.example").action == "block"

    def test_is_a_policy_engine(self, tmp_path):
        eng = schedules.ScheduledPolicyEngine(self.doc(), mdb(tmp_path))
        assert isinstance(eng, policy_engine.PolicyEngine)

    def test_engine_cached_between_calls(self, tmp_path):
        eng = schedules.ScheduledPolicyEngine(
            self.doc(), mdb(tmp_path),
            now=lambda: at("2026-11-18T03:30:00"))
        first = eng._current_engine()
        assert eng._current_engine() is first

    def test_no_schedules_wrap_returns_original(self, tmp_path):
        doc = dict(BASE_DOC)
        base = policy_engine.PolicyEngine(doc, mdb(tmp_path))
        assert schedules.wrap_engine(doc, None, base) is base

    def test_bad_schedule_fails_closed_at_load(self, tmp_path):
        doc = self.doc(schedules=[dict(BEDTIME, timezone="Nowhere")])
        with pytest.raises(schedules.ScheduleError):
            schedules.ScheduledPolicyEngine(doc, mdb(tmp_path))


class TestWrapEngineSet:
    def test_single_policy_wrapped(self, tmp_path):
        ppath = tmp_path / "policy.json"
        cpath = tmp_path / "categories.json"
        import json
        doc = dict(BASE_DOC)
        doc["_schedules"] = [BEDTIME]
        ppath.write_text(json.dumps(doc))
        cpath.write_text('{"domains": {"games.example": ["games"]}}')
        raw_set = engine_set.EngineSet(
            default=policy_engine.PolicyEngine(
                BASE_DOC, category_db.CategoryDB.load(str(cpath))))
        wrapped = schedules.wrap_default_engine(
            raw_set, str(ppath), str(cpath),
            now=lambda: at("2026-11-18T03:30:00"))
        assert isinstance(wrapped.default, schedules.ScheduledPolicyEngine)
        assert wrapped.policy_for_client(None).decide(
            "games.example").action == "block"

    def test_no_schedules_returns_same_set(self, tmp_path):
        ppath = tmp_path / "policy.json"
        cpath = tmp_path / "categories.json"
        import json
        ppath.write_text(json.dumps(BASE_DOC))
        cpath.write_text('{"domains": {}}')
        raw_set = engine_set.EngineSet(
            default=policy_engine.PolicyEngine(
                BASE_DOC, category_db.CategoryDB.load(str(cpath))))
        assert schedules.wrap_default_engine(
            raw_set, str(ppath), str(cpath)) is raw_set

    def test_multipolicy_with_schedules_refused(self, tmp_path):
        ppath = tmp_path / "policy.json"
        cpath = tmp_path / "categories.json"
        import json
        doc = dict(BASE_DOC)
        doc["_schedules"] = [BEDTIME]
        ppath.write_text(json.dumps(doc))
        cpath.write_text('{"domains": {}}')
        db = category_db.CategoryDB.load(str(cpath))
        raw_set = engine_set.EngineSet(
            default=policy_engine.PolicyEngine(BASE_DOC, db),
            per_policy={1: policy_engine.PolicyEngine(BASE_DOC, db)})
        with pytest.raises(schedules.ScheduleError):
            schedules.wrap_default_engine(raw_set, str(ppath), str(cpath))
