"""Baseline-floor and time-window semantics of the exception overlay.

The protected baseline (the tenant's selected default policy) is a
floor no allow_domains exception can cross: delegated exceptions relax
guardian-added restrictions, never the owner-controlled baseline.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from policy_bundle import ExceptionOverlay, PolicyBundle  # noqa: E402


class StubEngine:
    """Decides from fixed rule sets, like a compiled policy engine."""

    def __init__(self, blocked=(), default_action='allow'):
        self.blocked = set(blocked)
        self.default_action = default_action

    def decide(self, domain):
        from policy_engine import Decision
        if domain in self.blocked:
            return Decision(action='block', rule='explicit_block',
                            reason=f'{domain} blocked', category=None)
        return Decision(action=self.default_action, rule='default',
                        reason='default', category=None)


NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)


def entry(kind='allow_domains', domains=(), starts=None, expires=None):
    return {
        'kind': kind,
        'domains': list(domains),
        'starts_at': (starts or NOW - timedelta(hours=1)).isoformat(),
        'expires_at': (expires or NOW + timedelta(hours=1)).isoformat(),
        'exception_id': 7}


def overlay(assigned, baseline, entries, now=NOW):
    return ExceptionOverlay(assigned, tuple(entries), now,
                            baseline=baseline)


class TestBaselineFloor:
    def test_allow_domains_cannot_override_baseline_block(self):
        # Guardian-added restriction (assigned policy) and the baseline
        # block different domains; the exception names both.
        assigned = StubEngine(blocked={'game.example'})
        baseline = StubEngine(blocked={'adult.example'})
        ov = overlay(assigned, baseline,
                     [entry(domains=['adult.example', 'game.example'])])
        assert ov.decide('adult.example').action == 'block'
        assert 'protected baseline' in ov.decide('adult.example').reason

    def test_exception_relaxes_guardian_added_block(self):
        assigned = StubEngine(blocked={'game.example'})
        baseline = StubEngine(blocked={'adult.example'})
        ov = overlay(assigned, baseline, [entry(domains=['game.example'])])
        decision = ov.decide('game.example')
        assert decision.action == 'allow'
        assert decision.rule == 'exception_allow_domains'

    def test_subdomain_of_baseline_block_stays_blocked(self):
        assigned = StubEngine()
        baseline = StubEngine(blocked={'www.adult.example'})
        ov = overlay(assigned, baseline, [entry(domains=['adult.example'])])
        # Baseline's own engine decides sub.example independently; the
        # overlay defers to whatever the baseline decides.
        assert ov.decide('www.adult.example').action == 'block'
        assert ov.decide('other.example').action == 'allow'

    def test_baseline_default_block_stands(self):
        # Baseline default-deny (schedule/default block) cannot be
        # excepted either.
        assigned = StubEngine()
        baseline = StubEngine(default_action='block')
        ov = overlay(assigned, baseline, [entry(domains=['x.example'])])
        assert ov.decide('x.example').action == 'block'

    def test_disable_policy_remains_full_bypass_owner_only(self):
        assigned = StubEngine(blocked={'game.example'})
        baseline = StubEngine(blocked={'adult.example'})
        ov = overlay(assigned, baseline, [entry(kind='disable_policy')])
        assert ov.decide('adult.example').action == 'allow'
        assert ov.decide('game.example').action == 'allow'


class TestTimeWindows:
    def test_not_yet_started_exception_does_not_apply(self):
        assigned = StubEngine(blocked={'game.example'})
        ov = overlay(assigned, StubEngine(),
                     [entry(domains=['game.example'],
                            starts=NOW + timedelta(hours=1))])
        assert ov.decide('game.example').action == 'block'

    def test_expired_exception_does_not_apply(self):
        assigned = StubEngine(blocked={'game.example'})
        ov = overlay(assigned, StubEngine(),
                     [entry(domains=['game.example'],
                            expires=NOW - timedelta(seconds=1))])
        assert ov.decide('game.example').action == 'block'

    def test_expiry_boundary_is_exclusive(self):
        assigned = StubEngine(blocked={'game.example'})
        ov = overlay(assigned, StubEngine(),
                     [entry(domains=['game.example'], expires=NOW)],
                     now=NOW)
        assert ov.decide('game.example').action == 'block'
        before = overlay(assigned, StubEngine(),
                         [entry(domains=['game.example'], expires=NOW)],
                         now=NOW - timedelta(microseconds=1))
        assert before.decide('game.example').action == 'allow'

    def test_no_entries_falls_through(self):
        assigned = StubEngine(blocked={'game.example'})
        ov = overlay(assigned, StubEngine(), [])
        assert ov.decide('game.example').action == 'block'


class TestBundleWiring:
    def test_for_device_passes_default_engine_as_floor(self):
        class Engines:
            pass
        engines = Engines()
        engines.default = StubEngine(blocked={'adult.example'})
        engines.per_policy = {2: StubEngine(blocked={'game.example'})}
        bundle = PolicyBundle(engines=engines, devices={'9': 2},
                              revision=3, tenant_id=1,
                              exceptions={'9': (entry(
                                  domains=['adult.example',
                                           'game.example']),)},
                              now=NOW)
        engine = bundle.for_device(9)
        assert engine.decide('adult.example').action == 'block'
        assert engine.decide('game.example').action == 'allow'


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "filtering-engine", "src"))
import category_db  # noqa: E402
from schedules import ScheduledPolicyEngine  # noqa: E402


def real_engine(doc, domains=None, now=NOW):
    db = category_db.CategoryDB(domains or {}, meta={})
    return ScheduledPolicyEngine(doc, db, now=lambda: now)


BASELINE_DOC = {
    'default_policy': 'allow', 'blocklist': [], 'allowlist': [],
    'category_rules': {'allow': [], 'block': ['adult']},
    '_schedules': [{'name': 'bedtime', 'days': [0, 1, 2, 3, 4, 5, 6],
                    'start': '00:00', 'end': '23:59', 'timezone': 'UTC',
                    'block_categories': [], 'block_domains': ['fun.example'],
                    'enabled': True}]}

ASSIGNED_DOC = {
    'default_policy': 'allow', 'blocklist': ['games.example'],
    'allowlist': [], 'category_rules': {'allow': [], 'block': []}}


class TestRealEngines:
    """The floor holds when baseline blocks come from real engine
    machinery: category rules and time schedules, not stubs."""

    def test_baseline_category_block_stands(self):
        baseline = real_engine(BASELINE_DOC, {'adult-site.example': ['adult']})
        assigned = real_engine(ASSIGNED_DOC, {'adult-site.example': ['adult']})
        ov = overlay(assigned, baseline, [entry(
            domains=['adult-site.example', 'games.example'])])
        decision = ov.decide('adult-site.example')
        assert decision.action == 'block'
        assert 'protected baseline' in decision.reason

    def test_baseline_schedule_block_stands(self):
        baseline = real_engine(BASELINE_DOC)
        assigned = real_engine(ASSIGNED_DOC)
        ov = overlay(assigned, baseline, [entry(domains=['fun.example'])])
        assert ov.decide('fun.example').action == 'block'

    def test_guardian_added_block_still_relaxes_with_real_engines(self):
        baseline = real_engine(BASELINE_DOC)
        assigned = real_engine(ASSIGNED_DOC)
        ov = overlay(assigned, baseline, [entry(domains=['games.example'])])
        assert ov.decide('games.example').action == 'allow'
