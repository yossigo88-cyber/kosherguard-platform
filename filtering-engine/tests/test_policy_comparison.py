"""Tests for the Stage 11A tighten-only comparator (plan 4.5).

The full comparison matrix: equivalent and demonstrably stricter
candidates pass; less-restrictive, incomparable, invalid, and
cap-exceeded candidates fail. The comparator is a pure deterministic
function; restrictiveness is never read off names, labels, or rule
counts.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import policy_comparison  # noqa: E402
from policy_comparison import at_least_as_restrictive  # noqa: E402


def policy(default="allow", allow=(), block=(), cat_allow=(), cat_block=()):
    return {
        "default_policy": default,
        "allowlist": list(allow),
        "blocklist": list(block),
        "category_rules": {"allow": list(cat_allow), "block": list(cat_block)},
    }


# -- acceptance cases ---------------------------------------------------

def test_identical_policies_are_equivalent():
    p = policy(block=["bad.test"], cat_block=["adult-content"])
    result = at_least_as_restrictive(p, dict(p))
    assert result.allowed, result.reason


def test_block_all_vs_block_all_allowed():
    assert at_least_as_restrictive(
        policy(default="block"), policy(default="block")).allowed


def test_strict_superset_blocking_allowed():
    baseline = policy(block=["bad.test"], cat_block=["adult-content"])
    candidate = policy(block=["bad.test", "worse.test"],
                       cat_block=["adult-content", "gambling"])
    assert at_least_as_restrictive(candidate, baseline).allowed


def test_default_block_candidate_over_default_allow_baseline():
    assert at_least_as_restrictive(policy(default="block"),
                                   policy(default="allow")).allowed


def test_correlated_shared_lists_no_false_rejection():
    # Both policies share allowlist and blocklist entries; signatures
    # whose per-policy halves cannot differ are infeasible and must not
    # cause false rejection.
    baseline = policy(allow=["school.test"], block=["bad.test"],
                      cat_block=["adult-content"])
    candidate = policy(allow=["school.test"],
                       block=["bad.test", "extra.test"],
                       cat_block=["adult-content", "malware-phishing"])
    result = at_least_as_restrictive(candidate, baseline)
    assert result.allowed, result.reason


def test_equivalent_different_spelling_allowed():
    baseline = policy(block=["bad.test"], cat_block=["news"])
    candidate = {
        "default_policy": "allow",
        "allowlist": [],
        "blocklist": ["BAD.test."],  # normalizes to bad.test
        "category_rules": {"allow": [], "block": ["news"]},
    }
    assert at_least_as_restrictive(candidate, baseline).allowed


# -- rejection cases -----------------------------------------------------

def test_candidate_allowlisting_baseline_blocked_domain_rejected():
    baseline = policy(block=["bad.test"])
    candidate = policy(allow=["bad.test"])
    result = at_least_as_restrictive(candidate, baseline)
    assert not result.allowed
    assert "less restrictive" in result.reason


def test_candidate_dropping_baseline_blocklist_entry_rejected():
    baseline = policy(block=["bad.test", "worse.test"])
    candidate = policy(block=["worse.test"])  # bad.test becomes allowed
    assert not at_least_as_restrictive(candidate, baseline).allowed


def test_candidate_allowlisting_subdomain_of_blocked_rejected():
    # The engine's allowlist really would win on the subdomain (suffix
    # comparability makes the signature feasible).
    baseline = policy(block=["bad.test"])
    candidate = policy(block=["bad.test"], allow=["chat.bad.test"])
    assert not at_least_as_restrictive(candidate, baseline).allowed


def test_incomparable_policies_rejected():
    a = policy(allow=["a.test"], block=["b.test"])
    b = policy(allow=["b.test"], block=["a.test"])
    assert not at_least_as_restrictive(a, b).allowed
    assert not at_least_as_restrictive(b, a).allowed


def test_looser_default_rejected():
    baseline = policy(default="block", allow=["school.test"])
    candidate = policy(default="allow")
    assert not at_least_as_restrictive(candidate, baseline).allowed


def test_allowlist_overrides_category_block_makes_candidate_looser():
    # Precedence: an explicit allowlist entry beats a category block, so
    # adding it really does loosen filtering and must be rejected.
    baseline = policy(cat_block=["news"])
    candidate = policy(allow=["good.test"], cat_block=["news"])
    assert not at_least_as_restrictive(candidate, baseline).allowed


def test_category_allow_vs_category_block_rejected():
    baseline = policy(cat_block=["games"])
    candidate = policy(cat_allow=["games"])  # invalid alone (overlap) -> ok
    assert not at_least_as_restrictive(candidate, baseline).allowed


def test_category_block_removed_rejected():
    baseline = policy(cat_block=["games", "gambling"])
    candidate = policy(cat_block=["games"])
    assert not at_least_as_restrictive(candidate, baseline).allowed


def test_default_allow_vs_default_block_interplay():
    baseline = policy(default="block", allow=["school.test"])
    candidate = policy(default="allow", block=["bad.test"])
    assert not at_least_as_restrictive(candidate, baseline).allowed
    # But an identical-allowlist block-default candidate passes.
    candidate2 = policy(default="block", allow=["school.test"],
                        block=["bad.test"])
    assert at_least_as_restrictive(candidate2, baseline).allowed


def test_invalid_candidate_rejected():
    result = at_least_as_restrictive({"default_policy": "bogus"}, policy())
    assert not result.allowed
    assert "invalid" in result.reason


def test_invalid_baseline_rejected():
    result = at_least_as_restrictive(policy(), {"default_policy": "bogus"})
    assert not result.allowed
    assert "invalid" in result.reason


def test_names_and_counts_are_not_the_basis():
    # A policy "named" strict with more rules can still be looser.
    baseline = policy(block=["bad.test"])
    candidate = policy(allow=["bad.test"],
                       block=["x.test", "y.test", "z.test"],
                       cat_block=["games", "gambling", "news"])
    assert not at_least_as_restrictive(candidate, baseline).allowed


# -- fail-safe caps -------------------------------------------------------

def test_category_cap_rejects():
    cats = [f"cat-{i:02d}" for i in range(11)]
    baseline = policy(cat_block=cats)
    candidate = policy(cat_block=[f"catx-{i:02d}" for i in range(11)])
    result = at_least_as_restrictive(candidate, baseline)  # 22 > 20
    assert not result.allowed
    assert "categor" in result.reason


def test_rule_list_cap_rejects():
    baseline = policy(block=[f"d{i}.test" for i in range(501)])
    result = at_least_as_restrictive(policy(), baseline)
    assert not result.allowed
    assert "cap" in result.reason


def test_witness_choice_cap_rejects(monkeypatch):
    monkeypatch.setattr(
        policy_comparison, "MAX_WITNESS_CHOICES_PER_SIGNATURE", 4)
    baseline = policy(allow=["a1.test", "a2.test", "a3.test"])
    candidate = policy(allow=["b1.test", "b2.test", "b3.test"])
    result = at_least_as_restrictive(candidate, baseline)
    assert not result.allowed
    assert "fail safe" in result.reason


# -- determinism ----------------------------------------------------------

def test_pure_and_deterministic():
    baseline = policy(block=["bad.test"], cat_block=["news"])
    candidate = policy(block=["bad.test", "x.test"], cat_block=["news"])
    first = at_least_as_restrictive(candidate, baseline)
    second = at_least_as_restrictive(candidate, baseline)
    assert first == second
    assert first.allowed
