"""Startup validation tests for the policy configuration.

The complete policy structure must be validated before the service
starts. Every invalid type or malformed value must fail clearly with
PolicyConfigError - never silently turn a malformed rule into an
unintended allow or block decision (a silently ignored block rule is an
unintended allow, and vice versa).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from category_db import CategoryDB
from policy_engine import PolicyConfigError, PolicyEngine


def make_db():
    return CategoryDB({"school.example": ["education"]})


VALID_POLICY = {
    "default_policy": "allow",
    "allowlist": ["override.example"],
    "blocklist": ["tracker.example"],
    "category_rules": {"allow": ["education"], "block": ["adult"]},
}


def policy(**overrides):
    merged = dict(VALID_POLICY)
    merged.update(overrides)
    return merged


# -- valid configurations are accepted ----------------------------------------

def test_valid_full_policy_accepted():
    engine = PolicyEngine(VALID_POLICY, make_db())
    assert engine.decide("override.example").rule == "explicit_allow"
    assert engine.decide("tracker.example").rule == "explicit_block"


def test_minimal_policy_accepted():
    engine = PolicyEngine({"default_policy": "block"}, make_db())
    assert engine.decide("anything.example").action == "block"


def test_metadata_keys_allowed():
    engine = PolicyEngine(policy(_meta={"note": "kept by operators"}), make_db())
    assert engine.decide("tracker.example").action == "block"


def test_entries_are_normalized():
    engine = PolicyEngine(policy(allowlist=["  Www.Override.EXAMPLE. "]),
                          make_db())
    assert engine.decide("www.override.example").rule == "explicit_allow"


# -- top-level structure -------------------------------------------------------

def test_policy_must_be_an_object():
    with pytest.raises(PolicyConfigError):
        PolicyEngine(["default_policy", "allow"], make_db())


def test_unknown_top_level_key_rejected():
    # A typo like "allow_list" must fail loudly, not silently drop the
    # rules the operator thought were active.
    with pytest.raises(PolicyConfigError, match="unknown policy keys"):
        PolicyEngine(policy(allow_list=["tracker.example"]), make_db())


# -- default_policy -------------------------------------------------------------

def test_missing_default_policy_rejected():
    with pytest.raises(PolicyConfigError, match="default_policy"):
        PolicyEngine({"allowlist": []}, make_db())


def test_non_string_default_policy_rejected():
    with pytest.raises(PolicyConfigError, match="default_policy"):
        PolicyEngine(policy(default_policy=1), make_db())


def test_invalid_default_policy_value_rejected():
    with pytest.raises(PolicyConfigError, match="default_policy"):
        PolicyEngine(policy(default_policy="maybe"), make_db())


# -- allowlist / blocklist -------------------------------------------------------

def test_allowlist_must_be_a_list_not_a_string():
    # The silent-failure case: a bare string would otherwise be iterated
    # character by character, so "tracker.example" would never match and
    # the intended block would silently never happen.
    with pytest.raises(PolicyConfigError, match="allowlist must be a list"):
        PolicyEngine(policy(allowlist="tracker.example"), make_db())


def test_blocklist_must_be_a_list():
    with pytest.raises(PolicyConfigError, match="blocklist must be a list"):
        PolicyEngine(policy(blocklist={"tracker.example": True}), make_db())


def test_list_entry_must_be_a_string():
    with pytest.raises(PolicyConfigError, match="allowlist\[0\]"):
        PolicyEngine(policy(allowlist=[123]), make_db())


def test_empty_domain_entry_rejected():
    with pytest.raises(PolicyConfigError, match="blocklist\[1\].*empty"):
        PolicyEngine(policy(blocklist=["tracker.example", ""]), make_db())


def test_whitespace_only_domain_entry_rejected():
    with pytest.raises(PolicyConfigError, match="empty"):
        PolicyEngine(policy(allowlist=["   "]), make_db())


def test_invalid_domain_entry_rejected():
    with pytest.raises(PolicyConfigError, match="invalid domain"):
        PolicyEngine(policy(blocklist=["exa mple.com"]), make_db())


# -- category_rules --------------------------------------------------------------

def test_category_rules_must_be_an_object():
    with pytest.raises(PolicyConfigError, match="category_rules must be an object"):
        PolicyEngine(policy(category_rules=["adult"]), make_db())


def test_category_rules_unknown_key_rejected():
    with pytest.raises(PolicyConfigError, match="unknown category_rules keys"):
        PolicyEngine(policy(category_rules={"allowed": ["adult"]}), make_db())


def test_category_allow_must_be_a_list():
    with pytest.raises(PolicyConfigError, match="category_rules.allow must be a list"):
        PolicyEngine(policy(category_rules={"allow": "adult", "block": []}),
                     make_db())


def test_category_entry_must_be_a_string():
    with pytest.raises(PolicyConfigError, match="category_rules.block\[0\]"):
        PolicyEngine(policy(category_rules={"allow": [], "block": [5]}),
                     make_db())


def test_empty_category_entry_rejected():
    with pytest.raises(PolicyConfigError, match="empty category"):
        PolicyEngine(policy(category_rules={"allow": [""], "block": []}),
                     make_db())


def test_invalid_category_entry_rejected():
    with pytest.raises(PolicyConfigError, match="invalid category name"):
        PolicyEngine(policy(category_rules={"allow": [],
                                            "block": ["adult content!"]}),
                     make_db())


def test_category_in_both_lists_rejected():
    with pytest.raises(PolicyConfigError, match="both allow and block"):
        PolicyEngine(policy(category_rules={"allow": ["news"],
                                            "block": ["news"]}),
                     make_db())
