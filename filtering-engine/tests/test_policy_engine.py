"""Automated tests for the central policy engine.

Covers: rule precedence, allowlists, blocklists, category rules,
unknown domains, subdomain matching, and normalization.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from category_db import CategoryDB
from policy_engine import PolicyConfigError, PolicyEngine, normalize_domain


def make_db():
    return CategoryDB({
        "school.example": ["education"],
        "adult-site.example": ["adult"],
        "mixed.example": ["adult", "education"],
        "news.example": ["news"],
    })


def make_engine(policy=None):
    base = {
        "default_policy": "allow",
        "allowlist": ["override.example"],
        "blocklist": ["tracker.example"],
        "category_rules": {"allow": ["education"], "block": ["adult"]},
    }
    if policy:
        base.update(policy)
    return PolicyEngine(base, make_db())


# -- precedence -----------------------------------------------------------

def test_explicit_allow_beats_everything():
    # override.example is allowlisted AND in a blocked category.
    db = CategoryDB({"override.example": ["adult"]})
    engine = PolicyEngine({
        "default_policy": "block",
        "allowlist": ["override.example"],
        "blocklist": ["override.example"],
        "category_rules": {"allow": [], "block": ["adult"]},
    }, db)
    d = engine.decide("override.example")
    assert d.action == "allow"
    assert d.rule == "explicit_allow"


def test_explicit_block_beats_category_rules():
    db = CategoryDB({"tracker.example": ["education"]})
    engine = PolicyEngine({
        "default_policy": "allow",
        "allowlist": [],
        "blocklist": ["tracker.example"],
        "category_rules": {"allow": ["education"], "block": []},
    }, db)
    d = engine.decide("tracker.example")
    assert d.action == "block"
    assert d.rule == "explicit_block"


def test_category_block_beats_category_allow():
    engine = make_engine()
    d = engine.decide("mixed.example")  # adult + education
    assert d.action == "block"
    assert d.rule == "category_block"
    assert d.category == "adult"


def test_category_allow_beats_default_block():
    engine = make_engine({"default_policy": "block"})
    d = engine.decide("school.example")
    assert d.action == "allow"
    assert d.rule == "category_allow"
    assert d.category == "education"


def test_category_block_applies():
    engine = make_engine()
    d = engine.decide("adult-site.example")
    assert d.action == "block"
    assert d.rule == "category_block"


def test_default_policy_when_nothing_matches():
    assert make_engine().decide("anything-else.example").action == "allow"
    engine = make_engine({"default_policy": "block"})
    d = engine.decide("anything-else.example")
    assert d.action == "block"
    assert d.rule == "default"


def test_uncategorized_domain_uses_default_not_category():
    engine = make_engine({"default_policy": "block"})
    d = engine.decide("news.example")  # category news: in neither rule list
    assert d.rule == "default"
    assert d.action == "block"


# -- allowlists / blocklists -----------------------------------------------

def test_blocklist_match():
    d = make_engine().decide("tracker.example")
    assert (d.action, d.rule) == ("block", "explicit_block")


def test_allowlist_match():
    d = make_engine().decide("override.example")
    assert (d.action, d.rule) == ("allow", "explicit_allow")


def test_subdomains_match_listed_parent():
    engine = make_engine()
    assert engine.decide("sub.tracker.example").action == "block"
    assert engine.decide("deep.sub.tracker.example").action == "block"
    assert engine.decide("www.override.example").action == "allow"


def test_partial_suffix_does_not_match():
    # "eviltracker.example" must NOT match the listed "tracker.example".
    assert make_engine().decide("eviltracker.example").rule == "default"


# -- categories --------------------------------------------------------------

def test_parent_domain_category_applies_to_subdomain():
    d = make_engine().decide("www.school.example")
    assert (d.action, d.rule) == ("allow", "category_allow")


def test_most_specific_category_entry_wins():
    db = CategoryDB({
        "example.org": ["adult"],
        "safe.example.org": ["education"],
    })
    engine = PolicyEngine({
        "default_policy": "block",
        "allowlist": [], "blocklist": [],
        "category_rules": {"allow": ["education"], "block": ["adult"]},
    }, db)
    assert engine.decide("www.safe.example.org").rule == "category_allow"
    assert engine.decide("other.example.org").rule == "category_block"


# -- unknown domains / normalization ----------------------------------------

def test_unknown_domain_default_allow():
    d = make_engine().decide("never-seen-before.example")
    assert (d.action, d.rule) == ("allow", "default")


def test_unknown_domain_default_block():
    d = make_engine({"default_policy": "block"}).decide("never-seen-before.example")
    assert (d.action, d.rule) == ("block", "default")


def test_normalization_case_and_trailing_dot():
    assert normalize_domain("  Www.Tracker.EXAMPLE. ") == "www.tracker.example"
    d = make_engine().decide("TRACKER.EXAMPLE.")
    assert (d.action, d.rule) == ("block", "explicit_block")


def test_empty_domain_rejected():
    with pytest.raises(ValueError):
        make_engine().decide("   ")


# -- invalid configuration ----------------------------------------------------

def test_invalid_default_policy_rejected():
    with pytest.raises(PolicyConfigError):
        PolicyEngine({"default_policy": "maybe"}, make_db())


def test_category_in_both_lists_rejected():
    with pytest.raises(PolicyConfigError):
        PolicyEngine({
            "default_policy": "allow",
            "category_rules": {"allow": ["news"], "block": ["news"]},
        }, make_db())
