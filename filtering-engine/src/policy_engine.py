"""Central policy engine for the KosherGuard core filtering engine (Stage 3).

Decides whether a domain should be allowed or blocked based on a
configurable policy. Policies are pure data (JSON) loaded at startup, so
policy changes never require application code changes.

Rule precedence (highest first) - also documented in README.md:

1. Explicit allowlist match   -> ALLOW (rule: explicit_allow)
2. Explicit blocklist match   -> BLOCK (rule: explicit_block)
3. Category block rule        -> BLOCK (rule: category_block)
4. Category allow rule        -> ALLOW (rule: category_allow)
5. Default policy             -> allow/block (rule: default)

A listed domain matches itself and every subdomain of it, so a list entry
of "example.com" covers "www.example.com" and "a.b.example.com".

Configuration validation: the complete policy structure is validated at
startup by validate_policy() before the engine (or the DNS service) will
run. Invalid types and malformed values are rejected with a
PolicyConfigError that names the exact offending field. A malformed rule
is never silently ignored, because a silently ignored block rule is an
unintended allow and a silently ignored allow rule is an unintended
block. See README.md for the schema.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

VALID_ACTIONS = ("allow", "block")

# Domain and category syntax, shared with category_db.py (which imports
# them from here so the policy engine and the database agree).
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")

# The complete policy schema. Keys starting with "_" are tolerated as
# metadata; any other unknown key is rejected so a typo (e.g.
# "allow_list") fails loudly instead of silently dropping the rules the
# operator thought were active.
POLICY_KEYS = {"default_policy", "allowlist", "blocklist", "category_rules"}
CATEGORY_RULE_KEYS = {"allow", "block"}


class PolicyConfigError(ValueError):
    """Raised when a policy configuration is invalid."""


@dataclass(frozen=True)
class Decision:
    """The outcome of one policy decision.

    action:   "allow" or "block"
    rule:     which rule fired ("explicit_allow", "explicit_block",
              "category_block", "category_allow", "default")
    reason:   human-readable explanation, safe for logs
    category: the category that caused the decision, if a category rule fired
    """

    action: str
    rule: str
    reason: str
    category: Optional[str] = None


def normalize_domain(domain: str) -> str:
    """Lowercase, strip surrounding whitespace and any trailing dot."""
    return domain.strip().lower().rstrip(".")


def domain_matches(domain: str, listed: str) -> bool:
    """True if `domain` equals `listed` or is a subdomain of it."""
    return domain == listed or domain.endswith("." + listed)


def _domain_list(value, name: str) -> List[str]:
    """Validate one domain list (allowlist/blocklist); returns the
    normalized entries. Every malformed entry is a hard error."""
    if not isinstance(value, list):
        raise PolicyConfigError(
            f"{name} must be a list of domain strings, got {type(value).__name__}"
        )
    result = []
    for i, entry in enumerate(value):
        where = f"{name}[{i}]"
        if not isinstance(entry, str):
            raise PolicyConfigError(
                f"{where}: domain entry must be a string, "
                f"got {type(entry).__name__} ({entry!r})"
            )
        domain = normalize_domain(entry)
        if not domain:
            raise PolicyConfigError(f"{where}: empty domain entry")
        if not DOMAIN_RE.match(domain):
            raise PolicyConfigError(f"{where}: invalid domain {entry!r}")
        result.append(domain)
    return result


def _category_list(value, name: str) -> List[str]:
    """Validate one category list (category_rules.allow/.block)."""
    if not isinstance(value, list):
        raise PolicyConfigError(
            f"{name} must be a list of category strings, got {type(value).__name__}"
        )
    result = []
    for i, entry in enumerate(value):
        where = f"{name}[{i}]"
        if not isinstance(entry, str):
            raise PolicyConfigError(
                f"{where}: category entry must be a string, "
                f"got {type(entry).__name__} ({entry!r})"
            )
        category = entry.strip().lower()
        if not category:
            raise PolicyConfigError(f"{where}: empty category entry")
        if not CATEGORY_RE.match(category):
            raise PolicyConfigError(f"{where}: invalid category name {entry!r}")
        result.append(category)
    return result


def validate_policy(policy: dict) -> dict:
    """Validate the complete policy structure; returns the normalized
    policy. Raises PolicyConfigError on the first problem found, with a
    message naming the exact field. Called before the service starts, so
    bad configuration fails clearly at startup instead of mis-filtering
    live traffic."""
    if not isinstance(policy, dict):
        raise PolicyConfigError(
            f"policy must be a JSON object, got {type(policy).__name__}"
        )
    unknown = {
        key
        for key in policy
        if key not in POLICY_KEYS
        and not (isinstance(key, str) and key.startswith("_"))
    }
    if unknown:
        raise PolicyConfigError(
            f"unknown policy keys: {sorted(unknown)} "
            f"(valid keys: {sorted(POLICY_KEYS)}; "
            f"keys starting with '_' are allowed for metadata)"
        )

    default = policy.get("default_policy")
    if not isinstance(default, str) or default not in VALID_ACTIONS:
        raise PolicyConfigError(
            f"default_policy must be one of {VALID_ACTIONS}, got {default!r}"
        )

    allowlist = _domain_list(policy.get("allowlist", []), "allowlist")
    blocklist = _domain_list(policy.get("blocklist", []), "blocklist")

    rules = policy.get("category_rules", {})
    if not isinstance(rules, dict):
        raise PolicyConfigError(
            f"category_rules must be an object with 'allow' and 'block' "
            f"lists, got {type(rules).__name__}"
        )
    unknown_rule_keys = set(rules) - CATEGORY_RULE_KEYS
    if unknown_rule_keys:
        raise PolicyConfigError(
            f"unknown category_rules keys: {sorted(unknown_rule_keys)} "
            f"(valid keys: {sorted(CATEGORY_RULE_KEYS)})"
        )
    category_allow = _category_list(rules.get("allow", []), "category_rules.allow")
    category_block = _category_list(rules.get("block", []), "category_rules.block")
    overlap = set(category_allow) & set(category_block)
    if overlap:
        raise PolicyConfigError(
            f"categories listed in both allow and block rules: {sorted(overlap)}"
        )

    return {
        "default_policy": default,
        "allowlist": allowlist,
        "blocklist": blocklist,
        "category_allow": category_allow,
        "category_block": category_block,
    }


class PolicyEngine:
    """Evaluates domains against an allow/block/category policy."""

    def __init__(self, policy: dict, category_db) -> None:
        validated = validate_policy(policy)
        self._default = validated["default_policy"]
        self._allowlist = set(validated["allowlist"])
        self._blocklist = set(validated["blocklist"])
        self._category_allow = set(validated["category_allow"])
        self._category_block = set(validated["category_block"])
        self._db = category_db

    def decide(self, domain: str) -> Decision:
        """Return the Decision for a domain (any case, trailing dot ok)."""
        domain = normalize_domain(domain)
        if not domain:
            raise ValueError("empty domain")

        # 1. Explicit allowlist wins over everything (surgical overrides).
        hit = self._best_match(domain, self._allowlist)
        if hit:
            return Decision(
                "allow", "explicit_allow",
                f"{domain} matches allowlist entry {hit}",
            )

        # 2. Explicit blocklist.
        hit = self._best_match(domain, self._blocklist)
        if hit:
            return Decision(
                "block", "explicit_block",
                f"{domain} matches blocklist entry {hit}",
            )

        categories = self._db.categories_for(domain)

        # 3. Blocked category beats allowed category.
        for cat in sorted(categories):
            if cat in self._category_block:
                return Decision(
                    "block", "category_block",
                    f"{domain} is in blocked category {cat!r}",
                    category=cat,
                )

        # 4. Allowed category.
        for cat in sorted(categories):
            if cat in self._category_allow:
                return Decision(
                    "allow", "category_allow",
                    f"{domain} is in allowed category {cat!r}",
                    category=cat,
                )

        # 5. Default policy.
        return Decision(
            self._default, "default",
            f"no rule matched {domain}; default policy is {self._default}",
        )

    @staticmethod
    def _best_match(domain: str, listed: set) -> Optional[str]:
        """The longest listed entry matching the domain (deterministic)."""
        best = None
        for entry in listed:
            if domain_matches(domain, entry) and (best is None or len(entry) > len(best)):
                best = entry
        return best
