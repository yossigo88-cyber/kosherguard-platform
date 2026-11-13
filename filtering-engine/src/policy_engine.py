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
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

VALID_ACTIONS = ("allow", "block")


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


class PolicyEngine:
    """Evaluates domains against an allow/block/category policy."""

    def __init__(self, policy: dict, category_db) -> None:
        default = policy.get("default_policy")
        if default not in VALID_ACTIONS:
            raise PolicyConfigError(
                f"default_policy must be one of {VALID_ACTIONS}, got {default!r}"
            )
        self._default = default
        self._allowlist = {normalize_domain(d) for d in policy.get("allowlist", [])}
        self._blocklist = {normalize_domain(d) for d in policy.get("blocklist", [])}
        rules = policy.get("category_rules", {})
        if not isinstance(rules, dict):
            raise PolicyConfigError("category_rules must be an object")
        self._category_allow = set(rules.get("allow", []))
        self._category_block = set(rules.get("block", []))
        overlap = self._category_allow & self._category_block
        if overlap:
            raise PolicyConfigError(
                f"categories listed in both allow and block rules: {sorted(overlap)}"
            )
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
