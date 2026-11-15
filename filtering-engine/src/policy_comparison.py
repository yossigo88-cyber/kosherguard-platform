"""The tighten-only policy comparator (Stage 11A).

Implements the mandatory tighten-only security rule of
docs/reviews/STAGE_11_TECHNICAL_PLAN.md section 4.5: a policy assigned to
a registry entry reached through unauthenticated network bindings must
never be less restrictive than the default policy. "Less restrictive" is
decided here, by a deterministic comparison derived from the engine's
actual decision semantics - never by policy names, labels, or rule counts.

Method (the plan's feasible-signature method): a domain's decision depends
on exactly four inputs - whether it matches the candidate's allowlist
(alA), the candidate's blocklist (blA), the baseline's allowlist (alB),
the baseline's blocklist (blB) - plus its category set C. For each of the
16 match signatures the method first decides whether any real domain can
have it, using the actual suffix semantics of policy_engine.domain_matches
(an entry matches the domain itself and every subdomain of it). A
signature is FEASIBLE iff there is a choice of one entry from each list
the signature requires a match in, with all chosen entries mutually
suffix-comparable, whose most specific (longest) entry f is neither equal
to nor a subdomain of any entry of the lists the signature requires NO
match in; the certificate is the domain f itself. If a required-match list
is empty the signature is infeasible; the all-zero signature is always
feasible (the domain space is infinite and finitely many suffix rules
cannot cover it). Then:

    candidate A is AT LEAST AS RESTRICTIVE AS baseline B
      <=> for every feasible signature and every C that is a subset of U
          (U = the union of the four category rule lists):
          dec(B, alB, blB, C) == block  implies  dec(A, alA, blA, C) == block

where dec reproduces PolicyEngine.decide's precedence: explicit allowlist
match -> allow; explicit blocklist match -> block; any category of the
domain in category_block -> block; any category in category_allow ->
allow; otherwise the policy's default_policy.

C ranges over ALL subsets of U, so the verdict never depends on the
current category-database contents (documented conservatism: a pair that
is safe only because of today's category assignments is rejected). Both
policies are first normalized by the engine's own validate_policy(), so
the comparison inputs are the exact data the engine would enforce, and a
policy that fails validation is rejected.

Fail-safe caps (plan 4.5): at most 20 referenced categories, at most 500
entries per rule list, at most 100,000 witness-choice combinations per
signature. Any cap failure REJECTS the comparison - safety is never
guessed. The comparison is a pure deterministic function of the two
normalized policy documents: same inputs, same answer.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

from policy_engine import PolicyConfigError, domain_matches, validate_policy

MAX_REFERENCED_CATEGORIES = 20
MAX_RULE_LIST_ENTRIES = 500
MAX_WITNESS_CHOICES_PER_SIGNATURE = 100_000


@dataclass(frozen=True)
class ComparisonResult:
    """The verdict of one tighten-only comparison.

    allowed: True only when the candidate is proven at least as
             restrictive as the baseline.
    reason:  human-readable explanation (the rejection reason, or why the
             pair is accepted). Safe for API responses and audit details.
    """

    allowed: bool
    reason: str


class _Reject(Exception):
    """Internal control flow: the comparison must fail (caps, input)."""


def _decision(policy, al: bool, bl: bool, categories: frozenset) -> str:
    """PolicyEngine.decide's precedence for one signature + category set."""
    if al:
        return "allow"
    if bl:
        return "block"
    if categories & policy["_category_block"]:
        return "block"
    if categories & policy["_category_allow"]:
        return "allow"
    return policy["default_policy"]


def _suffix_comparable(a: str, b: str) -> bool:
    """True when one entry equals the other or is a subdomain of it."""
    return domain_matches(a, b) or domain_matches(b, a)


def _signature_feasible(match_lists: list, nomatch_lists: list) -> bool:
    """True when some real domain can have this match signature.

    A witness is one entry chosen from each required-match list, all
    mutually suffix-comparable, whose most specific entry f is matched by
    no entry of any required-NO-match list; f itself is then a domain with
    exactly this signature.
    """
    if not match_lists:
        # The all-zero signature: always feasible.
        return True
    for entries in match_lists:
        if not entries:
            return False
    choices = 1
    for entries in match_lists:
        choices *= len(entries)
    if choices > MAX_WITNESS_CHOICES_PER_SIGNATURE:
        raise _Reject(
            f"comparison infeasible to compute safely: a match signature has "
            f"{choices} witness-entry combinations, above the cap of "
            f"{MAX_WITNESS_CHOICES_PER_SIGNATURE}; the assignment is rejected "
            "(fail safe)")
    for combo in itertools.product(*match_lists):
        comparable = True
        for first, second in itertools.combinations(combo, 2):
            if not _suffix_comparable(first, second):
                comparable = False
                break
        if not comparable:
            continue
        most_specific = max(combo, key=len)
        if all(
            not domain_matches(most_specific, entry)
            for entries in nomatch_lists
            for entry in entries
        ):
            return True
    return False


def _normalize(document, role: str) -> dict:
    try:
        normalized = validate_policy(document)
    except PolicyConfigError as exc:
        raise _Reject(f"the {role} policy is invalid and cannot be compared: {exc}")
    for field in ("allowlist", "blocklist", "category_allow", "category_block"):
        if len(normalized[field]) > MAX_RULE_LIST_ENTRIES:
            raise _Reject(
                f"the {role} policy's {field} has {len(normalized[field])} "
                f"entries, above the cap of {MAX_RULE_LIST_ENTRIES}; the "
                "comparison is infeasible to compute safely and the "
                "assignment is rejected (fail safe)")
    normalized["_category_allow"] = frozenset(normalized["category_allow"])
    normalized["_category_block"] = frozenset(normalized["category_block"])
    return normalized


def _same_rules(a: dict, b: dict) -> bool:
    return (
        a["default_policy"] == b["default_policy"]
        and sorted(a["allowlist"]) == sorted(b["allowlist"])
        and sorted(a["blocklist"]) == sorted(b["blocklist"])
        and a["_category_allow"] == b["_category_allow"]
        and a["_category_block"] == b["_category_block"]
    )


def at_least_as_restrictive(candidate, baseline) -> ComparisonResult:
    """Compare a candidate policy against the baseline (default) policy.

    Returns a ComparisonResult. `allowed` is True only when every domain
    the baseline blocks is also blocked by the candidate - proven by
    exhaustive enumeration of feasible match signatures and category
    subsets. Identical policies compare as equivalent and pass;
    demonstrably stricter candidates pass; less-restrictive, incomparable,
    invalid, or uncomputable comparisons fail.
    """
    try:
        cand = _normalize(candidate, "candidate")
        base = _normalize(baseline, "baseline")
        if _same_rules(cand, base):
            return ComparisonResult(
                True, "the candidate's rules are identical to the default "
                      "policy's rules (equivalent)")
        category_universe = (
            cand["_category_allow"] | cand["_category_block"]
            | base["_category_allow"] | base["_category_block"]
        )
        if len(category_universe) > MAX_REFERENCED_CATEGORIES:
            raise _Reject(
                f"the two policies reference {len(category_universe)} "
                f"categories, above the cap of {MAX_REFERENCED_CATEGORIES}; "
                "the comparison is infeasible to compute safely and the "
                "assignment is rejected (fail safe)")
        universe = sorted(category_universe)

        # The four lists in signature order: (alA, blA, alB, blB).
        cand_lists = (cand["allowlist"], cand["blocklist"])
        base_lists = (base["allowlist"], base["blocklist"])
        all_lists = cand_lists + base_lists

        for signature in itertools.product((False, True), repeat=4):
            match_lists = [
                entries for entries, bit in zip(all_lists, signature) if bit
            ]
            nomatch_lists = [
                entries for entries, bit in zip(all_lists, signature) if not bit
            ]
            if not _signature_feasible(match_lists, nomatch_lists):
                continue
            sig_a = (signature[0], signature[1])
            sig_b = (signature[2], signature[3])
            # Every category subset of the universe (deliberately
            # independent of the current category database).
            for size in range(len(universe) + 1):
                for subset in itertools.combinations(universe, size):
                    categories = frozenset(subset)
                    if (_decision(base, sig_b[0], sig_b[1], categories) == "block"
                            and _decision(cand, sig_a[0], sig_a[1], categories) != "block"):
                        return ComparisonResult(
                            False,
                            "the candidate is less restrictive than the default "
                            "policy: a domain with match signature "
                            f"(candidate allowlist={sig_a[0]}, candidate "
                            f"blocklist={sig_a[1]}, default allowlist={sig_b[0]}, "
                            f"default blocklist={sig_b[1]}) and category set "
                            f"{sorted(categories)} would be BLOCKED by the default "
                            "policy but allowed by the candidate")
        return ComparisonResult(
            True, "the candidate is proven at least as restrictive as the "
                  "default policy over every feasible match signature and "
                  "category subset")
    except _Reject as exc:
        return ComparisonResult(False, str(exc))
