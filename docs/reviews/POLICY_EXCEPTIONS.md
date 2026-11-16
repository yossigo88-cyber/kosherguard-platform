# Scoped time-limited policy exceptions

Status: TESTED at the commit that adds this file. Implements the approved
requirement: time-limited, scoped exceptions with a reason, the approving
user, the affected device/group, start and expiration times, and an audit
record. Parents (guardians) may approve delegated, limited exceptions;
protection removal and high-impact bypasses are owner-only.

## What is implemented

- **Model** (migration 0015, `policy_exceptions`): kind
  (`allow_domains` limited, `disable_policy` protection removal),
  scope (one device or one group), domain list, reason, approver,
  start/expiration window, revocation, creation timestamp.
- **Rules** (`app/exception_ops.py`):
  - Every exception requires a reason and an expiration time; owner
    exceptions are capped at 30 days.
  - Guardians need the explicit `exceptions` delegation (added to the
    default-deny capability set) and are limited to `allow_domains`
    exceptions of at most 24 hours. `disable_policy` (protection
    removal) is refused for guardians, as are cross-tenant targets and
    invalid domains.
  - Creation and revocation write audit events with the actor, scope,
    window and reason.
- **Publication**: active or upcoming non-revoked exceptions are
  resolved to concrete devices (group membership is pinned at
  publication time, so later moves do not extend an exception) and
  emitted as `exceptions.json` in the same immutable, hash-verified
  generation as the policy and device map. A revoke takes effect at the
  next publication like any policy change.
- **Edge evaluation** (`dns-edge/policy_bundle.py`): a per-device
  exception overlay with time windows wraps the scheduled engine. An
  active `allow_domains` exception allows the listed domains (and
  subdomains); an active `disable_policy` exception allows all traffic
  for the scoped device. Outside the window the normal policy decision
  applies. Expired and revoked exceptions never fire.
- **API**: `GET/POST /api/exceptions`, `DELETE /api/exceptions/{id}`.
  Viewers are read-only. The tenant write lock serializes exception
  changes against publications.
- **UI**: exceptions panel with create form (kind, device/group scope,
  domains, reason, hours valid), live table with status, and revoke;
  rendered and inspected with the local harness (screenshot reported).

## Tests (`tests/test_exceptions.py`, full suite 231 passed)

- Guardian default-deny until the `exceptions` capability is granted;
  guardian `disable_policy` and >24h windows refused (403); legitimate
  delegated group-scoped allow-domains exception created.
- Publication carries the exception; the published bundle allows the
  domain inside the window and blocks it again after expiry; revocation
  removes it from the next generation; audit events recorded.
- Owner-only `disable_policy` works and applies at the edge; missing
  expiration refused (400); cross-tenant targets 404; viewer create and
  revoke denied (403).

## Not yet implemented (known gaps)

- The five-role model (security-admin) is still pending; until then the
  owner holds the high-impact exception authority the spec assigns to
  owner/security administrator.
- One-time exception schedules and holiday schedules (Q21) are only
  partially covered: dated schedules exist; one-time allow windows are
  served by exceptions, not by a dedicated schedule type.
- An exception takes effect at the next publication; there is no
  out-of-band push to edges. "Additional approval for especially
  sensitive changes where practical" (Q20) is not implemented; the
  owner-only restriction is the current control.
- Group scope resolves at publication; moving a device between groups
  after publication does not extend or transfer its exceptions.
