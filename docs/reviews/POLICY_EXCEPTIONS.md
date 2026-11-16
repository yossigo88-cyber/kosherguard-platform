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
  generation as the policy and device map. Revocation enqueues its own
  republication automatically (the job executes as the tenant owner so
  it cannot die on the worker's publish-delegation recheck), but it is
  still eventual: the revoked exception remains effective at the edge
  until the worker picks the job up and edges load the new generation.
  If republication fails, the last known good generation stays active
  with the revoked exception still in it; bounded retries (5 attempts,
  exponential backoff, capped at 5 minutes) then mark the job failed,
  and the failure is visible in the publication-jobs panel and audit
  log. Expiry needs no publication: the overlay enforces the window at
  query time, so an expired exception stops applying on its own.
- **Protected baseline floor** (`dns-edge/policy_bundle.py`): the
  per-device exception overlay consults the baseline engine (the
  tenant's selected protected baseline, always `engines.default`)
  before honoring an `allow_domains` match. A baseline block - domain,
  category, default-deny or schedule - stands; the exception only
  relaxes restrictions added on top of the baseline (assigned/group
  policies, which are themselves tighten-only). Guardians therefore
  cannot weaken, replace, disable or bypass the protected baseline via
  delegated exceptions, satisfying the owner's later explicit
  requirement over the broader reading of Q20. `disable_policy` remains
  a privileged owner-only full bypass: the API refuses it to guardians,
  and at the edge it allows all traffic for the scoped device, baseline
  included. Both edge consumers (the DoH server and the filtering
  proxy) load the same `policy_bundle.load_bundle` /
  `PolicyBundle.for_device` path, so the floor applies identically.
  Outside the window the normal policy decision applies. Expired and
  revoked exceptions never fire.
- **API**: `GET/POST /api/exceptions`, `DELETE /api/exceptions/{id}`.
  Viewers are read-only. The tenant write lock serializes exception
  changes against publications.
- **UI**: exceptions panel with create form (kind, device/group scope,
  domains, reason, hours valid), live table with status, and revoke;
  rendered and inspected with the local harness (screenshot reported).

## Tests (`tests/test_exceptions.py`, `dns-edge/tests/test_exception_overlay.py`)

- Guardian default-deny until the `exceptions` capability is granted;
  guardian `disable_policy` and >24h windows refused (403); legitimate
  delegated group-scoped allow-domains exception created.
- Publication carries the exception; the published bundle allows the
  domain inside the window and blocks it again after expiry; revocation
  removes it from the next generation; audit events recorded.
- Owner-only `disable_policy` works and applies at the edge; missing
  expiration refused (400); cross-tenant targets 404; viewer create and
  revoke denied (403).
- Baseline floor: end-to-end (API -> publication -> edge) a guardian
  exception naming both a baseline-blocked and a guardian-blocked
  domain leaves the baseline block standing (reason carries
  "protected baseline") while the guardian-added block opens; real
  `ScheduledPolicyEngine` coverage for baseline category blocks and
  schedule windows; subdomain matching; baseline default-deny;
  `disable_policy` full bypass; start/expiry boundaries with the expiry
  instant exclusive.
- Revocation cycle: guardian without publish delegation revokes; the
  auto-enqueued job executes under the worker's delegation recheck; the
  resulting generation no longer carries the exception.
- Publication with exceptions but no assigned policy emits an empty
  device map rather than failing (publisher cross-check satisfied).

## Security history

- The first published exceptions increment (through commit 9e72bac)
  honored `allow_domains` without consulting the baseline engine: a
  guardian exception could open baseline-blocked domains, weakening the
  protected baseline contrary to the owner's explicit requirement. It
  also left revoked exceptions effective at the edge until a manual
  publish, and failed publication with 500 when an exception existed
  without any assigned policy. All three were corrected in the follow-up
  commit that added the baseline floor, revocation auto-republication
  and the empty-device-map fix, with the tests above. Reviewers should
  treat any checkout at or before 9e72bac as carrying the flaw.

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
