# Device groups and protected baseline

Status: TESTED at the commit that adds this file. Covers tenant device
groups with tighten-only group policies, the owner-controlled protected
baseline, and explicit default-deny guardian delegation.

## What is implemented

- **Device groups** (`app/group_ops.py`, migration 0013): one optional
  group per device; a group may name one tenant policy. Resolution order
  is direct device assignment > group policy > tenant default. Group
  policies must prove at-least-as-strict against the selected baseline,
  including when the group has no members (a stale weaker group policy
  cannot survive a baseline change). Membership moves and renames are
  audited; viewer role denied; cross-tenant ids are 404.
- **Publication** resolves group and direct assignments into the same
  immutable generation as the device map (`publication_ops`). A disabled
  assigned policy refuses publication (409) instead of silently dropping
  the device to the weaker default.
- **Protected baseline** (migration 0014): exactly one owner-selected
  default policy per tenant. Guardians cannot edit, disable, replace
  schedules on, or re-select the baseline (403), and cannot weaken it
  indirectly through a new or updated policy: every guardian policy
  candidate must prove tighten-only against the baseline, assigned or
  not. Until the owner selects a baseline, guardian policy writes are
  refused (409). Baseline selection itself is owner-only.
- **Explicit delegation** (`delegated_settings` JSON, default `[]`):
  guardians are default-deny. Owner grants per-capability access
  (`policies,schedules,devices,groups,apps,publish`) via
  `PUT /api/guardians/{user_id}/delegation`, same-tenant guardians only,
  audited. There is no baseline, category-admin, or device-removal
  capability. Category administration requires owner + platform flag; a
  guardian with the flag is still denied. Generic MDM profile/app-removal
  and app-policy routes are owner-only; a guardian with `apps` gets
  inventory only.
- **Worker re-verification** (`app/worker.py`): at execution the worker
  re-checks the actor exists, is same-tenant, owner-or-guardian with MFA,
  and, for guardians, still holds the `publish` delegation. A revoked
  delegation fails the queued job rather than running under the stale
  queue-time grant.
- **Write serialization**: mutating policy/device/group/publication
  requests lock the tenant's publication-state row for the transaction,
  serializing baseline changes against publications on the same tenant.

## Tests (all at this commit, `python3 -m pytest tests -q`)

- `tests/test_groups.py`: group policy publishes and schedules reach the
  device bundle evaluation (real publication tree, `policy_bundle`
  evaluation); direct assignment precedence over group; membership move;
  tenant isolation, viewer denial, duplicate/blank names, tighten-only
  group policy update refusal.
- `tests/test_protected_baseline.py`: real TOTP guardian login
  (`tests/mfa_support.py`); default-deny; forbidden baseline
  weakening/replacement/disable/schedule edits/re-selection; forbidden
  direct category write, MDM profile/app-removal and app-policy bypass;
  owner-only delegation endpoint with validation and audit; legitimate
  delegated tighter policy, schedule, group assignment and device
  assignment; revoke removes access.
- `tests/test_baseline_edges.py`: guardian policy writes refused before a
  baseline is selected; disabled group policy refuses publication;
  worker re-checks publish delegation at execution (revoked job fails,
  re-granted job completes); category admin requires owner AND platform
  flag (guardian with flag denied).
- Full control-plane suite: 229 passed. Real PostgreSQL for API, worker
  and migration tests.

## UI

Rendered with the local harness (PostgreSQL + uvicorn + headless
Chrome): group create with policy selection, membership move/remove,
direct-over-group-over-baseline precedence warning, protected-baseline
label and owner-only default button, guardian delegation prompt marked
owner-only. Screenshots recorded with the report to the parent agent.

## Not yet implemented (known gaps)

- Five-role model (owner / security-admin / guardian / viewer / support)
  and support workflows; currently owner / guardian / viewer.
- Secure owner-recovery flow (bypasses disabled earlier are closed, but
  no replacement recovery exists; owner lockout requires operator
  intervention).
- Time-limited scoped exceptions (reason, approver, device group,
  start/expiry, audit); schedules only add blocks.
- Onboarding/enrollment tickets, offboarding, category source history,
  website/legal content, compatibility matrices, load testing.
- Group policy editing exists via API only; the UI manages group
  creation, policy selection and membership. Direct assignment removal
  is not exposed; reassignment replaces it.
- The write lock serializes same-tenant configuration and publication
  writes through one database; it is not a distributed lock across
  multiple control-plane databases.
- Existing external archives, snapshots, WAL segments and replicas from
  before the privacy changes are not erased by code; operator deletion
  is still required (see PRIVACY_ACCESS_MFA_FIXES.md).
