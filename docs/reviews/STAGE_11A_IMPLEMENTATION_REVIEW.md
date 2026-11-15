# Stage 11A Implementation Review: Device Registry Data Model + API

**Status: implementation complete on the feature branch, awaiting the
owner's independent review. Nothing was deployed, no server was
touched, `main` is untouched, and Stage 11B/11C/11D/11E have NOT
begun.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation`
**Starting HEAD:** `8cf9b951fd8d54071915f1803d73f0d2e152d793`
**Final SHA:** the branch HEAD of the Stage 11A commit series that adds
this file; reported to the owner together with this document.
**Main (verified unchanged):** `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`

Scope implemented (owner authorization of 2026-11-15, "BEGIN STAGE 11A
IMPLEMENTATION", plus the follow-up requiring exact flake documentation
and fail-closed comparison): registry schema/migration, shared binding
canonicalization, the tighten-only comparator, Store methods and
transactional invariants, authenticated API endpoints, audit logging,
comprehensive tests, and this report. The governing design is the
approved `docs/reviews/STAGE_11_TECHNICAL_PLAN.md`.

Out of scope and NOT implemented (unchanged boundaries): Stage 11B
dashboard UI (the `devices` route placeholder in `static/app.js` is
untouched), Stage 11C engine multi-policy loading and DNS query
routing, Stage 11D publication extensions (including the publish-time
tighten-only re-check - see "Later integration points" below), Stage
11E last-seen reporting, DoH/DoT, device tokens, Apple/MDM/APNs, any
deployment or server change, any change to `main`.

---

## 1. Changed files (exact list)

Modified:

- `dashboard/src/db.py` - `SCHEMA_STAGE11` migration + `init_db()`
  wiring + module docstring.
- `dashboard/src/store.py` - device registry operations, tighten-only
  enforcement, extended policy-protection invariant, real registry
  counts in `overview_counts()`, new `/api/config` count helper.
- `dashboard/src/server.py` - `/api/devices*` routes and the
  `devices_registered` field in `/api/config`.
- `dashboard/src/engine_bridge.py` - re-exports of the two new engine
  modules (validation stays single-sourced).
- `dashboard/README.md` - registry section + honest test count.
- `filtering-engine/README.md` - new modules + honest test count.
- `README.md` - Stage 11A status paragraph + honest test counts.

Added:

- `filtering-engine/src/address_canonicalization.py` - the shared
  binding canonicalizer (plan 6.2).
- `filtering-engine/src/policy_comparison.py` - the tighten-only
  comparator (plan 4.5).
- `filtering-engine/tests/test_address_canonicalization.py` - 31 tests.
- `filtering-engine/tests/test_policy_comparison.py` - 32 tests.
- `dashboard/tests/test_devices.py` - 67 tests.
- `dashboard/tests/test_device_assignment.py` - 23 tests.
- `docs/reviews/STAGE_11A_IMPLEMENTATION_REVIEW.md` - this file.

No other file changed. `dashboard/static/*` (UI), all engine runtime
files (`dns_service.py`, `policy_engine.py` decision logic,
`category_db.py`), and all deployment files are untouched.

## 2. Migration and schema

`db.py` gains `SCHEMA_STAGE11`, executed by `init_db()` after the Stage
10 schema, in the same idempotent `CREATE ... IF NOT EXISTS` style:

- `devices` - durable administrative records. `id` is AUTOINCREMENT
  (never reused); `name` unique; `state` CHECK-constrained to
  `active/inactive/disabled/removed`; `management_status`
  CHECK-constrained to `unmanaged/enrolled` and only ever written as
  `unmanaged` in Stage 11A (the API rejects any attempt to set it).
  `last_seen_at` exists per the plan and stays NULL (Stage 11E).
- `device_associations` - `kind` CHECK-constrained to
  `ipv4/ipv6_prefix/token_hash`; the combined CHECK constraint permits
  exactly three (kind, identity_class) pairs: `ipv4` ->
  `network_binding`, `ipv6_prefix` -> `network_binding`, `token_hash`
  -> `credential`. SQLite aborts any INSERT or UPDATE producing another
  combination, even with API validation bypassed (proven by direct-SQL
  tests, including an UPDATE attempt to upgrade a binding to a
  credential). The partial unique index
  `uq_live_association (kind, value) WHERE retired_at IS NULL` is the
  canonical duplicate check: only canonical strings are ever stored, so
  two spellings of one network collide with a 409.
- `device_policy_assignments` - history rows are never updated in place
  except the `active` flag flip and are never deleted while the device
  exists; the partial unique index
  `uq_active_assignment (device_id) WHERE active = 1` enforces at most
  one active assignment per device (proven by direct-SQL tests).

One schema adjustment vs the plan text: the plan's listing places the
combined CHECK table-constraint between column definitions; SQLite
requires table constraints after the column list, so the constraint
text is unchanged but positioned after the columns. Its enforced
semantics are identical.

Migration evidence: `test_migration_from_realistic_pre_stage11_database`
builds a realistic pre-Stage-11 database (original schema + Stage 10
migration + an admin, a policy with rules, a domain record, a
publication selection, and audit rows), runs `init_db()`, and proves
the new tables/constraints exist and every pre-existing row survives.
`test_migration_is_idempotent` runs `init_db()` three times and proves
registry data survives re-migration.
`test_table_rebuild_migration_path_preserves_rows` exercises the
documented future-credential-kind path (table rebuild whose new CHECK
names the existing pairs PLUS the new one): existing rows survive and
invalid pairs stay rejected.

## 3. Canonical address handling

`filtering-engine/src/address_canonicalization.py` implements plan 6.2
exactly, one shared function used by the dashboard at write time (the
engine lookup wiring is Stage 11C; `canonical_source_key()` is provided
now so the rule stays single-sourced):

- IPv4: strict `ipaddress.IPv4Address` parsing; canonical dotted-quad
  stored; leading zeros (`192.168.001.50`), non-dotted forms, prefix
  notation, out-of-range octets, whitespace, and IPv6 input rejected,
  never repaired.
- IPv6: only strict /64 networks. Equivalent spellings
  (`2001:0DB8:0000:0000:0000:0000:0000:0000/64`, `2001:DB8::/64`,
  `2001:db8:0:0::/64`) all store as `2001:db8::/64`. Host bits set
  (`2001:db8::1/64`), other prefix lengths (/48, /128, /32), zone IDs,
  and malformed input rejected with field-named reasons. IPv4-mapped
  rejected in mixed (`::ffff:192.0.2.1/64`) and hex
  (`::ffff:c000:201/64`) spellings via an explicit `ipv4_mapped` check.
  The deprecated IPv4-compatible class is rejected arithmetically (top
  96 bits zero): `::/64` in every spelling (`::/64`,
  `0:0:0:0:0:0:0:0/64`, `::0.0.0.0/64`) plus `::1/64`,
  `::192.0.2.1/64`, `::c000:201/64`. Boundary cases pinned: NAT64
  `64:ff9b::/64` accepted; `2001:db8::0.0.0.0/64` canonicalizes to
  `2001:db8::/64`.
- `token_hash` is a reserved kind: the canonicalizer refuses it and the
  API rejects token registration outright (Stage 11A issues, stores,
  and authenticates no device tokens). Clients can never supply
  `identity_class`; it is derived server-side from `kind`
  (`POST .../associations` with `identity_class` in the body -> 400).

The full matrix runs at both layers: 31 unit tests in the engine
package and API-level duplicates/rejections in
`dashboard/tests/test_devices.py`.

## 4. Tighten-only comparator

`filtering-engine/src/policy_comparison.py` implements plan 4.5's
feasible-signature method on top of the engine's own `validate_policy()`
and `domain_matches()` suffix semantics:

- Both policies normalized by `validate_policy()`; an invalid policy is
  rejected (never compared).
- Fast path: identical normalized rule data -> equivalent, allowed.
- All 16 match signatures `(alA, blA, alB, blB)`; feasibility per the
  plan (mutually suffix-comparable witness entries whose most specific
  entry is matched by no required-NO-match list; empty required list ->
  infeasible; all-zero signature always feasible).
- Every category subset of the universe `U` (union of the four category
  rule lists), reproducing `PolicyEngine.decide`'s precedence: explicit
  allow -> allow, explicit block -> block, category block -> block,
  category allow -> allow, default.
- Fail closed (owner follow-up, restated here as implemented): any
  invalid input, any cap breach, or any comparison that cannot prove
  safety REJECTS. Caps: 20 referenced categories, 500 entries per rule
  list, 100,000 witness-choice combinations per signature. Nothing is
  ever guessed; names, labels, and rule counts play no role.
- Pure and deterministic (a test asserts identical inputs give an
  identical result object).

32 engine tests cover the plan matrix: identical (including
block-all vs block-all), strict-superset, correlated shared lists (no
false rejection), normalization-equivalent spelling, allowlisting a
baseline-blocked domain, dropping a blocklist entry, allowlisting a
subdomain of a blocked domain, incomparable pairs, looser default,
allowlist-overrides-category-block, category allow vs block, removed
category block, default allow/block interplay, invalid
candidate/baseline, all three caps, and determinism.

Enforcement (all server-side, inside the same `BEGIN IMMEDIATE`
`_write_txn` as the mutation):

1. **Assignment** (`POST /api/devices/<id>/assign-policy`): the
   candidate's current version is compared against the current
   default's current version; failure -> 409 naming the policy and the
   reason; no assignment row is written (verified).
2. **Default-policy change** (`POST /api/policies/<id>/select`):
   every active assignment is re-proven against the NEW default inside
   the selection transaction; any violation refuses the whole change
   with 409 naming the conflicting registry entries and policies
   (verified: the selection pointer does not move). Note this is
   applied to ALL active assignments, slightly broader than the plan's
   "assignments on devices with live bindings", so the invariant "every
   active assignment passes tighten-only against the current default"
   holds unconditionally - a device that gains a binding later can
   never activate an unchecked assignment.
3. **Publish**: intentionally NOT implemented - Stage 11D. Required
   later integration point, exactly as the owner directed: the publish
   path must re-run the comparison for every active assignment against
   the freshly exported versions before any file is written.

A further fail-safe: assignment is refused (409) when no policy is
selected for publication, because the comparison would have no
baseline.

## 5. Store methods and transactional invariants

All mutations go through the existing `_write_txn` (BEGIN IMMEDIATE)
pattern; every check and its guarded write are in one transaction.
Implemented operations: register (with optional initial bindings and
optional initial assignment, all atomic), read/list (search + state
filter), update editable fields, state transitions, soft removal, add
binding, retire binding, assign, unassign, assignment history,
per-device audit history, effective-policy view.

Invariants (each test-covered):

- Device names unique; validated with the same `_check_text` rules as
  policies (1-80 chars, no control characters).
- A removed entry cannot receive new bindings or assignments (409).
- At most one active assignment per device (partial unique index; a
  six-thread concurrent-assignment test proves exactly one winner).
- Assigned policies must exist and be enabled.
- Reassignment deactivates the old row and inserts a new historical row
  atomically; history is preserved.
- Removal is soft: state -> `removed`, all live bindings retired, the
  active assignment deactivated, in one transaction; records and
  history kept.
- Re-enabling never resurrects retired bindings (a new device can
  register the old address and gets no inherited policy - tested).
- The Stage 10 selected-for-publication invariant is extended, not
  duplicated: a policy cannot be disabled or deleted while selected OR
  referenced by an ACTIVE assignment (same write lock). Because
  assignment history rows carry a foreign key to `policies` and are
  never deleted, a policy with ANY assignment history also cannot be
  hard-deleted (409 explaining why); this is the FK-safe reading of
  "assignment history is preserved" and is documented as a deliberate
  judgment call.
- Every mutation writes its audit entry in the same transaction, with
  the exact action names `device.create`, `device.update`,
  `device.state`, `device.binding.add`, `device.binding.retire`,
  `device.policy.assign`, `device.policy.unassign`. Details begin with
  `device '<name>' (id <id>):` so the per-device audit read is an exact
  id-anchored filter. No credential material exists or is logged.

## 6. API endpoints

All under the existing session check and CSRF header requirement
(every device route proven 401 without a session and 403 without
`X-KosherGuard-Request: 1`); bodies are size-capped and strictly
validated by the existing machinery; integer ids come from the route
pattern; errors are `{"error": ...}` via `StoreError` with the correct
status codes (400/404/409).

| Method + path | Behavior |
| --- | --- |
| `GET /api/devices?search=&state=` | List with assigned-policy summary and live-binding counts; response note states bindings are routing hints, not identity |
| `POST /api/devices` | Register (201); optional `bindings` and `policy_id`, all atomic |
| `GET /api/devices/<id>` | Detail: fields, `entry_kind` (`device` vs `network_or_group`), associations with `identity_class`, active assignment, full assignment history |
| `PUT /api/devices/<id>` | Edit name/description/type/os/notes; rejects `management_status` and `state` (400) |
| `POST /api/devices/<id>/state` | `active/inactive/disabled/removed` transitions; removal retires bindings and deactivates the assignment atomically |
| `POST /api/devices/<id>/associations` | Add binding (201); canonicalized per 6.2; malformed 400, canonical duplicate 409 |
| `DELETE /api/devices/<id>/associations/<aid>` | Retire (sets `retired_at`) |
| `POST /api/devices/<id>/assign-policy` | `{policy_id}` assigns with the in-transaction tighten-only check (409 on violation); `{policy_id: null}` unassigns |
| `GET /api/devices/<id>/effective-policy` | The three distinct states (below) |
| `GET /api/devices/<id>/audit` | Per-device filtered audit entries |

`GET /api/overview` now returns real registry counts (`devices`,
`devices_by_state`); `GET /api/config` keeps
`devices_connected: false, mdm_operational: false` and gains
`devices_registered` (administrative records, not connected devices).
The device-vs-network/group distinction is explicit in every device
response (`entry_kind`), in validation messages, and in audit details.

## 7. Assigned / published / enforced honesty

`GET /api/devices/<id>/effective-policy` returns the three states
distinctly, within Stage 11A's boundaries:

- `assigned`: the saved assignment (policy id/name, current version,
  version at assignment) or the string `"default"`;
  `assigned_applies_to_live_queries` is false for
  inactive/disabled/removed entries (the default policy applies).
- `published`: always `null` with `published_note` - assignments are
  not part of published generations until Stage 11D; a saved assignment
  changes nothing an engine does.
- `enforced`: `"unavailable"` when no engine status file exists (the
  current staging truth: the Oracle VM runs the dashboard only, and no
  claim otherwise is made), `"rejected"` when the engine reports a
  `last_error`, `"stale"` when its hashes do not match the active
  revision, and a confirmed object only when the engine's own status
  hashes match the active published revision - and even then it
  explicitly covers the default policy only. A saved assignment is
  never presented as enforced.

## 8. Test commands and exact results

Environment: Python 3.10.12, pytest 8.4.2, dnslib 0.9.24 (per
`filtering-engine/requirements.txt`).

**Baseline, BEFORE any Stage 11A change (fresh clone of the starting
HEAD `8cf9b951`), recorded exactly as it happened - the baseline is
not described as clean:**

- `python3 -m pytest dashboard/tests -q` -> **165 passed** (105.28s).
- `python3 -m pytest filtering-engine/tests -q` -> **144 passed, 2
  failed** (55.06s). The two failures were
  `tests/test_concurrency.py::test_shutdown_deadline_is_overall_not_per_worker`
  and
  `tests/test_dns_service.py::test_blocked_domain_other_qtypes_nxdomain_in_sinkhole_mode`.
  Re-running exactly those two tests -> **2 passed** (2.81s). Both are
  timing-sensitive under this sandbox's scheduling (the suite contains
  a documented timing-sensitive shutdown test); they failed only in the
  full-suite initial run and passed on the immediate rerun. They are
  reported here rather than concealed.

**After Stage 11A (working tree):**

- `python3 -m pytest filtering-engine/tests -q` -> **209 passed**
  (57.84s): the 146 baseline tests plus 63 new
  (31 canonicalization + 32 comparator). No failures, no flakes in this
  run. (3 benign warnings observed in one fresh-clone run; no test
  impact.)
- `python3 -m pytest dashboard/tests -q` -> **255 passed** (run per
  test file after the suite-level 120 s execution cap of this
  environment; the aggregate covers every file): the 165 baseline tests
  plus 90 new (67 registry + 23 assignment). Zero existing tests were
  modified; all original guarantees preserved.
- Syntax checks (exact command):
  `python3 -m py_compile filtering-engine/src/address_canonicalization.py filtering-engine/src/policy_comparison.py dashboard/src/db.py dashboard/src/engine_bridge.py dashboard/src/store.py dashboard/src/server.py`
  -> exit 0 (clean).
- Migration against a realistic pre-Stage-11 database (exact proof, not
  an empty database):
  `python3 -m pytest dashboard/tests/test_devices.py -k migration -q`
  covers `test_migration_from_realistic_pre_stage11_database`
  (original schema + Stage 10 migration + admin, policy with rules,
  domain record, publication selection, and audit rows, then
  `init_db()`; all pre-existing rows proven to survive),
  `test_migration_is_idempotent`, and
  `test_table_rebuild_migration_path_preserves_rows` - all passing
  within the 67-test registry suite result above.

**Fresh-clone verification (pre-commit overlay):** a brand-new
`git clone` of the branch at `8cf9b951` plus exactly the changed/added
files listed in section 1, overlaid onto it: engine suite **209
passed** (57.98s); dashboard suite **255 passed** (the three batched
runs covering 188 tests, plus the registry suite re-run in the same
overlay after the final hardening edit: 67 passed). This proves the
change set is self-contained and no local state was required. It is an overlay of the
local working tree, NOT a clone of the final committed tree; the final
committed tree is verified separately after the commits land (a fresh
clone of the committed branch, both suites re-run), and that result is
reported with the final SHA.

**Final committed-tree validation (post-commit):** after all 14
commits landed, a brand-new
`git clone --branch stage-9b-deployment-preparation` of the COMMITTED
branch (HEAD `5377d2b4d3ec0c92960060b603aee8655a9b4119`, confirmed
against the GitHub API) was checked: all 14 changed/added files are
byte-identical to the tested working tree (`cmp` per file), and every
committed blob SHA returned by the GitHub contents API matched the
locally computed `git hash-object` of the tested file (14/14). Both
suites were then re-run on the clone with these exact invocations and
results:

- `python3 -m pytest tests -q` (cwd: `filtering-engine/`) -> **209
  passed**, 3 benign warnings (57.99s). (The baseline and post-change
  runs above used `python3 -m pytest filtering-engine/tests -q` from
  the repository root; this committed-tree run used the equivalent
  invocation from inside `filtering-engine/`.)
- `python3 -m pytest dashboard/tests/test_devices.py dashboard/tests/test_device_assignment.py -q`
  (from the repo root) -> **90 passed** (47.85s); the new Stage 11A
  suites.
- `python3 -m pytest dashboard/tests --ignore=dashboard/tests/test_devices.py --ignore=dashboard/tests/test_device_assignment.py -q`
  (from the repo root) -> **165 passed** (105.44s); the entire
  pre-existing dashboard suite.

Dashboard total: **255 passed** (90 + 165, two invocations; this
environment's suite-level 120 s execution cap requires split runs).
The tested code SHA is `5377d2b4d3ec0c92960060b603aee8655a9b4119`;
the only later commit updates this report itself and changes no code,
test, schema, or documentation-of-record file.

**Note on `engine_bridge.py` scope:** its only change is import
re-exports of the two new engine modules so the dashboard can import
them through the existing bridge path. It adds no function that reads
the registry, and it changes no published payload, no publication
generation, and no runtime engine behavior. Publication-path wiring
remains Stage 11D and engine lookup wiring remains Stage 11C; both are
untouched.

**Deviations and judgment calls (complete list):**

1. The combined CHECK table-constraint is positioned after the column
   list (SQLite grammar); semantics unchanged (section 2).
2. The default-policy-change re-check covers ALL active assignments,
   not only binding-bearing ones (stronger invariant; section 4).
3. A policy referenced by any (even historical) assignment row cannot
   be hard-deleted, because history rows keep a foreign key to it; the
   API returns a clear 409 instead of a database error (section 5).
4. Assignment is refused when no default policy is selected (no
   baseline; fail closed).
5. Existing test files were NOT modified. One implementation bug was
   caught during development by the baseline suite (a route-registration
   mistake that broke `GET /api/audit`); it was fixed and the full
   baseline expectations pass unchanged.
6. The two baseline engine flakes documented above are pre-existing
   and unchanged by this stage (both files untouched).

**Confirmations:** no deployment or external system was touched (no
Oracle, Render, production site, DNS, firewall, or device access; no
account creation or paid service); `main` remains at
`5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` (verified by API after the
final commit); no merge, no force-push; nothing from the old KosherGuard
project was used.

**Later integration points (explicitly not this stage):** the publish
path MUST re-run the tighten-only check per plan 4.5 enforcement point
3 (Stage 11D); engine loading/lookup wiring (11C); UI (11B); last-seen
(11E). Stage 11 implementation stops here for independent review.
