# Filtering-log ingestion vs device offboarding

Branch: `full-platform-build`.
Review baseline: `a0444d292936e573120c504733f24caf1b07f90e`.
Code/test candidate: `21c071f79ea9e0544aae3d41ce4797bf08d8547a`.

This is a code-and-disposable-database correction, not a production or iPhone
release. No merge, deployment, main change, DNS change, real Apple credential,
real device operation, purchase, force-push or branch deletion was performed.

## 1. Race verified, not hypothetical

The offboarding completion API already obtains the tenant row lock in
`current_user`, then locks its case and device. It revokes the device's issued
credentials, deletes its filtering decisions, marks it offboarded and commits.
The bearer `/api/filter-logs` API bypassed that authenticated-browser wrapper.
`record_decisions` read the registry, then purged/inserted without a shared
lifecycle lock. The route's savepoint was not cross-transaction serialization.

A disposable real-PostgreSQL negative control restored the baseline ingestion
and main modules, paused ingestion at `purge_expired` immediately AFTER successful
registry validation but BEFORE INSERT, completed real offboarding via its API,
checked zero rows, then resumed ingestion. Both proxy and DoH credentials got
HTTP 200 and left one device-linked row after completed offboarding. These two
expected-vulnerability reproduction cases passed. They used synthetic domains,
real issuance records and fresh fixture MFA, not mocked database locks.

Running the new regression module with the baseline ingestion/main/worker
modules produced 12 failed / 7 passed. This is intentional negative-control
evidence, not a successful security test run. The fixed code was restored
before publication. The temporary vulnerable-behavior assertion harness was
not published as an ordinary test expecting a security defect.

## 2. Serialization and post-lock authorization

`record_decisions` now takes tenant -> device -> issued-credential locks, before
reading authorization facts used to accept rows. Locks remain held through the
route's INSERT/flush, savepoint release and outer commit. Offboarding and API
credential revocation already take the same tenant lock before device/credential
changes. Offboarding's case row is an additional row no ingestion path requests;
there is no inverse case/device dependency.

After waiting, ingestion refreshes device and credential identity-map values
with `populate_existing=True` and checks:

- Recognized proxy/DoH scope; required tenant, device and expiry claims.
- Existing device bound to the claimed tenant, with state exactly `active`.
- JTI exists, matches tenant AND device, is unrevoked and unexpired.
- Token expiry is still in the future after the lock wait and matches registry
  expiry; scope and policy binding match the registry.

This also applies to direct internal callers of `record_decisions`, not just
this HTTP route. Synthetic direct-call tests now provide the required expiry.
Allowed history and arbitrary reason/rule text remain unpersisted. Whole-batch
validation rollback remains protected by the existing savepoint.

Two valid orderings remain: ingestion commits first and offboarding deletes its
rows afterward, or offboarding commits first and ingestion is refused with 403.
A previously verified signature never reserves the right to write later.
The mint API also refuses inactive/offboarded devices for all three scopes,
preventing a new credential from silently restoring access after offboarding.

## 3. Real PostgreSQL forced regression evidence

`tests/test_ingestion_offboarding_pg.py`: 19 new cases:

- Two scope variants pause after signature verification, finish offboarding,
  then resume ingestion and require 403 and no surviving rows.
- Two scope variants pause AFTER registry validation, before INSERT. A separate
  connection inspects `pg_blocking_pids` and proves offboarding is actually
  blocked by the ingestion transaction. Ingestion then commits, offboarding
  completes and deletes its row, and a later report is rejected. Final device
  state and credential revocation are also checked.
- Four stale-identity-map tests preload the device and credential, hold the
  tenant lock in another transaction, force ingestion to wait, then revoke,
  expire, offboard or rebind before releasing. Each waiter refuses the write.
- Nine negative cases cover already-offboarded devices, revoked/expired
  credentials, scope/tenant/device/policy mismatch and missing device/expiry.
- One test refuses all three credential-mint scopes after actual offboarding.
- One worker test queues a valid publication, holds the tenant lock, proves
  the worker waits, demotes its actor, and checks no generation is published.

Events/barriers establish interleavings; bounded polling only observes the
real PostgreSQL wait graph. No fixed sleep is used as proof of serialization.
Threads have timeouts and release gates in `finally` blocks. PostgreSQL fixture
state is synthetic and truncated after tests. No external device is involved.

## 4. Related bearer and background paths reviewed

- **Proxy and DNS reporters:** both POST to this single control-plane ingestion
  API. Both use synchronous, best-effort blocked-domain reporting; failures
  are dropped, not spooled into durable history. A delayed report is still
  rejected by the new central authorization check. No alternate SQL writer
  of FilterDecision rows exists in the reviewed application paths.
- **Enrollment-ticket bearer redemption:** already locks tenant before ticket
  and device, then checks revocation, expiry, used state and device lifecycle.
  Existing real-PG ticket and offboarding races remain in the full suite.
- **NanoMDM HMAC check-in/DDM status:** existing ensure_active/confirm_checkin
  take the tenant lock, refresh enrollment and refuse inactive devices before
  accepting status/check-ins. These are HMAC peer paths, not scoped-log bearer
  endpoints. They do not recreate deleted filtering history.
- **Credential revocation feed:** GET-only, tenant-scoped export of revoked JTIs.
  A still-signed token may read its own tenant's revocation set even if revoked;
  this permits learning that it was revoked and writes no device history. This
  patch does not turn that feed into a device ingestion path or change its
  audience. Edge enforcement remains best-effort between refreshes and expiry.
- **Physical history retention:** ingestion, history/status reads and the
  standalone maintenance loop all call purge_expired. It now obtains the tenant
  lock BEFORE log deletes and refreshes retention configuration after waiting.
  Global sweeps take tenants in ascending ID order. Retention-setting writes
  join the same tenant-lock wrapper, preventing DELETE-first/tenant-first
  inversions and racing use of stale retention settings. Cleanup only deletes;
  it never inserts history. A new legitimate blocked event on an active device
  remains allowed after retention cleanup; offboarding is the terminal gate.
- **Publication worker:** found and fixed a related authorization race: actor
  role/MFA/delegation had been inspected before a tenant-lock wait. The worker
  now locks tenant first, then loads a fresh actor. Its existing job claim is
  preserved; device/offboarding and privacy paths do not wait on job rows.
  Server-only exception-revoke cleanup remains narrowly exempt from owner
  publishing authority exactly as before. It exports no browsing-history rows.
- **Credential-artifact cleanup worker:** locks metadata artifact rows and
  deletes obsolete files only; does not accept bearer reports, recreate history
  or acquire tenant locks after log/device locks. Existing fault tests pass.

## 5. Exact-SHA test ledger and commands

Fresh GitHub clone at EXACT code/test candidate
`21c071f79ea9e0544aae3d41ce4797bf08d8547a`:

```sh
cd control-plane
python -m pytest tests -q --junitxml=/tmp/kg-exact-candidate.xml
```

**451 passed, 0 failed**, including all original 432 tests, all original 20
PostgreSQL concurrency-matrix cases, the 19 new cases and migration roundtrips.
Output captured with exit-preserving redirection, not a tail-pipeline exit code.
Full log and JUnit preserved during verification. Dependencies installed in the
disposable test environment: control-plane requirements, pytest, pgserver,
and dnslib (needed by the cross-component DNS integration tests).

Earlier local runs: 14 new tests passed, then 19 new tests passed; focused
83-test run passed before the last worker case was added. Initial new-fixture
failures (missing created_by_user_id and incomplete Settings) were corrected.
An initial full local run had 448 passes / 3 failures due solely to missing
dnslib; this is NOT counted as a passing complete run. Installing dnslib and
fresh-cloning the published candidate yielded the complete 451-pass result above.

```sh
python -m compileall -q control-plane/app control-plane/tests
node --check control-plane/web/app.js
node --check portal/app.js
git diff a0444d2..HEAD --check
```

All pass at the code/test candidate. No UI code changed, so there is no new
visual product claim. No project lint/type/security-analysis tool was run.
The other seven component suites were not rerun for this patch; the prior
1,277 aggregate remains tied to 2826cad, not this candidate or final head.
The final delivery identifies the final documentation head and its exact-SHA
complete control-plane rerun separately from this candidate ledger.

## 6. Changed files relative to a0444d2

1. `control-plane/app/db.py`: document shared lifecycle/privacy lock discipline.
2. `control-plane/app/filter_log_ops.py`: locked fresh authorization and ordered
   retention cleanup.
3. `control-plane/app/main.py`: retention-wrapper serialization; refuse inactive
   credential minting. No extraction or unrelated route rewrite.
4. `control-plane/app/worker.py`: post-lock actor authorization.
5. `control-plane/tests/test_activity_privacy.py`: realistic complete claims and
   ensure unknown-JTI negative tests reach the registry rather than fail parsing.
6. `control-plane/tests/test_ingestion_offboarding_pg.py`: 19 real-PG regressions.
7. `docs/reviews/INGESTION_OFFBOARDING_REVIEW_2026-11-17.md`: this report.
8. `docs/reviews/FINAL_HANDOFF.md`: point to this follow-up and candidate evidence.
9. `docs/REQUIREMENTS_COVERAGE.md`: point to this follow-up and candidate evidence.

## 7. Limitations and safety boundary

Serialization is proven using PostgreSQL at its configured default READ
COMMITTED isolation. SQLite ignores FOR UPDATE and is not concurrency proof.
Tenant-level serialization intentionally trades per-tenant ingestion throughput
for a simple shared lifecycle boundary; no production load or lock-timeout
benchmark is claimed. Every future direct database writer must follow the same
lock protocol. Raw SQL by operators outside the application is not governed by
application locks. No schema migration is required by this correction.

This prevents accepted central filtering-log writes after committed offboarding;
it does not instantly halt already-running proxy/DNS requests, remove external
backups, prove real-device enforcement or make revocation distribution immediate.
Existing short-lived token expiry and refresh timing still bound edge staleness.
An offboarding case of kind cancellation intentionally does not offboard devices
or disable protection. Only device-offboarding kinds invoke this deletion gate.

Main was checked live and remains
`5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`.
