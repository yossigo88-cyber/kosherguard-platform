# Security corrections: 2026-11-17

## Scope and verification ledger

Repository: yossigo88-cyber/kosherguard-platform, full-platform-build.
Baseline: 5254763d1477578c477fa2ee7338e953837dc672.
Verified code candidate: 6399667e64b089f9b14915a6472fd402d0e9828f.
Main observed unchanged: 5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a.

Fresh clone from GitHub at that exact candidate SHA passed:

| Suite | Passed | Command |
| --- | ---: | --- |
| control-plane | 426 | python -m pytest tests -q |
| filtering-engine | 337 | python -m pytest tests -q |
| dns-edge | 87 | python -m pytest tests -q |
| mdm | 64 | python -m pytest tests -q |
| proxy-edge | 38 | python -m pytest tests -q |
| url-filter-server | 38 | python -m pytest tests -q |
| category-pipeline | 6 | python -m pytest tests -q |
| dashboard | 276 | tests sorted by path into four batches:130+34+67+45 |
| Total | 1272 | eight suites at candidate6399667 |

Commands run from each component directory. Every completed run preserved
pytest's exit status and wrote full logs plus JUnit XML. Dashboard was
batched because the full suite exceeds a command's time limit. Two early
whole-suite attempts timed out and are not counted as passes. The first
DNS run had a flaky negative test: appending fixed signature characters
could leave the signature unchanged by chance. The test now flips a
known character to a different value; all87 pass at candidate6399667.
Earlier diagnostics piped to tail without preserving status are not
completion evidence. The final fresh-clone runs do preserve status.

Additional checks at candidate: Python compileall for all Python
components, node --check for control-plane/web/app.js and portal/app.js,
and git diff --check passed. No configured ruff/mypy/bandit tool or
project-wide lint/type/security configuration was available. These were
not claimed as executed. Swift/Xcode compilation and physical-device
checks were unavailable and remain unverified. Benchmarks are existing
historical measurements, not newly rerun capacity evidence.

## Findings and corrections by original handoff part

### 1. Sensitive commands

staff_routes.py locks both decision paths, checks pending/expiry and
requires fresh actor TOTP + exact operation confirmation for rejection
and approval. Request creation validates enrollment+device tenancy and
lifecycle before saving; serialization independently rechecks related
rows. Approval-list authorization uses sensitive-operation privilege,
including staff security_admin with viewer tenant role. Support/read-only
staff remain denied. Approval produces approved_command_queued for
EraseDevice, or approved_manual_action_required for unintegrated Apple
steps, never executed. The UI displays decision detail for these states.

Evidence: test_staff_roles.py, test_security_hardening.py (foreign target
creation and deliberately corrupted reference serialization),
test_concurrency_pg.py (ordinary double approval queues exactly one
command, approve/reject one winner, expired double approval).

### 2. Exceptions and publication

Exception decisions lock their request; decision, created exception and
audit share a transaction. Lists require owner or delegated exceptions
permission, not any tenant session. Tenant-row locks serialize policy,
assignment/group/default/exception changes against publication, including
first publication where PublicationState may not exist. Failed cleanup
queue creation rolls back revocation and explicitly says NOT revoked and
remains active. Narrow system cleanup still republishes only the prior
snapshot minus revoked entries, not unrelated saved drafts.

Evidence: PG exception double approval, approve/reject, publish/create,
publish/revoke, first worker publication/approval and post-activation
crash/revoke recovery; test_exception_requests.py,
test_exception_revoke_authority.py and hardening rollback test.
A publish that orders before a mutation represents that prior snapshot;
a later publish includes the committed change. Revocation queues durable
narrow cleanup. This is serialization, not a promise every saved change
is instantly published.

### 3. Enrollment and device status

All command-derived status figures use the current enrollment only.
Ticket redemption and legacy creation serialize on the device and share
a partial unique pending/enrolled-per-device constraint. Placeholders
are reused, conflicting identities refused. Ticket revoke locks the same
row and refuses consumed/revoked tickets. Bearer redemption takes tenant,
then ticket, then device locks: the added legacy/ticket test found and
fixed a real FK key-share deadlock with the tenant write lock. Command
issuance, including approved destructive execution, refuses terminal
enrollment/device states; old tickets cannot enroll offboarded devices.
DDM/check-in also recheck lifecycle under tenant serialization.

Evidence: test_device_status.py old-cycle ack/pending/count/latest test;
PG distinct-ticket, legacy/ticket, redeem/revoke races; lifecycle tests
in test_offboarding.py, test_enrollment_tickets.py and hardening.

### 4. Restore readiness

Current-cycle manual attestation requires fresh MFA and confirmation.
A dataset credential must belong to this device/tenant, be unrevoked and
unexpired, and have been issued during the current enrollment cycle.
The enabled effective policy is proven tighten-only against the enabled
selected baseline. A verified on-disk generation must include that
current enrollment cycle and byte-match the effective and baseline
policies. Missing, corrupt, old or merely saved state fails readiness.
Old generations require republication to add cycle metadata. Readiness
never releases Setup Assistant or independently verifies Apple state.

Evidence: test_restore.py valid cycle, stale attestation, old enrollment,
expired/revoked/old/wrong-device credentials, unpublished/old publication,
changed policy, disabled baseline, looser assignment and cross-tenant.

### 5. Offboarding

Case transitions lock the row. Completion requires fresh MFA and explicit
complete-offboarding confirmation, and cannot follow cancellation or
repeat side effects. Repeat completion returns409; no second mutation.
Device transfer/loss completion revokes credentials, deactivates direct
assignments, offboards enrollment/device state and purges filtering rows
in the same DB transaction. Cancellation/nonpayment does not disable
protection. No automatic erase or ABM release is introduced.

Evidence: PG complete/complete, complete/cancel, attest/complete;
test_offboarding.py full verification/manual-attestation/device lifecycle.

### 6. Credential storage

Credential routes extracted into credential_routes.py. Writes use0600
files,0700 tenant directories, size verification, fsync and atomic rename.
Upload DB failure cleans the staged file. Rotation writes new bytes,
commits the pointer plus old-path cleanup intent, then deletes obsolete
bytes. Revocation commits unusable status plus cleanup intent before
removal. Deletion failure remains cleanup_pending and is retried by
maintenance. Cleanup confirmation is audited. A pending pointer cannot
be overwritten by another rotation. Relative paths and tenant-directory
symlink escapes are refused. Maintenance reaps old unreferenced UUID/tmp
files after24h, covering process death or failed rollback cleanup.

Evidence: real Session.commit failures for upload/rotate/revoke preserve
old active bytes and leave no staged orphan; disk failure, failed rename,
failed delete/retry, path traversal/symlink, orphan grace tests in
 test_security_hardening.py and normal lifecycle in test_credentials.py.
Limit: orphan sweep assumes transactions cannot stay open24h. It requires
worker maintenance and access to the same filesystem; it is not a claim
of immediate erasure while storage is unavailable.

### 7. Revocation/authentication

Browser revocation-feed reads use current_user and its MFA/session/role
gates; edge bearer access remains. Log ingestion checks issuance JTI,
tenant/device/scope, expiry and revocation, not signature alone.
Evidence: hardening MFA/feed and registry-binding negatives,
test_activity_privacy.py and test_filter_logs.py. Edge verifiers support
revoked-JTI lists; propagation depends on configured periodic feed
refresh and fail-closed policy. Not instant universal revocation.

### 8. Policies

Disabling selected, directly assigned or group-assigned policies is
refused. Tenant serialization protects assignments even before first
publication. Worker locks tenant before PublicationState, matching API
order; crash retry keeps durable job identity/revision recovery.
Evidence: direct/group disable and subsequent publish tests; PG worker
and exception matrix; existing worker crash/skip-locked/retry tests.

### 9. Accounts and rate limiting

Invite acceptance locks token; user uniqueness + unused-email invitation
partial index backstop races. Expired unused invitations are explicitly
retired so replacement works. Last staff-owner changes serialize the
owner set. Guardian role changes preserve last tenant owner. MFA reset
requires actor password, fresh MFA and confirmation, clears target
sessions/pending enrollment and rejects self-reset. Login and MFA
confirmation counters use row locks + savepoint-safe first insert.
Passwords default to600k PBKDF2-SHA256, transparently upgrade older valid
hashes, and bound stored iterations against CPU abuse. Test environment
uses an explicit50k target, not the production default.

Evidence: PG invite redemption/uniqueness, mutual staff-owner demotion,
login and MFA-failure counters; guardian/MFA/security tests; old-hash login
upgrade. Existing format remains supported within bounded parsing limits.

### 10. Payloads/errors

Recursive secret-key redaction in command responses; adapter free-text
errors are withheld except class and allowlisted failure category.
Adapter result details are fixed status text, not raw returned strings.
Evidence: payload/API tests in staff roles, sanitization and command
adapter failure regressions. Stored historical free-form error strings
are not retroactively rewritten by migration; operators should review
older records before enabling broader diagnostic exports.

### 11. Authorization review

All registered route families were inspected for shared authentication,
MFA, CSRF mutation dependencies, tenant/object checks, delegated guardian
capabilities and limited staff precedence. Reviewed sensitive approvals,
exceptions/requests, enrollments/commands, revocations, tenant roster,
guardians/audit, restore/offboarding, support and staff management.
The existing documented five-role model explicitly grants support and
read-only staff a names+counts tenant overview. That legitimate read
access is preserved rather than removed merely because it is global.
Audit logs remain tenant-scoped read-only visibility for authenticated
tenant users as documented; this task does not invent a narrower grant.
Tests cover authenticated sessions, cross-tenant object attempts,
read-only mutation refusal, delegated settings and fresh MFA negatives.
This is a source/test review, not an independent penetration test.

### 12. Honest status labels

DNS reporting says receipts/no reports, never connected solely because an
ingestion route exists. Device status labels server intent, command
ledger, stored receipts and unavailable APNs separately. Manual approval
and attestation remain manual, not executed. Policy publication is not
proof of filtering enforcement. UI decision detail follows honest states.

### 13. Related defects found during review

In addition to listed issues: worker/API lock-order inversion, legacy vs
ticket FK deadlock, expired-invite replacement blocked by uniqueness,
DDM/check-in lifecycle races, stale restore publication/credential evidence,
cleanup pointer overwrite and symlink directory escapes were addressed.
Generic publisher immutable-generation refusal was intentionally retained:
a test reusing a fixed filesystem root across fresh DBs was corrected,
not used to justify overwriting existing generations.

### 14-18. Testing, documentation, boundaries and handoff

See exact-SHA ledger above and FINAL_HANDOFF.md. Migration0025 adds
attestation enrollment/kind, cleanup marker, unique partial indexes and
wider approval status. Fresh PostgreSQL upgrade/downgrade/upgrade and
SQLite install/prior-row preservation pass. Existing deployments with
duplicate current enrollments or unused invitations must reconcile them
before migration; the unique-index build fails safely rather than silently
choosing an identity or deleting records. No production migration ran.

All20 PG matrix tests pass at candidate6399667. This is concrete evidence
for covered races, not a claim every theoretical interleaving is proven.
No production devices, Apple credentials, DNS/live site or infrastructure
were touched. No merge, force-push or branch deletion occurred. Apple
approval, native compilation/signing and physical-device testing remain
separate. This is not production-ready or iPhone-release-ready.

## Files changed at candidate6399667

- `control-plane/alembic/versions/0025_security_hardening.py`
- `control-plane/app/credential_ops.py`
- `control-plane/app/credential_routes.py`
- `control-plane/app/db.py`
- `control-plane/app/ddm_ops.py`
- `control-plane/app/device_status_routes.py`
- `control-plane/app/enrollment_routes.py`
- `control-plane/app/exception_request_routes.py`
- `control-plane/app/filter_log_ops.py`
- `control-plane/app/guardian_routes.py`
- `control-plane/app/main.py`
- `control-plane/app/mdm_ops.py`
- `control-plane/app/models.py`
- `control-plane/app/offboarding_routes.py`
- `control-plane/app/publication_ops.py`
- `control-plane/app/restore_routes.py`
- `control-plane/app/security.py`
- `control-plane/app/staff_routes.py`
- `control-plane/app/support_routes.py`
- `control-plane/app/worker.py`
- `control-plane/tests/conftest.py`
- `control-plane/tests/test_activity_privacy.py`
- `control-plane/tests/test_concurrency_pg.py`
- `control-plane/tests/test_ddm.py`
- `control-plane/tests/test_device_status.py`
- `control-plane/tests/test_filter_logs.py`
- `control-plane/tests/test_guardians.py`
- `control-plane/tests/test_mandatory_mfa.py`
- `control-plane/tests/test_migrations.py`
- `control-plane/tests/test_offboarding.py`
- `control-plane/tests/test_restore.py`
- `control-plane/tests/test_security_hardening.py`
- `control-plane/tests/test_staff_roles.py`
- `dns-edge/tests/test_doh_identity.py`

Later documentation/UI-only corrections are separately named in the final
delivery message. Do not label an earlier candidate test run as a run
against a later commit. Historical UI screenshots/load measurements are
not rerun evidence in this correction.
