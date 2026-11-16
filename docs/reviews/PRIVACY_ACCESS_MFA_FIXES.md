# Approved privacy, backend permissions and mandatory MFA fixes

Code-only build increment after 7afdaed. User approval: authenticated
November16,2026 12:56 message, covering these fixes and surrounding review.
Not deployed; no production archives or devices accessed. Original full-platform
coverage is still incomplete, and this is not launch approval.

## Privacy implementation

- Allowed-domain activity is rejected from storage unconditionally. There is
  no opt-in allowed browsing archive. Received valid allowed decisions return
  accepted=0, and no domain/rule/reason row is written.
- Only blocked qualified domains, source, tenant/device IDs and receipt time
  are collected in filter_decisions. Full URLs/paths are rejected. Arbitrary
  reason/rule strings are not retained, since they may carry path secrets.
- Tenant blocked retention defaults to7days. Verified owner can set1-30days
  through backend API and UI. Lowering retention deletes old rows immediately.
- Migration0012 physically deletes historical allowed/expired rows and invalid
  URL-like domains; retained legacy rule/reason strings are overwritten with
  fixed descriptions. This applies to the database on which migration runs,
  not production databases, which were not touched.
- Reads, status and ingestion purge physically with SQL DELETE, not a hidden
  dashboard filter. Standalone publication/maintenance worker purges all tenants
  each loop, even without incoming traffic; example service interval5seconds.
  The worker must actually be installed/running later. If stopped, offline rows
  remain until next loop/read/ingestion. This is not a hard deletion deadline
  guarantee during outages. Browser table refresh60seconds clears stale rows.
- API responses use no-store/private headers. No browser localStorage or export
  endpoint stores activity. No persistent reporter spool/cache exists. DNS
  reporter discards allowed events and posts blocked domains immediately with
  a bounded request timeout, dropping failures. DNS local JSON operational log
  retains event/outcome/transport/timing only, no domain/reason/device/client.
  Normal DNS stdout no longer emits decision bodies. Proxy callback likewise
  carries identifier-free block diagnostics only. Thus proxy detailed activity
  remains unconnected rather than silently writing an unpurged replica.
- New PostgreSQL dumps exclude filter_decisions DATA; schema retained. Supported
  restore strips activity DATA from legacy archive TOCs before restore, so old
  history cannot reappear through that path. A real local pg_dump/pg_restore
  test verifies both. Use matching PostgreSQL client/server major versions.

### Copies and deletion limitations

SQL DELETE is actual row deletion, not secure physical media erasure. PostgreSQL
MVCC dead pages, WAL/PITR, replicas, infrastructure snapshots, third-party
exports, old downloaded files, old JSON/journal logs, unmanaged browser copies
and existing immutable/offline backups are outside this code's ability to
prove erased. No existing external copy was accessed or deleted. Before a
pilot an operator must inventory each destination, purge historical allowed
history and expired blocked history there, disable detailed request/query/body
logging on reverse proxies/collectors, retire incompatible old archives under
their supported controls, and set volume/WAL/snapshot policies consistent with
the retention promise. Do not claim complete erasure while any such copy is
unaccounted for. Restoring archives by any path other than the reviewed script
must preserve its exclusion and run migrations/maintenance before serving.
Policy/category datasets and deliberate configuration audit records are
configuration, not browsing activity; those remain subject to their separate
backup/security requirements. No paid or live infrastructure was changed.

## Backend permissions and verified MFA

- Added guardian gates to all six previously unguarded policy, schedule,
  default-policy, device-create and assignment mutations. Viewers cannot call
  these or the existing protected setting/command endpoints directly.
- Owner/guardian and platform-admin accounts require a verified TOTP login
  session before any protected API. Password-only accounts get enrollment-only
  sessions with self-account/password/MFA/logout access. No development/env
  bypass exists. AuthSession.mfa_verified defaults false, including old sessions
  migrated by0011. Checking every request covers promotion of old viewer sessions.
- Enrollment verifies a server-stored pending secret and fresh password; has a
  five-attempt/60second persistent rate limit. Enrolling does not silently promote
  any session. Sign in again with a valid code. API checks both secret present
  and session verification; adding a secret later never upgrades an old session.
- Verified owner can recover another member's MFA only with fresh password.
  Reset deletes target sessions and pending secrets. Self-reset refused; a sole
  owner who loses MFA has no online bypass here. Recovery needs a separately
  reviewed identity-verification/operator procedure before production, not a
  support endpoint that silently disables MFA. No recovery codes are invented.
- Worker checks current actor tenant/role/enrolled MFA before executing queued
  publication, preventing demotion from keeping a hidden privileged path.
- Current role model is still owner/guardian/viewer plus platform-admin flag,
  not the full five-role/support model required by the original plan.

## Evidence and remaining tests

Before publication: control-plane220passed (PostgreSQL fixtures, clean Alembic
install/upgrade, retention physical deletion, API bounds/no-cache/rollback,
legacy/new archive copy tests, viewer direct calls, session promotion/recovery,
MFA lockout, queued demoted actor); engine337passed; DNS72passed; proxy32passed.
Feature tests enroll/login with real TOTP using a test helper, never disabling
production gates. Auth tests exercise raw password sessions separately.
JavaScript and shell syntax checks passed. Actual local UI rendered and
inspected: restricted privileged enrollment screen; owner saved3day retention
through form. These prove server behavior, not iPhone enforcement or deletion
from any external copies. Final fresh-clone results and exact SHA are reported
separately after publication.

Still missing original implementation: groups/scoped time-limited exceptions,
five-role model, full support/recovery/onboarding/offboarding workflows,
enrollment tickets, migration import tools, broader website/legal/compatibility
work, automatic proxy publication refresh and Apple/device/internet load tests.
Do not call the overall build complete from these suites.
