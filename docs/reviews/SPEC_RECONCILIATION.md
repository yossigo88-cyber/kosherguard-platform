# Full specification reconciliation (pre-M8 accounting)

Date: 2026-11-16. Every claim names its tree. "Local" = local clone
HEAD with held unpublished commits; "published" = exact GitHub
full-platform-build content. Test counts are LOCAL unless a fresh-clone
run of the exact published SHA says otherwise (that run is M7).

M7 fresh-clone verification of the exact published head bda1279 is
COMPLETE (2026-11-16, clean clone, per-suite runs): control-plane 107,
mdm 34, url-filter-server 29, dns-edge 60, proxy-edge 25,
category-pipeline 6, dashboard 276, filtering-engine 336 - all passing.
One filtering-engine TCP test (large-response downstream) failed once in
a full-suite run and passed in isolation; timing flake, not a code
regression. Local tree counts that include the HELD unpublished fixes
are labeled "local" and are never published-tree claims.

Legend: DONE = implemented + local tests pass. BUILT-UNVERIFIED = code
written, needs hardware/credentials/Apple approval to validate.
PARTIAL = some of the requirement exists. OUTSTANDING = not built.
HELD = implemented locally, unpublished pending user approval of the
per-tenant publication security fix. BLOCKED = external dependency.

## Part 1 - Complete product

Sixteen components listed; all have code present in the monorepo.
Integration end to end is NOT claimed: external gates (Apple
approvals, credentials, hardware) and held work remain. PARTIAL.

## Part 2 - ABM and Automated Device Enrollment

- mdm/ade.py (ADE profile construction, supervision options),
  mdm/nanodep.py (NanoDEP-compatible client, contract-grounded from
  micromdm/nanodep operations guide: Basic auth, dep_names, assigner,
  proxy, cursor pagination), mdm/tests (34 passing locally). DONE as
  code; live ABM sync BLOCKED (ADE server token - user provides).
- Apple Configurator route + 30-day provisional period: documented in
  docs/MDM_ENROLLMENT_AND_PUSH.md. DONE (documentation).
- "Must actually work with Apple's systems": not claimed - no live
  enrollment has run. BUILT-UNVERIFIED.

## Part 3 - Non-removable MDM from day one

- ADE enrollment profile with supervision + unenrollment prevention is
  constructed in mdm/profiles.py (payload-level). Hardware-verified
  non-removability requires a supervised device: BUILT-UNVERIFIED.
- No removable-profile substitute is claimed anywhere.

## Part 4 - Factory-reset protection

- Restrictions payload (erase disabled) in mdm/profiles.py;
  re-enrollment-after-restore architecture in
  docs/MDM_ENROLLMENT_AND_PUSH.md (Finder/Apple Devices/recovery/DFU
  covered with limitations stated). BUILT-UNVERIFIED (hardware).

## Part 5 - Own MDM server

- Decision (documented in docs/evaluations): NanoMDM (MIT) as the
  protocol server + our mdm domain layer (enrollments, command queue
  with queued/delivered/acknowledged/applied states, adapters,
  reconciler). 34 mdm tests + control-plane MDM route tests pass
  locally. Command-state honesty enforced (supervision fix: requested
  vs verified are separate model columns, rendered evidence sent).
  DONE as code; live device check-ins BLOCKED (APNs + devices).

## Part 6 - Remote management and policy updates

- Control-plane policy CRUD + versioning, publication pipeline,
  tighten-only invariant, server-hosted PAC (proxy-edge/pac.py) and
  dataset distribution (url-filter-server) so filtering changes need
  no profile reinstall. MDM profile vs filtering policy kept separate.
  DONE as code; delivery to real devices BLOCKED.

## Part 7 - APNs

- mdm/apns.py: CSR generation, certificate upload/renewal tracking,
  expiry states, push token registry. 14 tests. DONE as code; live
  push BLOCKED (Apple credentials).

## Part 8 - Filtering engine

- Reviewed Stage 1-11 engine preserved (policy engine, category db,
  DNS service, comparison/tighten-only). DONE (pre-existing, audited).
- proxy-edge: PAC generation + proxy server. DONE as code. Proxy
  authentication (spec 8B): DONE - policy-bound device tokens in
  Proxy-Authorization, fail-closed 407/403, credentials stripped
  before relay, token never logged; 25 proxy-edge tests pass locally.
- dns-edge: runner + DoH per-device identity + per-device policy
  selection. DONE as code (fail-closed).
- Scoped credential issuance/request path: guardian-facing issuance
  route + scoped token mint/verify for doh (dns-edge), proxy
  (policy-bound) and dataset (unbound) scopes - TestCredentialIssuance
  and TestProxyScopeMinting (5) pass on the published tree at bda1279.
  DNS credential issuance request path covered by the same route and
  the dns-edge doh_identity request/verify code. Revocation registry,
  revoke route and revocation feed are HELD (local only, 4 TestRevocation
  tests) pending the user's decision on the held set.
- NE content filter + iOS 26 NEURLFilter: iOS Swift sources +
  Xcode project structure, UNCOMPILED/UNSIGNED/UNTESTED.
  BUILT-UNVERIFIED.
- PIR/OHTTP: Apple's vetted pir-service-example integrated
  (deploy/pir), dataset export in Apple's format + tests. OHTTP
  gateway: candidate selected + deployment wiring + local stub-target
  interop test PASS (deploy/ohttp; see
  docs/reviews/OHTTP_GATEWAY_ASSESSMENT.md for the exact proven/
  unproven split - image build, Apple PIR interop, relay ciphersuite
  compat, device validation each separately unproven). Relay BLOCKED
  (Apple approval).
- Capabilities matrix (8F): categories/domain allow/block/custom rules/
  policy assignment per device (device_policy.py) exist; filtering
  SCHEDULES: control-plane API + ScheduledPolicyEngine + schedule-aware
  tighten-only proof + UI DONE as code; whole-pipeline INCOMPLETE -
  per-device/multi-policy schedule emission held pending the user's
  decision on the held publication set; diagnostics PARTIAL.

## Part 9 - Category database

- category-pipeline: taxonomy.json, PROVENANCE.md, seed build, license
  review (UT1/Shallalist excluded as non-commercial-only). 6 tests.
- Admin management: API + rendered-verified admin UI (M6). DONE
  (seed-dataset scope). Commercial feed: not purchased (no approval),
  not required - approved fallback in use.

## Part 10 - Administration dashboard

- control-plane/web: policies, devices, MDM (enrollments, commands,
  supervision split), categories panels - rendered evidence exists for
  MDM and categories. Overview, Customers, schedules UI, credentials
  screen added (schedules + overview rendered; credential-upload screen
  rendered evidence exists - 3 screenshots: fixture banner, metadata
  list with active/revoked states; minor textarea-width polish noted).

## Part 11 - Customer-facing website

- website/ + portal/ (registration, secure login, customer dashboard).
  Rendered evidence from 03:25 (7 screenshots). Live replacement of
  the existing site NOT authorized and not done. DONE as code.
- Backend connection: portal talks to control-plane API. DONE.

## Part 12 - Customer accounts and multi-tenancy

- Tenants, RBAC (owner/guardian/viewer), guardian invite/accept/role/
  MFA-reset lifecycle with fresh-auth enforcement (M6). DONE as code.
- Cross-tenant isolation: HELD - the per-tenant publication isolation
  fix (2af092e + regression tests) awaits user approval to publish.
  Until then isolation at the publication layer is NOT claimed.

## Part 13 - Database and backend

- SQLAlchemy models, migrations (alembic), append-only audit_events,
  hashed session/invite tokens. DONE as code.
- Background workers/queue: command queue is DB-backed; a separate
  worker process design is PARTIAL (reconciler runs in-process).

## Part 14 - Security

- M1 auth slice (hashing, rate limiting, lockout, CSRF, MFA),
  input validation, RBAC, audit. DONE + tests.
- HELD: publication per-tenant isolation fix + negative tests
  (published after approval only).
- Secrets: none in repo; credentials redacted from logs by design
  (device_auth never logs token values, tested).

## Part 15 - Hosting and infrastructure

- deploy/: Caddyfile.example, systemd units, backup.sh, restore.sh,
  monitoring.md, prometheus.yml.example, COSTS.md, pir/. PARTIAL:
  backup/restore scripts exist but are NOT yet exercised end to end
  (executable recovery evidence OUTSTANDING). No hosting purchased.

## Part 16 - Apple credentials and setup

- docs/setup/APPLE_CREDENTIALS.md distinguishes ADE token vs MDM push
  cert, full gate checklist. Configuration screens: MDM panel covers
  enrollment/commands; dedicated credential-upload screens DONE
  (fixture-only build): metadata-only API, secret bytes 0600 on
  server filesystem outside Git, rotate/revoke lifecycle, owner-only,
  tenant-scoped, environment-stamped with an on-screen fixture-only
  banner. 12 tests pass on the published tree at bda1279 (fresh clone).
No credentials invented or hardcoded.

## Part 17 - Testing

- Published-tree fresh-clone verification at bda1279 (M7, clean
  clone, per-suite): control-plane 107, mdm 34, url-filter-server 29,
  dns-edge 60, proxy-edge 25, category-pipeline 6, dashboard 276,
  filtering-engine 336 - all passing (one timing-flake TCP test passes
  in isolation). Local tree including HELD fixes: control-plane 120
  (delta = 6 default-mutation reproof + 3 per-tenant publication
  negative tests + 4 revocation tests, all held unpublished).

## Part 18 - 22 deliverables

1 Complete source code: present, gaps named here. PARTIAL.
2 Complete MDM server: BUILT-UNVERIFIED.
3 Apple enrollment integration: BUILT-UNVERIFIED.
4 Remote device management: BUILT-UNVERIFIED.
5 APNs integration: DONE as code.
6 Non-removable enrollment config: BUILT-UNVERIFIED.
7 Factory-reset restrictions: BUILT-UNVERIFIED.
8 Automatic re-enrollment architecture: DONE (documented).
9 Filtering engine: DONE (pre-existing, reviewed).
10 Filtering policy database: DONE (pipeline + admin tools).
11 Administration dashboard: PARTIAL (sections missing).
12 Customer management: DONE as code (guardian lifecycle M6).
13 Customer-facing website: DONE as code (not live).
14 Database and migrations: DONE.
15 Hosting/deployment configuration: PARTIAL (backup exercise owed).
16 Security implementation: DONE except HELD isolation fix.
17 Monitoring and logging: DONE as config/docs (not running).
18 Backup and recovery: PARTIAL (scripts, unexercised).
19 Apple integration instructions: DONE (docs/setup).
20 Testing results: published-tree M7 verification DONE at bda1279
   (counts in Part 17); hardware/Apple-gated validation remains
   BUILT-UNVERIFIED.
21 Documentation: reviews per milestone + design docs. DONE, updated.
22 Remaining limitations: THIS DOCUMENT + per-milestone reviews. DONE.

## Part 19 - Development rules

- main preserved; all work on full-platform-build; no deployment;
  no credentials; no fake functionality claimed (honesty labels
  throughout); no paid dependencies introduced (NanoMDM/NanoDEP MIT,
  Apple example code Apache-2.0 - both free; Apple example's
  production-readiness flagged).

## Approved answers (2026-11-16 02:25) reconciliation

- Q1 base 9eaa221: DONE. Q2 continuous milestones + per-milestone
  review docs: DONE (M1-M6 review docs).
- Q3 per-device identity: device credentials + DoH binding + per-device
  policy resolution DONE as code; iOS native-transport constraint
  documented with Apple sources (DOH_IOS_TRANSPORT.md); app-mediated
  path requires the iOS app (BUILT-UNVERIFIED); mTLS hardware-unknown
  recorded. IP binding kept as limited fallback only (explicit flag).
- Q4 option A (Swift + project structure + server components, labeled):
  DONE as labeled-unverified code.
- Q5 seed dataset + admin tools + provenance: DONE (M6, UI evidence).
- Multiple guardians per tenant: DONE (M6).
- Security audit before reuse: DONE (M1 + erratum held).
- External integrations marked awaiting approvals: DONE (labels).
- No purchases/deployment/credential/device operations: HELD (none done).
