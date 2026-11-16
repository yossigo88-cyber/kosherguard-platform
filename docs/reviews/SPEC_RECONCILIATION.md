# Full specification reconciliation (pre-M8 accounting)

Date: 2026-11-16. Every claim names its tree. "Local" = local clone
HEAD with held unpublished commits; "published" = exact GitHub
full-platform-build content. Test counts are LOCAL unless a fresh-clone
run of the exact published SHA says otherwise (that run is M7).

M7 fresh-clone verification of the exact published head bda1279 is
COMPLETE (2026-11-16, clean clone, per-suite runs): control-plane 107,
mdm 34, url-filter-server 29, dns-edge 60, proxy-edge 25,
category-pipeline 6, dashboard 276, filtering-engine 336 - all passing.
One filtering-engine TCP test (large-response downstream) failed in the
first full-suite run and passed in isolation. This is an UNEXPLAINED
intermittent failure: a passing retry does not establish its cause, and
an entirely clean filtering-engine full-suite run has not been
recorded. First-run result preserved: 336 passed, 1 failed. Local tree counts that include the HELD unpublished fixes
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
- Scoped credential issuance/request path: the published mint route
  (POST /api/devices/{id}/dataset-credential) accepts scopes "dataset"
  (unbound) and "proxy" (policy-bound) ONLY - TestCredentialIssuance
  (dataset) and TestProxyScopeMinting (5) pass on the published tree
  at bda1279. A "doh" scope request is rejected 400 on the published
  tree: minting doh-scoped tokens is part of the HELD set (7cbdbef)
  pending the user's decision. dns-edge's doh_identity request/verify
  code (scope "doh") IS published, but no published mint route issues
  tokens it accepts, so app-mediated DoH identity cannot run end to
  end until the held set lands. Revocation registry, revoke route and
  revocation feed are also HELD (local only, 4 TestRevocation tests).
- iOS request-path clients (606bdf4, 4b83612): initially published as
  standalone source; since wired - real call site (CredentialController
  in KosherGuardApp.swift, deliberately no-op until native session
  acquisition exists), members of KosherGuard.xcodeproj and the
  SwiftPM URLFilter target (Package.swift dependency declared). STILL
  no execution evidence (uncompiled/unsigned/untested), so dataset/
  proxy minting is tested server-side only and is NOT working iOS
  functionality. Session acquisition: AuthSessionClient + reachable sign-in action
  (CredentialSignInView -> CredentialController.signInAndIssue)
  written against the published login contract (no separate native
  token exchange exists server-side - the JSON login + static CSRF
  marker IS the native path; a dedicated device-auth exchange remains
  a possible future server addition). Configuration: MDM-managed App
  Configuration (AppConfiguration.swift), no baked-in URL; the
  kg_session cookie contract was re-verified against the published
  server (an initial draft used the wrong cookie name - caught by
  contract review, fixed before publish). Storage:
  KeychainCredentialStore (ThisDeviceOnly) with lifecycle handling
  (401 clears session; sign-out clears all). All UNCOMPILED with no
  execution evidence - real code, not working functionality. A no-op
  controller is NOT counted as implemented integration.
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
  supervision split), categories, overview, customers, schedules,
  credentials, guardians, account panels. Rendered evidence exists for
  MDM, categories, credentials (3 shots), schedules (4), overview/
  customers, and the guardian + account self-service flow (9 shots:
  guardians list, one-time invite link, SIGNED-OUT invite acceptance
  in a fresh cookie-less browser context with URL and network checks,
  invitee sign-in, role change, password change, MFA enrollment with a
  real TOTP code; pipeline: pgserver + uvicorn + puppeteer,
  /tmp/evidence/run_guard.py). Minor textarea-width polish noted on
  the credentials screen.
- Applications panel (built 2026-11-16, f9715ad+): per-device app
  allow/block policy + Install/Remove/inventory command queueing with
  an explicit data-loss confirmation on removal (WWDC21 session 10136:
  managed-app removal erases the app's data container; Apple command
  list dep789n2k1qp). RemoveApplication stays device-unverified.
- Filtering activity + edge status (built 2026-11-16, ebd1e2e..d2b8d1a):
  - Ingestion POST/GET /api/filter-logs, proxy-scope bearer auth,
    tenant/device binding from the verified token; proxy-edge
    DecisionForwarder (best-effort batch POST, env-gated).
  - END-TO-END evidence: the real FilteringProxy decided 3 requests
    (explicit_block, category_block, default-allow RELAYED to a live
    upstream), the real DecisionForwarder delivered them (sent=3,
    dropped=0), and the UI rendered those rows (screenshot
    filtering-02-e2e.png, run_filtering_e2e.py). Earlier fixture-post
    evidence is ingestion/render-only history, kept labeled as such.
  - GET /api/filter-status + panel block report EVIDENCED state only:
    configured (selected policy, publication revision), reported
    (decision count/sources/latest), "DNS decision reporting: not
    connected", health hard-coded UNKNOWN with a note that issuance,
    configuration and receipts are none of them health. No invented
    operational status.
- DDM app-settings delivery (built 2026-11-16, d2b8d1a): the control
  plane now IS the DM server NanoMDM forwards to. Verified sources:
  NanoMDM operations guide "-dm" flag (main branch, fetched
  2026-11-16): NanoMDM v0.3.0+ appends the endpoint (tokens,
  declaration-items, declaration/<type>/<id>, status) to the -dm base
  URL with the enrollment id in X-Enrollment-ID, optional HMAC via
  -dm-send/recv-hmac-key (X-Hmac-Signature, Base64 SHA-256);
  KMFDDM ddm/items.go, token.go, declaration.go, http/ddm/ddm.go
  (cloned 2026-11-16) for the exact wire shapes, each citing the Apple
  documentation URLs. Built: GET /api/ddm/tokens, /declaration-items,
  /declaration/<type>/<id>, PUT /api/ddm/status (verbatim
  DDMStatusReport rows + enrollment last_seen); X-Enrollment-ID
  resolved against MDMEnrollment; server tokens track policy
  content so changes re-sync.
  TRUST BOUNDARY (hardened 2026-11-16 after review): X-Enrollment-ID
  is an identifier, not authentication - before this fix, with no
  KG_DDM_HMAC_KEY set, any caller knowing an enrollment ID could read
  that device's declarations and POST forged status reports
  (reproduced in tests; the platform is pre-deployment, so no live
  exposure existed). Now FAIL-CLOSED: every /api/ddm/* route is 503
  unless KG_DDM_HMAC_KEY is configured, and then every request must
  carry a valid X-Hmac-Signature (NanoMDM -dm-send-hmac-key signs even
  GETs, over an empty body). The HMAC authenticates the forwarding
  NanoMDM peer; the device authenticates to NanoMDM via the MDM
  protocol. No protection is inferred from network topology.
  STATUS SEMANTICS (corrected 2026-11-16): a stored status report is
  RECEIPT ONLY. Application evidence requires a
  StatusItems.management.declarations.configurations[] entry matching
  the served identifier AND server-token with active=true and
  valid="valid" (verified shape: apple/device-management
  declarative/status + statusreport.yaml via KMFDDM
  ddm/status/status.go). Received states are extracted into
  DDMStatusReport.declaration_states for that later check.
  DeclarativeManagement added to
  SUPPORTED_COMMANDS as the activation command. 6 tests + full suite
  green at d2b8d1a (control-plane 156, mdm 60).
  REMAINING GAPS, explicitly: (a) running NanoMDM with -dm pointed at
  the control plane is deployment configuration, not authorized code
  work - the serving side is built and tested, the forwarding side is
  NanoMDM's own verified behavior; (b) a served declaration is not an
  applied one - only a device status report proves application, and
  that awaits the Part 17 device-testing phase; (c) supervision/iOS27+
  gates are device-side (Apple depd65c456fa).
- DNS decision reporting: NOT connected. Two SEPARATE dependencies:
  (1) doh minting scope lives in held unpublished commit 7cbdbef
  (user decision pending) - blocked on the held set; (2) the dns-edge
  directory-layout mismatch is its own issue, independent of the held
  doh work, and stays listed as a separate open item.

## Part 11 - Customer-facing website

- website/ + portal/ (registration, secure login, customer dashboard).
  Rendered evidence from 03:25 (7 screenshots). Live replacement of
  the existing site NOT authorized and not done. DONE as code.
- Backend connection: portal talks to control-plane API. DONE.

## Part 12 - Customer accounts and multi-tenancy

- Tenants, RBAC (owner/guardian/viewer), guardian invite/accept/role/
  MFA-reset lifecycle with fresh-auth enforcement (M6) + guardian
  management UI and signed-out invite acceptance (rendered evidence).
  Account self-service: password change (fresh-auth, invalidates the
  account's other sessions, count audited) and server-bound MFA
  enrollment (PendingMfaEnrollment: server-generated secret, one
  pending row per user, 10-minute expiry, single-use; client never
  supplies the secret) - hardening verified by tests (substitution,
  expiry, replay, cross-user binding, session invalidation). DONE.
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
  monitoring.md, prometheus.yml.example, COSTS.md, pir/. Backup/
  restore: dashboard SQLite scripts exercised end to end by 16
  dashboard tests (M7, bda1279); PostgreSQL pg_backup.sh/pg_restore.sh
  verified by a REAL roundtrip 2026-11-16 ~05:20 EST (pg_dump 16.2
  custom format, pg_restore --list verification, restore into a fresh
  target database, post-restore row counts matched:
  tenants=1 users=1, "BACKUP/RESTORE ROUNDTRIP VERIFIED"). DONE as
  executable evidence. Production scheduling/retention wiring is
  deployment work, not code. No hosting purchased.

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
  filtering-engine 336 passed / 1 failed on the first full-suite run
  (unexplained intermittent; the same test passes in isolation - cause
  not established, clean full-suite run not recorded). Local tree
  including HELD fixes: control-plane 120
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
15 Hosting/deployment configuration: DONE as code + executable backup
   evidence (see Part 15); live hosting not purchased/authorized.
16 Security implementation: DONE except HELD isolation fix.
17 Monitoring and logging: DONE as config/docs (not running).
18 Backup and recovery: DONE (PG roundtrip 2026-11-16 + 16 dashboard
   backup/restore tests).
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
