# Final security review and handoff (Milestone 8)

Branch: `full-platform-build` in `yossigo88-cyber/kosherguard-platform`
(https://github.com/yossigo88-cyber/kosherguard-platform/tree/full-platform-build).
The exact final head SHA is reported in the delivery message that
accompanies this document's publication commit (this file cannot name
its own commit); every count and claim below was verified at that head
against a fresh clone.

## Verification state at delivery

1,202 automated tests, all green at head across eight components:
control-plane 356, filtering-engine 337, dns-edge 87, mdm 64,
proxy-edge 38, url-filter-server 38, category-pipeline 6, dashboard 276.

Independent-coverage-audit closure: the read-only requirements audit
run against this branch's earlier head found three buildable gaps. All
three are closed in code on this branch (commit
44e48b1d9483b985984931a15cbdbd1c00542cb6, 13 new tests, full
control-plane suite re-run green at 184+172):
1. Customer-tenant onboarding: staff-owner-only POST
   /api/staff/tenants creates the customer tenant plus a 7-day owner
   invitation (raw token returned once, stored hashed, audited), with
   a staff-panel Add customer form; invite accept reuses the existing
   flow (Answers 28/33).
2. Customer portal (spec Part 2A): devices now show enrollment and
   supervision state, receipt-based online/stale/offline connectivity,
   last confirmed update and pending command count; policies show
   schedules; permitted settings are shown from the account's
   delegations; structured exception requests (submit/list/approve/
   reject) create real PolicyExceptions through the same validation
   and approver rules as direct creation.
3. Device update-state chain (Answer 23): GET /api/devices carries
   per device the desired published revision (server intent), the
   push_chain (per-status command ledger counts - queued = push
   requested, delivered = push accepted by the channel,
   acknowledged/not_now = device answers - plus the latest command),
   reported_vs_published (the latest stored DDM receipt's declaration
   states matched by identifier + server-token + active + valid
   against what the server currently serves that enrollment, with
   explicit no_enrollment / no_report_received /
   no_declarations_served / served_not_fully_reported /
   all_served_reported_applied states), and receipt-based
   connectivity with last device receipt. Every field is labeled as
   server ledger record or stored receipt; actual on-device
   enforcement remains unverified. Deepened at commit
   a408645ab3b659bbdca2b8ceb42cd575ee1a7b1a after the auditor's
   recheck; suite re-verified green at that head (184+172).
Three committed load-test harnesses with measured numbers and CI smoke
tests (docs/reviews/LOAD_TEST.md). UI flows verified end-to-end with a
local headless browser against the real application (synthetic accounts,
disposable database): sign-in with TOTP, protected baseline, policy
preview, sensitive-approval approve/reject with device+requester
identity, staff role changes, read_only denial, desktop and 390px
mobile layouts.

## Security posture (summary of the detailed review docs)

- Authentication: hashed server-side session tokens, TOTP MFA required
  for every privileged account before any administrative access
  (password-only login is a restricted enrollment session), fresh MFA
  code plus a typed operation-name confirmation for every sensitive
  operation (Answer 25).
- Destructive device operations: two-person approval - a different
  privileged approver than the requester, single-use, expiring,
  operation+target-bound requests; support/read-only staff can neither
  request nor approve even when holding a tenant owner role; the
  approval UI shows the exact target device and requester and states
  that queueing is not device-side completion.
- Staff roles (Answer 29): owner / security_admin / support_admin /
  read_only. read_only is enforced at a single choke point: every
  mutating call outside account self-service is rejected regardless of
  any tenant role the account also holds; the portal hides mutation
  controls as UX, with the backend enforcing independently.
- Tenancy: every tenant-scoped query filtered by tenant id; publication
  roots are per-tenant with no user-controlled path segment; support
  staff cross-tenant access limited to names+counts lists and four
  read-only MDM query commands.
- Secrets hygiene: structured JSON request logs without credentials or
  bodies; invite tokens returned once and never stored or logged;
  /metrics restricted to staff; TOTP secrets never logged.
- Untrusted device input: inbound device payloads allowlisted and
  minimized before persistence - "we never request it" is not a
  control.
- File-integrity: categories and publication artifacts are validated
  with the engine's own loader, written to tempfiles, atomically
  replaced, and digest-verified after write; publication refuses to
  ship a diverged categories file.
- Detailed per-area reports: SECURITY_FIXES_2026-11-16.md,
  PRIVACY_ACCESS_MFA_FIXES.md, ENROLLMENT_IDENTITY.md, OFFBOARDING.md,
  RESTORE_RECOVERY.md, CATEGORY_SOURCES.md, ACCOUNT_ROLES.md,
  INVENTORY_SUPPORT.md, GROUPS_PROTECTED_BASELINE.md,
  POLICY_EXCEPTIONS.md, PUBLICATION_WORKER_SCHEDULES.md.

## Consolidated remaining limitations (deliverable 22)

1. All live Apple integration is unexercised: no production ABM/ADE
   tokens, APNs certificates, or Apple Developer Program membership
   exist (Answers 36/40). MDM/ADE/APNs code is tested at the server
   layer only; device-side behavior (push delivery, command
   acknowledgment, non-removability, factory-reset protection,
   re-enrollment) is built-unverified until run against real supervised
   hardware.
2. The native iOS app and iOS 26 URL-filter extension are source-only:
   never compiled, signed, entitled, installed, or tested (no Xcode or
   devices). Per Answer 16, DNS-only filtering must not be represented
   as full URL filtering; per Answer 15, pre-iOS-26 devices receive
   only the features in docs/COMPATIBILITY.md.
3. Load numbers are small-environment synthetic measurements on a
   single-CPU container (docs/reviews/LOAD_TEST.md). They are not a
   production capacity estimate; Answer 23's end-to-end update-speed
   goals remain unproven because most delivery segments (APNs, device
   acknowledgment, PAC refresh, native/URL-filter updates) do not exist
   in this environment.
4. No deployment was performed: render.yaml and deploy/ are
   configuration only. Live website replacement, DNS changes, and any
   production rollout are separately approved steps (Part 2 question
   15) and remain undone.
5. Website privacy/support copy documents the controls implemented in
   this build; any deployment must re-verify that the copy still
   matches the deployed configuration (retention windows, archive
   operators, support contact address).
6. Backup/restore is runbook + tested scripts against this
   environment's PostgreSQL; production RTO/RPO targets (Answer 37: 1h
   RTO / 15-min RPO as future goals, no SLA pre-deployment) are
   unproven until rehearsed against production infrastructure.
7. MDM payload structures follow Apple's documented formats but are
   marked built-unverified on device throughout the code; the first
   physical enrollment is a test event, not a confirmation.

## Handoff

- Review entry point: docs/REQUIREMENTS_COVERAGE.md (per-requirement
  status), this file (security + limitations), docs/reviews/
  (per-area detail), tools/benchmark_*.py (reproduce the numbers).
- Everything above is on `full-platform-build`; `main` was never
  touched. No merges, force-pushes, or branch deletions were performed.
- Independent review can reproduce every claim: clone the branch, run
  each component's pytest suite, and run the three benchmark tools.
