# Security corrections and handoff (2026-11-17)

Repository: yossigo88-cyber/kosherguard-platform. Branch: full-platform-build.
Review baseline: `5254763d1477578c477fa2ee7338e953837dc672`.
Verified code candidate: `6399667e64b089f9b14915a6472fd402d0e9828f`.

## Evidence, not accumulated totals

A fresh clone at candidate6399667 passed1,272 tests across eight suites:
control-plane426, filtering-engine337, DNS87, MDM64, proxy38, URL38,
category6, dashboard276. Control-plane includes20 disposable-PostgreSQL
race tests, credential commit/filesystem fault tests, role/tenant/MFA
negatives and SQLite + PostgreSQL migration tests.

The prior1,210 and1,189 totals are historical and are not exact-head
verification. The old unresolvable44e48b1d9483b985984931a15cbdbd1c00542cb6
reference is withdrawn as evidence. The prior baseline had364
control-plane tests rerun, not a demonstrated full eight-suite rerun.

Full issue-by-issue findings, code paths, tests, limitations and changed
files: [security-corrections report](SECURITY_CORRECTIONS_2026-11-17.md).
Product coverage: [requirements matrix](../REQUIREMENTS_COVERAGE.md).
The final delivery message names the final published SHA and separates
candidate-SHA runs from later code and documentation commits.

## Corrected security behavior

- Sensitive approve/reject decisions are locked, fresh-MFA verified,
  tenant/target bound and single-use. Queued commands and manual Apple
  steps have distinct honest states, never a false executed result.
- Tenant-row serialization covers configuration, publication and device
  lifecycle writes. Bearer ticket redemption and worker publication use
  matching lock order. Database uniqueness backs current enrollment and
  unused invitation invariants.
- Restore readiness requires fresh enrollment-cycle evidence, a valid
  nonexpired dataset credential issued during that cycle, and published
  policy bytes matching the effective policy and protected baseline.
- Credential rotation/revocation commit metadata and cleanup intent
  before removing bytes. Cleanup failures remain visible and retryable.
- Ingestion checks the issuance registry, revocation, identity/scope and
  expiry. Periodic edge-feed propagation is not instant revocation.
- Support/read-only staff retain the limited tenant overview explicitly
  included in the existing five-role model. They gain no destructive or
  policy-changing authority.

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


## Safety boundary

No merge, force-push, branch deletion, deployment, DNS/live-site change,
purchase, real Apple credential change, or real-device operation occurred.
Main remains `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` at verification.
This is not a production-ready or iPhone-release-ready product.

## Independent-review followup verification

Code SHA `9d6d17b2d2e29dda0b5d66ea4523cf7ca337309c`: fresh GitHub checkout,
complete control-plane431 passed, including20 PostgreSQL matrix tests.
The earlier eight-suite1,272 result is still6399667 only. Followup adds
explicit queue-failed approval state/savepoint rollback and safe new-request
flow, exception-aware restore readiness, complete fixture isolation, and
actual publication-overlay race assertions. See the full report for each
regression and remaining lint/type/UI-visual and edge-propagation limits.
Revocation cleanup republishes the last published snapshot minus revoked
exceptions; it does not publish saved drafts. Active filtering exceptions
block restore readiness until both saved and pinned published overlays clear.
