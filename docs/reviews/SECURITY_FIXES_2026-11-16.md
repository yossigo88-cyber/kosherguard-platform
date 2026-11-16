# Security fixes - final report (2026-11-16)

Scope: the three vulnerabilities reported to the user and explicitly
authorized for correction (user approval 2026-11-16 10:31 EST):
security fixes, regression tests, edge-case and cross-family isolation
tests, existing-suite runs, side-effect review, and review of the
surrounding code for related vulnerabilities.

All fixes are published on branch full-platform-build, commits
af763a7..8e2db42 on top of the paused checkpoint eaba4b6. Remote ==
local verified via git protocol. Fresh-clone verification at the exact
published head 8e2db42: control-plane 178, mdm 64, proxy-edge 30,
dns-edge 60, url-filter-server 29, category-pipeline 6,
filtering-engine 337, dashboard 276 + test_devices_ui.mjs - all green.

## Fix 1 - cross-family publication vulnerability

Problem: every tenant published into the same publication root, and on
a failed publish the cleanup path removed the generation directory
unconditionally - one family's failed operation could delete or
overwrite another family's active configuration.

Fix (af763a7, f88fd8d, f141ebb):
- publisher.py: cleanup only removes a generation directory the same
  publish call created (created-flag); a pre-existing directory (a
  replay, a bug, or another publisher's data) is never deleted.
- publication_ops.py: publish_selected writes into
  tenant_root(root, tenant_id) built from the configured root and the
  integer tenant id only - no user-controlled path segment; tenants
  cannot see, overwrite, or delete each other's generations.
  publication_current reads the same tenant root.
- publication_ops.py/config.py: exported policy documents are validated
  with the engine's own validator (re-normalizing would have dropped
  nested category_rules); an optional categories_file (seed dataset)
  is validated before publication.

Regression tests (0759c42): one tenant's publish never touches another
tenant's generations - verified at the byte level: both tenants'
generation-1 policy.json files exist AND the first tenant's current
generation still loads in the engine and decides correctly after the
second tenant publishes (not merely directories present); a replayed
revision is refused and the original generation's manifest bytes and
the current pointer are unchanged (failed-publish cleanup only removes
self-created data); categories file publication path covered.

## Fix 2 - scheduled-block policy bypass

Problem (two parts): (a) the tighten-only comparison did not account
for schedules, so an assignment could omit required scheduled blocks of
the default and still pass 'at least as restrictive' validation -
fixed earlier by the schedule-aware coverage proof (73b61c7,
published); (b) the invariant was only enforced when a non-default
policy changed - mutating the selected default itself could leave
assignments weaker than the new baseline, and the default could be
disabled outright.

Fix (47c9fb6, f3518f5):
- policy_ops.enforce_on_content_mutation: mutating the selected default
  re-proves EVERY other active assignment against the PROPOSED baseline
  and refuses with per-policy violations while any assignment would end
  up weaker (strengthening the default is refused rather than silently
  breaking the invariant; weakening the default stays allowed because
  assignments remain at least as restrictive).
- main.py: disabling the selected default policy is refused; select
  another default first.

Regression tests: (a) the original omitted-schedule bypass - an
assignment without the default's required schedule is refused, a
covering schedule is accepted, missing schedule blocks refused
(test_assignment_without_default_schedule_refused,
test_assignment_with_covering_schedule_accepted,
test_missing_schedule_blocks_refused, published earlier); (b) the
default-mutation reproof - strengthen-default refused for base rules
and for schedules, covered assignment accepted, weaken-default
allowed, disable-selected-default refused, mutating an assigned
default policy itself allowed (750f06a).

## Fix 3 - device-management authentication/authorization

Problem: X-Enrollment-ID was an identifier acting as an authenticator.
The earlier fix (already published) made the HMAC mandatory so only the
NanoMDM peer can forward - but enrollment IDs alone still authorized
access for any enrollment row, including pending placeholders created
before any device ever checked in.

Fix (05454e0, f3518f5, 2909c36) - the actual trusted chain, now
implemented and documented in ddm_ops:
1. Device -> NanoMDM: the device authenticates through the MDM protocol
   (NanoMDM's responsibility; the control plane never talks to the
   device directly).
2. NanoMDM -> control plane: the shared HMAC key authenticates the
   forwarding peer on every request (fail-closed without
   KG_DDM_HMAC_KEY).
3. Authorization: an enrollment ID is a lookup key only. DDM serving
   (tokens, declaration-items, declaration, status) requires the
   enrollment to be in state enrolled/active; a pending placeholder
   authorizes NOTHING (ddm_ops.authorize_active).
- New POST /api/mdm/enrollment-checkin (same HMAC peer auth) records a
  NanoMDM-confirmed device check-in: pending -> enrolled, idempotent.
  It records ENROLLMENT ONLY. Verified mechanism (NanoMDM operations
  guide, main branch): NanoMDM forwards device check-in traffic only
  for enrollments it authenticated via the MDM protocol; the deployment
  syncs that confirmation to this route. Supervision is explicitly NOT
  accepted from this caller: supervision_verified can only be set from
  device-reported check-in data (mdm_ops.mark_supervision_verified),
  and no verified sync for it is wired yet, so it stays false. (An
  earlier draft of this route accepted a caller-claimed 'supervised'
  flag - removed after review: a claimed value is not verified
  supervision.)
- Credential revocation (approved companion hardening): IssuedCredential
  issuance registry (jti only, never the token), per-device revoke
  route, per-tenant revocation feed for edge verifiers; doh mint scope
  wired for the DNS edge (edge consumption of the feed is pending the
  distribution design, documented).

Regression tests (6b09060, 8801186): pending refused on all four DDM
routes; checkin activates; bad-HMAC checkin refused and does not
activate; unknown enrollment 404; idempotent checkin update; revocation
mint/revoke/feed and cross-tenant 404.

## Surrounding-code review

Reviewed publication, policy, credential, and DDM/MDM code adjacent to
the fixes:
- No policy-delete route exists; disable is the only removal path and
  is now guarded.
- select-default requires an enabled policy and the existing
  tighten-only/schedule-coverage proofs.
- Credential revoke is cross-tenant 404; the revocation feed is
  tenant-scoped.
- The HMAC peer key is deployment-wide: NanoMDM remains the trusted
  boundary for mapping devices to enrollment IDs (documented in the
  ddm_ops trust-model paragraph).
No additional serious vulnerability was found; nothing required a
further user decision gate.

## Residual limitations (explicit)

- Edge verifiers do not yet consume the revocation feed (distribution
  design pending); revocation at the edge is INCOMPLETE until that is
  implemented and exercised. Natural short token expiry bounds
  exposure.
- The enrollment-checkin sync wiring to NanoMDM is deployment work,
  not shipped code; until wired, enrollments stay pending and DDM
  serving stays closed to them (fail-closed).
- Device-side DDM behavior is BUILT-UNVERIFIED until the Part 17
  device-testing phase: a served declaration is not an applied one, and
  a received status report is receipt, not proof of application.
