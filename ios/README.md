# KosherGuard iOS (Swift sources)

STATUS: UNCOMPILED FOR iOS, UNSIGNED, UNTESTED ON APPLE HARDWARE.
No Apple SDK, Apple Developer account credentials, or device has run
any of this code. What DOES exist (2026-11-17, this milestone):
REAL compiler verification of the portable (non-NetworkExtension,
non-SwiftUI) sources - tools/run-swift-portable-tests.sh builds them
with the official Swift 6.0.3 Linux toolchain (swift.org
swift-6.0.3-RELEASE-ubuntu22.04) as a genuine SPM package against the
pinned swift-crypto 3.12.3 dependency and runs 174 tests under real
XCTest: no API shims, no assertion shims, no
substitute crypto. Reproduce with docs/setup/IOS_BUILD.md. Exact results are in
docs/reviews/IOS_FILTERING_IMPLEMENTATION_REVIEW.md. This proves the
portable logic (managed-config parsing/validation, rule-store
persistence/integrity/monotonicity, rule matching, sync orchestration,
prefilter download/integrity/cadence, auth and credential clients)
compiles and behaves as tested on Linux Foundation. It proves NOTHING
about NetworkExtension behavior, SwiftUI, Apple API availability,
signing, entitlements, or device behavior. The FilterExtension and
KosherGuardApp sources ARE compiled on every push by the unsigned CI
build (.github/workflows/ios-unsigned-build.yml: xcodebuild,
generic/platform=iOS, CODE_SIGNING_ALLOWED=NO, macos-26 / Xcode 26.6)
- a compile-only check: it never runs a test, links a device runtime,
signs, or touches hardware, and the compile status of any given commit
is whatever the latest Actions run for that commit says (failures have
occurred and been fixed at the tip; check the run for the exact SHA).

Entitlements/approvals these targets need before any real use
(corrected 2026-11-17 against Apple's Network Extensions Entitlement
documentation and TN3134 - an earlier draft used the wrong key
`com.apple.developer.networkextension.networkextension` and a
standalone boolean `url-filter-provider`; both were wrong):
- `com.apple.developer.networking.networkextension` - an ARRAY of
  strings. `content-filter-provider` on BOTH filter extension targets
  and the app; `url-filter-provider` (a string value of the same
  array, never a boolean key) on the app target. These must be
  granted in the provisioning profile in EVERY case - no development
  configuration relaxes signed entitlements (TN3134 documents
  deployment restrictions: content filter providers run on supervised
  devices, on child devices via Family Controls, or per-app on
  managed devices from iOS 16).
- Family Controls (`com.apple.developer.family-controls`) is a
  SEPARATE capability with its own Apple approval for distribution;
  the Screen Time child-device path is not wired (blocker ledger in
  docs/setup/IOS_BUILD.md).
- Apple-hosted OHTTP Relay capability (approval required before any
  distribution build; from docs/GENTECH_TECHNICAL_INVESTIGATION.md
  sections 5.4 and 10).
- Coverage honesty: NEURLFilter sees WebKit/URLSession traffic only;
  binary verdicts only; no per-device reporting by design.

## Layout

- `Sources/KosherGuard/` - the guardian-facing app: filter status,
  policy summary, enrollment state.
- `Sources/FilterExtension/` - the Network Extension content filter,
  TWO targets per Apple's content-filter model (each provider class
  runs as its own app extension on its own extension point):
  KosherGuardFilter (com.apple.networkextension.filter-data,
  FilterDataProvider) and KosherGuardFilterControl
  (com.apple.networkextension.filter-control, FilterControlProvider).
  Both are wired in KosherGuard.xcodeproj - HAND-AUTHORED, never
  opened in Xcode, first real compile is a verification step.
  The data provider is STRICTLY READ-ONLY over the shared app-group
  FilterRuleStore (integrity-checked, cross-process-locked,
  monotonic compare-and-replace generations, identity-bound to
  tenant/device/managed-config) written by the app's
  FilterSyncController from the control plane's
  /api/devices/{id}/filter-rules export - which itself is sourced
  ONLY from the last published immutable generation (guardian
  explicit allow/block domains only, never category expansions).
  Verdicts come from FilterVerdictEngine: FAIL-CLOSED when no valid,
  current, identity-bound snapshot exists (only exact-host bootstrap
  infrastructure hosts pass), the snapshot's defaultPolicy is
  enforced for unmatched hosts, expiry is evaluated per flow, and a
  corrupt/unreadable store falls back to last-known-good only inside
  its own expiry window. Update propagation uses the supported path:
  the control provider detects store changes (mtime+size+inode
  stamps), calls notifyRulesChanged(), and the data provider reloads
  in handleRulesChanged().
- `Sources/URLFilter/` - prefilter (Bloom) download/verification
  from our url-filter-server (PrefilterUpdater, wired into the sync
  action) and the iOS 26 NEURLFilterManager wrapper
  (URLFilterConfiguration - UNUSED PREPARATION: zero call sites, no
  Apple URL Filter provider target/class exists in the project, and
  a downloaded Bloom file is NOT an installed Apple URL Filter; see
  the blocker ledger in docs/setup/IOS_BUILD.md).
- `Sources/URLFilter/CredentialIssuanceClient.swift` - requests
  short-lived scoped device credentials from the control plane's mint
  route. Wired (2026-11-16): a real call site exists
  (CredentialController in KosherGuardApp.swift) and both clients are
  members of KosherGuard.xcodeproj (and the directory-based SwiftPM
  URLFilter target; Package.swift declares the KosherGuard ->
  URLFilter dependency). Still NO iOS execution evidence: compiled
  unsigned in CI only, unsigned, untested on device, so
  dataset/proxy/doh are not
  working iOS functionality - server-side minting is covered by
  control-plane tests only. The published control plane mints the doh
  scope, so the client no longer refuses it; end-to-end DoH use stays
  unproven until an iOS build exists. Session acquisition is now REAL CODE:
  AuthSessionClient signs in through the published /api/auth/login
  (JSON body + static CSRF marker header, MFA code when enrolled; the
  server's identical-401 anti-enumeration is honored) and captures the
  kg_session cookie (contract re-checked against the published server
  after an initial draft used the wrong cookie name). A reachable user
  action exists: CredentialSignInView's "Sign in and request
  credential" button runs CredentialController.signInAndIssue =
  sign-in -> dataset-scope mint -> Keychain save. Server URL and
  device ID come from MDM-managed App Configuration
  (AppConfiguration.swift, com.apple.configuration.managed), the real
  configuration mechanism - nothing fixture-baked; unconfigured
  devices show "Not configured by MDM". Keychain lifecycle: a 401 at
  mint deletes the stored session; signOut() calls the server logout
  and deletes both keys. STILL no execution evidence (compiled unsigned in CI
  only, never run), so none of this is working iOS functionality.
- `Sources/URLFilter/DNSOverHTTPSClient.swift` - RFC 8484 DoH client
  attaching the scoped credential as an Authorization header, the
  app-mediated identity path from docs/design/DOH_IOS_TRANSPORT.md
  option 1. UNUSED PREPARATION: `resolve` has ZERO call sites and
  `AppConfiguration.dohServerURL` is only parsed/validated; the DoH
  transport is used only inside PrefilterUpdater's dataset fetches.
  Same wiring status as CredentialIssuanceClient (Xcode
  member, no app call site beyond the controller, compiled
  unsigned in CI only). This does NOT give system-wide DNS interception: it
  resolves only for traffic the app routes itself, and an operational
  extension path stays gated on Apple entitlements, compilation,
  signing, and device validation. The published
  server mints doh-scoped credentials; the client surfaces 401/403
  (fails closed) on rejection, and end-to-end use against dns-edge
  remains unproven without an iOS build.
