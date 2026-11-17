# iOS build and test instructions (reproducible)

STATUS: the portable-logic test path below is real and reproducible on
Linux. A true iOS build (Xcode compilation of the app and the two
filter extensions) has NEVER been run - no macOS/Xcode exists in the
development sandbox used for this milestone, so no iOS SDK compile,
signing, entitlement or device claim exists anywhere in this repo.

## 1. Portable logic tests (Linux/macOS, no Apple SDK)

What this proves: the non-NetworkExtension, non-SwiftUI sources
(managed-config parsing/validation, rule-store
persistence/integrity/monotonicity/locking, verdict engine, sync
orchestration, prefilter download/integrity/cadence, auth and
credential clients) compile with a real Swift toolchain and behave as
tested under real XCTest. What it does NOT prove: anything about
NetworkExtension, SwiftUI, Apple API availability, entitlements,
signing or device behavior - those sources are not in this build.

Steps (exactly what the 2026-11-17 milestone evidence used):

1. Install the official Swift toolchain:
   - Linux: download `swift-6.0.3-RELEASE-ubuntu22.04.tar.gz` from
     https://download.swift.org/swift-6.0.3-release/ubuntu2204/swift-6.0.3-RELEASE/swift-6.0.3-RELEASE-ubuntu22.04.tar.gz
     (784207421 bytes), extract, put its `usr/bin` on `PATH`.
   - macOS: any Xcode with Swift 6 works for this target; the tests
     avoid Apple-only APIs.
2. From the repo root:

   ```sh
   bash tools/run-swift-portable-tests.sh
   ```

   The script copies the portable sources into a temporary SPM
   package (set `KG_SWIFT_TEST_WORK` to reuse one), pins
   `swift-crypto` exactly 3.12.3, and runs `swift test`. There are no
   API shims and no substitute crypto.
3. Expected result at this revision: 36 tests, 0 failures.

## 2. Real iOS build (blocked - requirements ledger)

An actual Xcode build needs, in order:

1. macOS with a current Xcode (the project declares
   `compatibilityVersion = "Xcode 14.0"`, `IPHONEOS_DEPLOYMENT_TARGET
   17.0`; the URL Filter code paths need the iOS 26 SDK).
   An unsigned SDK compile (`xcodebuild -scheme KosherGuard
   -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO`)
   needs only this - no Apple account.
2. Fix-on-first-compile expectation: `ios/KosherGuard.xcodeproj` and
   everything under `ios/Configuration/` are hand-authored and have
   never been opened in Xcode; treat the first real compile as a
   verification step, not a formality.
3. Signed builds need an Apple Developer account with:
   - the Network Extensions capability values used in
     `ios/Configuration/*.entitlements` (key
     `com.apple.developer.networking.networkextension`, array values
     `content-filter-provider` on both extension targets and the app,
     plus `url-filter-provider` on the app) granted to the App IDs in
     the provisioning profiles - a development configuration does NOT
     waive signed entitlements;
   - the App Group `group.com.kosherguard.shared` (placeholder -
     replace with the real team-prefixed group everywhere: both
     entitlements files, `FilterRuleStore.appGroupIdentifier`);
   - for the Screen Time / Family Controls distribution path, the
     separate Family Controls entitlement approval from Apple;
   - for content-filter deployment, supervised devices (TN3134:
     iOS content filter providers run on supervised devices only, or
     child devices via Family Controls, or per-app on managed devices
     from iOS 16).
4. Device validation checklist once a signed build exists:
   filter enablement via NEFilterManager, app-group sharing between
   app and both extensions, notifyRulesChanged propagation, rule
   persistence across the first device lock (the store uses the
   after-first-unlock data-protection class precisely so lock-time
   filtering keeps working - verify on hardware), and expiry /
   fail-closed behavior with the device offline past the snapshot
   lifetime.

## 3. Known unused-preparation code (not dead weight, not wired)

These compile in the portable build or the app target but have no
production call path yet; they are preparation, listed here so no
report can imply otherwise:

- `DNSOverHTTPSClient.resolve` - 0 call sites. DoH is used only as
  the dataset transport inside `PrefilterUpdater`; app-mediated DNS
  resolution is unimplemented. `AppConfiguration.dohServerURL` is
  parsed and validated only.
- `URLFilterConfiguration.enableStandaloneFilter` - 0 call sites; the
  NEURLFilterManager wrapper is compiled into the app target but no
  Apple URL Filter provider target/class exists in the project, and
  no UI invokes it. Downloading the Bloom prefilter file is NOT an
  installed Apple URL Filter.
