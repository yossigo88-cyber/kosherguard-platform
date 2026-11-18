# Stage 12 - First Real Xcode Build: ACTUAL Results

- Repository: https://github.com/yossigo88-cyber/kosherguard-platform (public)
- Branch: `stage-12-free-ios-build`. This running report covers five runs on five successive heads: run 1 built `5c737e9c3e891de089affb62193f46f2713a9f37` (the header run below), run 2 built `c789cd36394cf5044c846af5f0e7bda53465e1c8`, run 3 built `7abe15773b74646e6613ff56aac506d13c55730e`, run 4 built `a4026c23ae6be14dcfda2a002f20c24dcea36ff3`, and run 5 built `50573f04511ffcc614a7f1afe965e5553ea18c1d` - the current tested code, which SUCCEEDED with the packaging warning and all Swift warnings resolved.
- Run 1: GitHub Actions run 44207115197 ("iOS unsigned build"), 2026-11-18T00:21:14Z, free standard `macos-26` runner, $0 compute for public repos, no artifacts uploaded
- Untouched: `main` `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`, `stage-10` `791f0ef`, `stage-11` `62c0ccc`, superseded `stage-12-free-ci-unsigned-build` `b30a6bb`
- Status: FIVE REAL RUNS COMPLETED. Run 1 failed with 6 compile errors (fixed, user-approved). Run 2 CONFIRMED those 6 are gone and surfaced 1 new compile error in a different file. Run 3 CONFIRMED that error is fixed (all four extensions link) and surfaced 2 pre-existing errors further along in the app target. Run 4 CONFIRMS those 2 are fixed: **BUILD SUCCEEDED** - the app target and all four extensions compile and link, unsigned. Run 5 (packaging validation) CONFIRMS the URLFilter ExtensionKit appex now embeds in the app bundle's `Extensions` directory per Apple's requirement, and all Swift warnings are resolved: **BUILD SUCCEEDED**, zero code warnings. Nothing was signed, deployed or purchased. A successful unsigned compile is NOT evidence of working filtering on a device.

## 1. What ran

- Job `static-validation` (ubuntu-latest): SUCCESS in ~3s (`python3 tools/validate-ios-project.py` - all checks passed).
- Job `xcode-compile` (macos-26, Xcode 26.6 at /Applications/Xcode_26.6.app, iPhoneOS 26.5 SDK, arm64 target, `-destination generic/platform=iOS`, Debug, `CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO`): **FAILURE, exit code 65**, job duration ~43s.
- Workflow activation itself proves the approved `Workflows: write` grant works; run status and logs were retrieved with the existing token (no new permission needed).

## 2. How far the build got

- Xcode 26.6 selection and `xcodebuild -list` succeeded (project/scheme parsed - the hand-authored pbxproj loads).
- Swift driver planning started for all four extension targets (KosherGuardURLFilter, KosherGuardFilterControl, KosherGuardFilter, KosherGuardDNSProxy).
- Compilation FAILED in the shared URL filter sources; no target reached the link stage.

## 3. Exact compiler errors (verbatim from the job log)

All in `ios/Sources/URLFilter/FilterRuleStore.swift`, same root cause at 6 sites (lines 503, 546, 717, 867, 985, 1086):

```
error: type 'NSData.WritingOptions.Element' (aka 'NSData.WritingOptions') has no case 'completeUntilFirstUserAuthentication', but it does have a case named 'DataWritingFileProtectionCompleteUntilFirstUserAuthentication'; if 'completeUntilFirstUserAuthentication' worked before, a recent change to the underlying C enum may have affected how prefixes are stripped from its case names
```

One non-fatal warning (unrelated): `FilterSyncController.swift:542:17: warning: no calls to throwing functions occur within 'try' expression`.

Full raw job log available in the GitHub Actions UI and via the run-logs API for run 44207115197.

## 4. Diagnosis

The code uses the old-style Swift name `.completeUntilFirstUserAuthentication` for the Foundation `NSData.WritingOptions` file-protection flag. The correct current SDK spelling is `.completeFileProtectionUntilFirstUserAuthentication`. This is a source-level compile error, not a build-configuration or signing issue - the unsigned-CI path itself works end to end.

## 5. Prepared fix (reviewed locally, NOT yet pushed)

Six one-token replacements in `ios/Sources/URLFilter/FilterRuleStore.swift`:
`options.insert(.completeUntilFirstUserAuthentication)` -> `options.insert(.completeFileProtectionUntilFirstUserAuthentication)` at the same six lines. No logic change; the file-protection semantic is identical. A neighboring comment on line 862 that names the protection level is untouched (comment only). Rebuild required after the fix to confirm zero remaining errors; more errors may surface once this file compiles, since compilation stopped here.

---

## Run 2 - verification rebuild (2026-11-18T00:34:38Z)

- Run: GitHub Actions run 44208950518, head `c789cd3`, same free `macos-26` runner, Xcode 26.6 / iPhoneOS 26.5 SDK. Run URL: https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44208950518
- static-validation: SUCCESS. xcode-compile: FAILURE, exit code 65, ~46s.
- Checks and tests, stated exactly: the only pre-push check run was `tools/validate-ios-project.py` (all checks passed). The repo DOES have a portable Swift test harness (`tools/run-swift-portable-tests.sh`, which compiles and runs sources including `FilterRuleStore.swift` under SPM/XCTest - the 136 passing tests recorded in the Stage 10 review), but it was NOT run for this fix: no Linux Swift toolchain was installed in the execution sandbox, and the six changed lines sit inside `#if canImport(Darwin)` guards that the portable harness cannot exercise anyway. The real Xcode run is what exercised the change and surfaced the next issue. Python suites were run after the push for general completeness only and are unrelated to this change: `mdm/tests` 136 passed, `filtering-engine/tests` 337 passed; `url-filter-server` tests could not collect (missing fastapi in this sandbox), `control-plane` needs pgserver.

### The six FilterRuleStore errors are GONE

`FilterRuleStore.swift` compiles clean; the URLFilter, FilterControl and Filter targets advanced past it. Failure moved to the DNSProxy extension compile batch.

### Remaining error (1 unique, verbatim)

`ios/Sources/DNSProxyExtension/DNSProxyProvider.swift:164:49`:

```
error: missing argument for parameter 'completionHandler' in call
            let chunk = try await flow.readData()
                                                ^
NetworkExtension.NEAppProxyTCPFlow.readData:3:13: note: 'readData(completionHandler:)' declared here
```

Diagnosis: the code awaits `NEAppProxyTCPFlow.readData()` as if an async variant exists; the iOS SDK only declares the completion-handler form, so the call must be wrapped (e.g. `withCheckedThrowingContinuation`). This is a real source-level API-usage error, one site, not a one-token rename. NO fix applied - pending the user's decision, per instruction.

### Warnings (non-fatal, pre-existing)

- `FilterSyncController.swift:542:17` - 'no calls to throwing functions occur within try'
- `ApplePrefilter.swift:121:45` - "immutable value 'skew' was never used"
- `ApplePrefilter.swift:121:56` - "immutable value 'damp' was never used"

---

## Run 3 - DNS readData wrapper verification rebuild (2026-11-18T00:44:36Z)

- Run: GitHub Actions run 44210301294, head `7abe15773b74646e6613ff56aac506d13c55730e`, same free `macos-26` runner, Xcode 26.6 / iPhoneOS 26.5 SDK. Run URL: https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44210301294
- static-validation: SUCCESS. xcode-compile: FAILURE, exit code 65, ~45s.
- The fix under test: one call-site change plus one new private helper in `ios/Sources/DNSProxyExtension/DNSProxyProvider.swift` (+25/-1, nothing else). `readTCPChunk(_:)` bridges `NEAppProxyTCPFlow.readData(completionHandler:)` to async/await with `withCheckedThrowingContinuation` (`CheckedContinuation<Data?, Error>`); the system calls the handler exactly once per read request and the continuation is resumed exactly once (throwing on error, else returning data, nil = end-of-stream). Errors/EOF still propagate to `readTCPLoop`, which closes the flow (fail closed).

### Pre-push gates - actually run this time, in this order, BEFORE the push

1. `python3 tools/validate-ios-project.py` - all checks passed, exit 0 (14 informational placeholders, expected until a real team ID exists).
2. `bash tools/run-swift-portable-tests.sh` - **136 tests, 0 failures, exit 0**, on the official `swift-6.0.3-RELEASE-ubuntu22.04` toolchain (download.swift.org, 784207421 bytes, the exact toolchain documented in `docs/setup/IOS_BUILD.md`), real SPM + pinned swift-crypto 3.12.3 + real XCTest. Honest limit, unchanged: the harness compiles only the portable sources (`FilterRuleStore.swift` et al.); `DNSProxyProvider.swift` imports NetworkExtension and is NOT compiled by it, so this run proves no portable-logic regression but does NOT exercise the wrapper. The macOS run below is the wrapper's real verification.

### The DNSProxyProvider.swift:164 error is GONE - the extension now links

- Zero occurrences of the `readData`/`completionHandler` error anywhere in the 2303-line raw log.
- `KosherGuardDNSProxy` compiled AND linked (`KosherGuardDNSProxy.appex` produced). For the first time in Stage 12 all four extension targets (URLFilter, FilterControl, Filter, DNSProxy) compiled and linked.

### Remaining errors (2 unique, verbatim) - pre-existing code, NOT from this fix

Both in the `KosherGuard` app target, in `ios/Sources/URLFilter/URLFilterConfiguration.swift`:

```
ios/Sources/URLFilter/URLFilterConfiguration.swift:120:24: error: cannot find 'pirServer' in scope
ios/Sources/URLFilter/URLFilterConfiguration.swift:129:24: error: cannot find 'issuer' in scope
```

Root cause (verified with git, not inferred): the `NSPIRConfiguration` validation block inside `static func disableFilter()` (lines 107-135, including both error sites) references local constants `pirServer`/`issuer` that are only bound inside `enable()` (lines 48/51, from the loaded configuration); `disableFilter()` never binds them. `git blame` attributes the whole block to commit `023802f1` (2026-11-17, "Repackage URL Filter as a dedicated extension..."), before Stage 12 began; the function itself dates to `20f38247` (2026-11-16).

Why runs 1-2 did not show them: the run-2 raw log (44208950518) contains ZERO mentions of `URLFilterConfiguration.swift` - the app-target compile batch containing it was never reached because the DNS extension failed first. These errors were masked, not introduced.

NO fix applied - choosing the correct source of the expected PIR endpoints inside `disableFilter()` (or whether the check belongs there at all) is a behavior decision pending the user's direction.

### Warnings (non-fatal)

- `FilterSyncController.swift:542:17` - 'no calls to throwing functions occur within try'
- `ApplePrefilter.swift:121:45` - "immutable value 'skew' was never used"
- `ApplePrefilter.swift:121:56` - "immutable value 'damp' was never used"
- `MDMEnrollmentClient.swift:24:14` - "immutable value 'data' was never used" (app target; surfaced for the same masking reason as the errors above)
- Plus a benign `appintentsmetadataprocessor` notice ("Metadata extraction skipped. No AppIntents.framework dependency found.") - not a Swift defect.

### How far the build got

The four extension targets compiled and linked; the app target failed at the `URLFilterConfiguration.swift` compile batch and never linked. More errors may exist behind these two. Nothing signed, deployed or purchased; no Apple account or device changes.

---

## Run 4 - URLFilterConfiguration disableFilter() fix verification rebuild (2026-11-18T01:16:23Z) - BUILD SUCCEEDED

- Run: GitHub Actions run 44214515026, head `a4026c23ae6be14dcfda2a002f20c24dcea36ff3`, same free `macos-26` runner, Xcode 26.6 / iPhoneOS 26.5 SDK. Run URL: https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44214515026
- static-validation: SUCCESS (~5s). xcode-compile: SUCCESS (~71s) - **BUILD SUCCEEDED** - the first successful Stage 12 build.
- The fix under test: `ios/Sources/URLFilter/URLFilterConfiguration.swift` only, +11/-29. The copied `NSPIRConfiguration`/Info.plist mismatch-validation block was REMOVED from `static func disableFilter()`; `enable()` is byte-identical.

### The lifecycle decision (why removal, not rebinding)

`pirServer` and `issuer` are per-call inputs of `enable(from:)`: bound there from the CURRENT managed configuration, used to fail closed when unconfigured, to cross-check the Info.plist declaration, and to build the `setConfiguration` call. `disableFilter()` takes no configuration, never calls `setConfiguration`, and uses neither value - so the enable-time check has no meaning there. Keeping any version of it in the disable path would also WEAKEN security: the caller (`KosherGuardApp.swift`, configuration lifecycle) calls `disableFilter()` as the fail-closed path precisely when the PIR keys are missing or invalid, so disabling must stay able to succeed in exactly that state. The copied block was dead code that could never compile; removing it changes no enable-time validation, the fail-closed default (`shouldFailClosed = true`), or any other behavior. Nothing was hardcoded.

### Pre-push gates - actually run, in this order, BEFORE the push

1. `python3 tools/validate-ios-project.py` - all checks passed, exit 0 (14 informational placeholders, expected until a real team ID exists).
2. `bash tools/run-swift-portable-tests.sh` - **136 tests, 0 failures, exit 0**, on the official `swift-6.0.3-RELEASE-ubuntu22.04` toolchain (download.swift.org, 784207421 bytes, per `docs/setup/IOS_BUILD.md`), real SPM + pinned swift-crypto 3.12.3 + real XCTest. Honest limit, unchanged: the harness compiles only the portable sources; `URLFilterConfiguration.swift` imports NetworkExtension and is NOT compiled by it. The macOS run below is the compile verification for this change.

### Verified in the raw log (2580 lines)

- ZERO `error:` lines anywhere in the xcode-compile log; both run-3 errors (`pirServer`, `issuer`) are gone.
- Real link steps for all four extensions: `Ld .../KosherGuardURLFilter.appex/...`, `Ld .../KosherGuardFilterControl.appex/...`, `Ld .../KosherGuardFilter.appex/...`, `Ld .../KosherGuardDNSProxy.appex/...`.
- **The app target now links**: `Ld .../Debug-iphoneos/KosherGuard.app/KosherGuard normal (in target 'KosherGuard')`, followed by `Touch .../KosherGuard.app` and `** BUILD SUCCEEDED **`.

### Warnings (non-fatal, unresolved)

Five unique Swift warnings, all pre-existing code (none from this fix):

- `FilterSyncController.swift:542:17` - 'no calls to throwing functions occur within try'
- `ApplePrefilter.swift:121:45` - "immutable value 'skew' was never used"
- `ApplePrefilter.swift:121:56` - "immutable value 'damp' was never used"
- `MDMEnrollmentClient.swift:24:14` - "immutable value 'data' was never used"
- `AppBlockingView.swift:125:9` - 'switch must be exhaustive' (app UI target; surfaced now because the app target compiled fully for the first time)

Plus two non-Swift notices:

- `warning: KosherGuardURLFilter.appex is an ExtensionKit extension and must be embedded in the parent app bundle's Extensions directory, but is embedded in the parent app bundle's PlugIns directory` - NEW packaging warning, surfaced now that bundling completed. Non-fatal for the unsigned compile, but it must be fixed before a real signed deployment can load the URL Filter extension. NOT fixed in this round (out of the authorized scope).
- Benign `appintentsmetadataprocessor` notices ("Metadata extraction skipped. No AppIntents.framework dependency found.") - not a defect.

### Limits, stated plainly

- This is an UNSIGNED compile-and-link success on a CI runner. It proves the Swift source compiles and links for iPhoneOS 26.5 arm64 with `CODE_SIGNING_ALLOWED=NO`. It does NOT prove the app runs, the URL Filter or DNS proxy filter anything, or that any target loads on a device.
- The ExtensionKit embedding warning above is unresolved and blocks real extension loading until fixed.
- Nothing signed, deployed or purchased; no Apple account or device changes; `main`, `stage-10-ios-runtime-integration`, `stage-11-apple-build-signing` and the superseded `stage-12-free-ci-unsigned-build` untouched.

## Run 5 - packaging validation round (2026-11-18T01:34Z) - BUILD SUCCEEDED, warnings resolved

- Run: GitHub Actions run 44216829456, head `50573f04511ffcc614a7f1afe965e5553ea18c1d`, same free `macos-26` runner, Xcode 26.6 / iPhoneOS 26.5 SDK. Run URL: https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44216829456
- static-validation: SUCCESS. xcode-compile: SUCCESS - **BUILD SUCCEEDED**.
- Scope: investigate the run-4 ExtensionKit packaging warning against Apple's requirements before changing anything; correct confirmed packaging issues; fix only safe, necessary Swift warnings; re-run gates and one free unsigned build; document signing/device readiness.

### Investigation: what Apple actually requires (verified, not assumed from the warning)

1. The run-4 warning verbatim: `KosherGuardURLFilter.appex is an ExtensionKit extension and must be embedded in the parent app bundle's Extensions directory, but is embedded in the parent app bundle's PlugIns directory`.
2. Apple's own sample project for this exact extension point - "Filtering traffic by URL" (https://developer.apple.com/documentation/networkextension/filtering-traffic-by-url), project archive downloaded from Apple's docs-assets CDN - embeds `SimpleURLFilterExtension.appex` with a copy phase named "Embed Foundation Extensions" using `dstPath = "$(EXTENSIONS_FOLDER_PATH)"` and `dstSubfolderSpec = 16`, and sets `IPHONEOS_DEPLOYMENT_TARGET = 26.0` on the extension target.
3. Apple Technote TN3134 (https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment): a URL filter provider is packaged as an app extension and requires iOS 26.0 minimum.
4. Conclusion: the warning was CORRECT. `KosherGuardURLFilter.appex` (declared with `EXAppExtensionAttributes` / `EXExtensionPointIdentifier com.apple.networkextension.url-filter-control`) is an ExtensionKit extension and belongs in the app bundle's `Extensions` directory. The other three appexes are traditional NetworkExtension app extensions (`NSExtension` dictionary) and correctly stay in `PlugIns`.

### Fix 1 (packaging, confirmed): `ios/KosherGuard.xcodeproj/project.pbxproj`

- Split the single "Embed Foundation Extensions" copy phase (which had embedded ALL FOUR appexes into `PlugIns`, dstSubfolderSpec 13) into two:
  - "Embed App Extensions" (PlugIns, dstSubfolderSpec 13, unchanged destination): KosherGuardFilter, KosherGuardFilterControl, KosherGuardDNSProxy.
  - "Embed Foundation Extensions" (NEW phase, `dstPath = "$(EXTENSIONS_FOLDER_PATH)"`, dstSubfolderSpec 16 - byte-matching Apple's sample): KosherGuardURLFilter only.
- Raised the URLFilterExtension target's `IPHONEOS_DEPLOYMENT_TARGET` from 17.0 to 26.0 (Debug + Release), matching TN3134's minimum OS and Apple's sample. The app and other extension targets keep 17.0; no other build setting changed.
- Verified in the run-5 raw log: the built app contains `KosherGuard.app/Extensions/KosherGuardURLFilter.appex` and `KosherGuard.app/PlugIns/{KosherGuardDNSProxy,KosherGuardFilter,KosherGuardFilterControl}.appex`. The packaging warning is GONE. No deployment-target-mismatch warning appeared.

### Fix 2 (Swift warnings): all four were safe to fix; all four fixed

- `AppBlockingView.swift:125` 'switch must be exhaustive': the iOS 26 SDK added a KNOWN case, `AuthorizationStatus.approvedWithDataAccess` (Apple doc: https://developer.apple.com/documentation/familycontrols/authorizationstatus/approvedwithdataaccess - iOS 26.4+, "grants everything that .approved allows" plus non-tokenized data access). It is availability-annotated, so it cannot be a case pattern on the app's iOS 17.0 deployment target. The approved path is now a shared local function; a plain `default` branch routes `.approvedWithDataAccess` (guarded by `if #available(iOS 26.4, *)`) to the same approved path, and every other unknown state still fails closed to `.notAuthorized` - the pre-existing fail-closed rule is preserved, not weakened.
- `FilterSyncController.swift:542` unnecessary `try?` on a non-throwing `flatMap`: replaced with `if let stagingFile { try? ... }`. Same behavior.
- `ApplePrefilter.swift:121` unused `skew`/`damp`: removed from `encodeLabel`'s declaration (the used copies in `adapt()` at line 166 are untouched). Same behavior.
- `MDMEnrollmentClient.swift:24` unused `data`: `let (data, response)` -> `let (_, response)`. Same behavior; the function still always throws `unsignedProfileRefused` in this build.
- NOT "fixed": the benign `appintentsmetadataprocessor` notices ("Metadata extraction skipped. No AppIntents.framework dependency found.") - toolchain noise, not a code defect.

### Pre-push gates - actually run, in this order, BEFORE the push

1. `python3 tools/validate-ios-project.py` - all checks passed, exit 0 (14 informational placeholders, expected until a real team ID exists).
2. `bash tools/run-swift-portable-tests.sh` on the official `swift-6.0.3-RELEASE-ubuntu22.04` toolchain (download.swift.org, 784207421 bytes, freshly downloaded this round). FIRST run: 135/136 - the source-level regression test `AppShieldReachabilityTests.testSectionCallsRealShieldFlow` failed because it textually required `@unknown default`, which the corrected exhaustiveness fix cannot keep (a known SDK case needs a real `default`). The test (`tools/swift-portable-tests.swift`) was updated to assert the SAME rule against the new structure: the switch must have a `default` branch whose tail still maps to `state = .notAuthorized`, and the new `.approvedWithDataAccess` handling must be present. SECOND run (the recorded result): **136 tests, 0 failures, exit 0**. No test was deleted or weakened; the fail-closed assertion still exists and still guards the same behavior. Honest limit, unchanged: the harness compiles only the portable Foundation sources; NetworkExtension/ExtensionKit and SwiftUI files are NOT compiled by it - the macOS run verifies those. (Note: `AppBlockingView.swift` is app-target SwiftUI code, not in the portable compile set; the harness test reads it as source text only.)

### Verified in the run-5 raw log

- ZERO `error:` lines. `** BUILD SUCCEEDED **`.
- Real compile/link for all five targets (app + four extensions).
- Zero Swift warnings and zero packaging warnings. Remaining output is only the benign AppIntents metadata notices and runner-infra noise (git hint, Node.js 20 deprecation of the checkout action).
- Run 5 built exactly head `50573f04511ffcc614a7f1afe965e5553ea18c1d`.

### What is ready for signing and real-device testing - and what is NOT proven

Ready (compile/package level only):

- The app and all four extensions compile and link cleanly for iPhoneOS 26.5 arm64 with zero warnings.
- The bundle layout now matches Apple's requirement for every extension type: three NetworkExtension appexes in `PlugIns`, the ExtensionKit URL Filter appex in `Extensions`.

Still required before any device run (unchanged blockers, NOT done in this stage):

- A real Apple Developer team ID and signing: `TEAMIDPLACEHOLDER` remains in all four entitlements files, and `kosherguard.example.com` / `group.com.kosherguard.shared` placeholders remain (the validator's 14 informational notes). Code signing is OFF in this workflow by design.
- Apple's distribution approval for the Family Controls entitlement is required before App Store / distribution use of the app-blocking feature (per Apple's Family Controls documentation).
- Platform requirements from TN3134 still gate real behavior: URL filter provider needs iOS 26.0+; content filter on iOS requires supervised devices (or Screen Time child authorization); DNS proxy provider requires supervised/managed devices for the relevant modes.
- Entitlement, provisioning and installation validation cannot happen in an unsigned CI compile; neither can actual filtering behavior.

### Limits, stated plainly

- This remains an UNSIGNED compile-and-link success on a CI runner. It proves source correctness and correct bundle layout only - not app launch, not extension loading, not filtering, not MDM, not device behavior.
- Nothing signed, deployed or purchased; no Apple account or device changes; `main`, `stage-10-ios-runtime-integration`, `stage-11-apple-build-signing` and the superseded `stage-12-free-ci-unsigned-build` untouched.

### Changed files in this round (commit `50573f04511ffcc614a7f1afe965e5553ea18c1d`)

- `ios/KosherGuard.xcodeproj/project.pbxproj` - packaging fix + URLFilterExtension deployment target 26.0
- `ios/Sources/KosherGuard/AppBlockingView.swift` - `.approvedWithDataAccess` exhaustiveness fix
- `ios/Sources/URLFilter/FilterSyncController.swift` - unnecessary `try?` removed
- `ios/Sources/URLFilter/ApplePrefilter.swift` - unused constants removed
- `ios/Sources/URLFilter/MDMEnrollmentClient.swift` - unused binding removed
- `tools/swift-portable-tests.swift` - regression assertion updated to the corrected fail-closed structure
