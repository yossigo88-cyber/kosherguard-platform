# Stage 12 - First Real Xcode Build: ACTUAL Results

- Repository: https://github.com/yossigo88-cyber/kosherguard-platform (public)
- Branch: `stage-12-free-ios-build` at `5c737e9c3e891de089affb62193f46f2713a9f37`
- Run: GitHub Actions run 44207115197 ("iOS unsigned build"), 2026-11-18T00:21:14Z, free standard `macos-26` runner, $0 compute for public repos, no artifacts uploaded
- Untouched: `main` `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`, `stage-10` `791f0ef`, `stage-11` `62c0ccc`, superseded `stage-12-free-ci-unsigned-build` `b30a6bb`
- Status: THREE REAL RUNS COMPLETED. Run 1 failed with 6 compile errors (fixed, user-approved). Run 2 CONFIRMED those 6 are gone and surfaced 1 new compile error in a different file. Run 3 CONFIRMS that error is fixed (its target now links) and surfaced 2 pre-existing errors further along in the app target. Nothing was signed, deployed or purchased. No compilation success of the app is claimed.

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
