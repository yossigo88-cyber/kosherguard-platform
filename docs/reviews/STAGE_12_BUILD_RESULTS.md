# Stage 12 - First Real Xcode Build: ACTUAL Results

- Repository: https://github.com/yossigo88-cyber/kosherguard-platform (public)
- Branch: `stage-12-free-ios-build` at `5c737e9c3e891de089affb62193f46f2713a9f37`
- Run: GitHub Actions run 44207115197 ("iOS unsigned build"), 2026-11-18T00:21:14Z, free standard `macos-26` runner, $0 compute for public repos, no artifacts uploaded
- Untouched: `main` `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`, `stage-10` `791f0ef`, `stage-11` `62c0ccc`, superseded `stage-12-free-ci-unsigned-build` `b30a6bb`
- Status: TWO REAL RUNS COMPLETED. Run 1 failed with 6 compile errors (fixed, user-approved). Run 2 (verification) CONFIRMS those 6 are gone and surfaced 1 new compile error in a different file. Nothing was signed, deployed or purchased. No compilation success is claimed.

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
- Checks and tests, stated exactly: the only pre-push check run was `tools/validate-ios-project.py` (all checks passed). No Swift tests were run for this fix; the real Xcode run is what exercised the Darwin-specific change and surfaced the next issue. Python suites were run after the push for general completeness only and are unrelated to this change: `mdm/tests` 136 passed, `filtering-engine/tests` 337 passed; `url-filter-server` tests could not collect (missing fastapi in this sandbox), `control-plane` needs pgserver.

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
