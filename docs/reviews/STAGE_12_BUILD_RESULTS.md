# Stage 12 - First Real Xcode Build: ACTUAL Results

- Repository: https://github.com/yossigo88-cyber/kosherguard-platform (public)
- Branch: `stage-12-free-ios-build` at `5c737e9c3e891de089affb62193f46f2713a9f37`
- Run: GitHub Actions run 44207115197 ("iOS unsigned build"), 2026-11-18T00:21:14Z, free standard `macos-26` runner, $0 compute for public repos, no artifacts uploaded
- Untouched: `main` `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`, `stage-10` `791f0ef`, `stage-11` `62c0ccc`, superseded `stage-12-free-ci-unsigned-build` `b30a6bb`
- Status: BUILD RUN COMPLETED - REAL RESULT. The unsigned compile FAILED with 6 genuine Swift compiler errors in one file. Nothing was signed, deployed or purchased. No compilation success is claimed.

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
