# Stage 11 review: Apple build, signing and real-device validation preparation

Date: 2026-11-17. Branch: `stage-11-apple-build-signing`, created from
the published Stage 10 tip `791f0ef647dabba449b1e5bee32fc75fec5ce2b5`.
Base and `main` (`5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`) and the
Stage 10 branch are unchanged (verified with `git ls-remote` after
push).

SCOPE HONESTY: this stage is PREPARATION. No iOS target has been
compiled with Xcode, nothing was signed, nothing ran on any Apple
device, and no Apple account, APNs or Apple Business configuration was
touched or assumed. Working iPhone filtering or app blocking is NOT
established. No purchase was made and no credential was requested.

## 1. Objective results

### 1. Exact macOS and Xcode requirements (DONE, source-verified)

Full matrix in docs/setup/APPLE_BUILD_REQUIREMENTS.md section 1.
Headline: minimum Xcode 26.0 (iOS 26 SDK, for the URL Filter code) on
macOS Sequoia 15.6+; recommended Xcode 27.2 on macOS Tahoe 26.6+;
App Store uploads will require the iOS 27 SDK (Xcode 27) from April
2027 (Apple Developer News 2026-09-09). Project settings need no
change; iOS 26-only symbols are availability-guarded (verified by
inspection).

### 2. Mac access check (DONE - verified negative, with a working free alternative)

- The development sandbox is Linux-only (verified: `uname -a`,
  no xcodebuild/xcrun/sw_vers). **The agent has no Mac.**
- No user-owned Mac is confirmed (a Windows PC is confirmed in project
  memory).
- **Found working route**: GitHub-hosted `macos-26` runners carry
  Xcode 26.6 (default) through 26.0.1 (iOS 26 SDK) and are **free for
  public repositories** (GitHub billing docs, verified today). The
  workflow is written and committed at `ci/ios-compile-check.yml`.
- LIMITATION, honestly stated: the GitHub token authorized for agent
  pushes lacks the `workflow` scope; GitHub rejected the push of
  `.github/workflows/ios-compile-check.yml` with exactly that error.
  Per the standing rule, no new credential was requested. The workflow
  therefore lives at `ci/ios-compile-check.yml` and becomes active
  after ONE manual user step (copy it to `.github/workflows/` in the
  GitHub web UI - step 0.3 in docs/setup/APPLE_ACCOUNT_SETUP_STEPS.md).
  **Until that step, no Xcode compile has run and none is claimed.**
- Paid persistent-Mac options priced in APPLE_BUILD_REQUIREMENTS.md
  section 2b (MacStadium from $109/month; Mac mini purchase from $599;
  AWS EC2 Mac ~$1/hr class with 24h minimum; MacinCloud ~$30+/month
  per 2026 comparison listings - verify before buying).

### 3. Every required entitlement, certificate and provisioning profile (DONE)

Complete inventory in docs/reviews/APPLE_CAPABILITY_MATRIX.md: 7
entitlement rows across the 5 targets (incl. the three managed Network
Extension values, Family Controls, App Groups, keychain access group),
the PIR onboarding registration and DNS TXT requirement, the
CloudKit `.url.filtering` registration (tier unverified - flagged),
5 App IDs, development + distribution profiles, Apple
Development/Distribution certificates, the MDM Vendor CSR signing
certificate and the MDM APNs push certificate with its yearly-renewal/
same-topic constraint.

### 4. Paid membership vs Apple approval (DONE)

Same document, section 4: the only money Apple charges is the **$99/yr
Developer Program** (plus hardware); every managed capability
(content-filter-provider, dns-proxy, url-filter-provider, Family
Controls distribution, URL Filter PIR onboarding, MDM Vendor CSR) is
**$0 but approval-gated**, each with its request route cited. Apple
Business is free. A free Apple account covers Xcode + unsigned compile
+ basic dev signing only - none of the managed entitlements.

### 5. Project prepared for an actual Xcode build (DONE, within sandbox limits)

- `ios/KosherGuard.xcodeproj/xcshareddata/xcschemes/KosherGuard.xcscheme`:
  shared scheme so `xcodebuild -scheme KosherGuard` builds the app and,
  via target dependencies, all 4 extensions. Hand-authored like the
  rest of the project - its first use is a verification step.
- `tools/validate-ios-project.py`: static pre-flight validator (all
  pbxproj file references resolve, build-phase/fileRef integrity, every
  Swift file on disk is in a target, plists/entitlements parse, exactly
  one extension-point declaration per extension Info.plist, the URL
  Filter extension's EX identifier matches Apple's sample value, app
  group consistency, bundle-ID nesting, placeholder sweep).
  **RUN: PASS** (0 failures; 14 informational placeholder notes, all
  expected until a real team ID exists; `--strict-placeholders`
  enforces the sweep at signing time).
- `tools/apply-apple-team-id.sh`: one command applies the real Team
  ID / bundle prefix / app group / PIR hosts across the pbxproj, all
  plists/entitlements and the 3 Swift files that mirror them; dry-run
  by default, `--write` applies and re-runs the validator. DRY RUN
  TESTED against a dummy team ID with PIR hosts: 24 placeholder
  lines across 10 files would change, no unintended matches.
- `ci/ios-compile-check.yml`: the unsigned-compile workflow (see 2).
- Not done (impossible here): the compile itself, signing, any
  simulator/device run.

### 6. Remote app blocking on personal vs supervised iPhones (DONE)

docs/reviews/REMOTE_APP_BLOCKING_INVESTIGATION.md. Verified against
Apple's current device-management documentation and Apple Support
(2026-09-17): admin-controlled remote app blocking exists ONLY on
supervised devices - `blockedAppBundleIDs`/`allowListedAppBundleIDs`
(iOS 15-26, supervised, deprecated in 27) and the DDM
`app.settings` DeniedApps/AllowedApps (iOS 27+, **requires
supervision + Automated Device Enrollment**). On personal iPhones the
only path is the on-device consented Screen Time model implemented in
Stage 10: the device user selects the apps (opaque tokens), the server
can only activate/pause that set, and local revocation always wins.
User Enrollment (BYOD) cannot touch personal apps. Product
consequences are listed in the document section 4.

### 7. Launch blocking vs internet blocking (DONE)

Same document, section 1: a mechanism-by-mechanism table separating
launch blocking (restrictions profile / DDM app settings / Screen Time
shields - the app never runs) from internet blocking (NEFilter
verdicts, NEURLFilterManager, DNS proxy, DNS edge - the app runs but
its traffic fails), with each row's remote-admin capability,
supervision requirement and revocation behavior. The Stage 10 code
paths are mapped to the correct mechanism for each.

### 8. Real-device test plan (DONE)

docs/reviews/REAL_DEVICE_TEST_PLAN.md: Phases 0-7 covering compile
gates, signed build, website filtering (filter providers, URL Filter,
DNS proxy), app blocking on both device classes (incl. the launch vs
network distinction test), policy updates (propagation, monotonicity,
identity binding), removal protection, and failure handling (offline
expiry, corrupt store, first-lock persistence, sign-out teardown,
server down, 401 handling). Each test has explicit pass criteria and
evidence requirements; no device claim is allowed from compile or
simulator evidence.

## 2. Verification performed in this stage

| Check | Result |
| --- | --- |
| `python3 tools/validate-ios-project.py` on the final tree | PASS (run 2026-11-17) |
| `tools/apply-apple-team-id.sh` dry run | PASS (24 placeholder lines, 10 files, reviewed) |
| Push of branch to GitHub with the authorized vault token | PASS after relocating the workflow file; first push attempt rejected by GitHub on `workflow` scope (recorded above) |
| Remote refs after push | main 5f75d213 unchanged, stage-10 791f0ef unchanged, stage-11 = HEAD |
| Swift/server test suites | NOT RERUN - zero changes to Swift, Python or test files in this stage (docs + project metadata + new tooling only); the Stage 10 results (Swift 136, control-plane 518, mdm 136, url-filter-server 50) stand on the unchanged trees |
| Xcode compile | NOT RUN - no Mac access (see 1.2); prepared and gated on the user's one-step CI enable |
| Sources | Apple Xcode system-requirements page; Apple Developer News k1mtkt1k; TN3134; Apple Family Controls entitlement doc; Apple MDM vendor CSR help; Apple device-management applicationaccess payload docs; Apple Support depd65c456fa (app settings configuration, requires supervision); actions/runner-images macos-26 readme; GitHub Actions billing docs + 2026 pricing-change post; micromdm.io certificates guide; macstadium.com/pricing. All fetched 2026-11-17 |

## 3. Changed files (this stage)

- `ios/KosherGuard.xcodeproj/xcshareddata/xcschemes/KosherGuard.xcscheme` (new)
- `ci/ios-compile-check.yml` (new; enable manually - see 1.2)
- `tools/validate-ios-project.py` (new, executable)
- `tools/apply-apple-team-id.sh` (new, executable)
- `docs/setup/APPLE_BUILD_REQUIREMENTS.md` (new)
- `docs/setup/APPLE_ACCOUNT_SETUP_STEPS.md` (new - the owner's exact steps and costs)
- `docs/setup/IOS_BUILD.md` (updated: section 2 points at the Stage 11 documents)
- `docs/reviews/APPLE_CAPABILITY_MATRIX.md` (new)
- `docs/reviews/REMOTE_APP_BLOCKING_INVESTIGATION.md` (new)
- `docs/reviews/REAL_DEVICE_TEST_PLAN.md` (new)
- `docs/reviews/STAGE_11_APPLE_BUILD_SIGNING_PREP_REVIEW.md` (this report)

## 4. What still blocks working iPhone filtering (unchanged from Stage 10, now with owners and costs)

1. A real Xcode compile (owner: anyone - free via CI after step 0.3).
2. $99/yr Apple Developer Program membership (owner: Yossi; payment).
3. Apple approvals: NE managed values, Family Controls distribution,
   URL Filter PIR onboarding, MDM Vendor CSR (owner: Yossi submits;
   Apple decides).
4. A Mac for signed builds + Apple Configurator (owner: Yossi; buy/rent/borrow).
5. A spare iPhone, supervision, and the device test phases (owner:
   Yossi approval; may involve erasing the spare device).
