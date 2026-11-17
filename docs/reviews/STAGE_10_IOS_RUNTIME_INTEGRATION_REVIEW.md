# Stage 10 iOS Runtime Integration - Implementation Review

**Status: code complete for review, UNPUBLISHED. Nothing is deployed,
nothing is merged, `main` is untouched, and no Apple account,
certificate, entitlement or device was touched.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-10-ios-runtime-integration`
**Base (published, verified):** `e99a1a4c8a656c90ff6c34faeecbbe4473205ad0`
**HEAD at this report:** `acfa56ccae8b066db74e94f170b5b2210d9200c7`
(8 commits ahead of base; 27 files changed, +2425/-135 at code HEAD
`ad64101f364cac09f7055811c31139a0aaf7d1d8`; the 8th commit is this
report itself)

Full commit list (oldest first):

1. `54e46569fb2b8cd1a364c47a856ef63303b75477` url-filter-server: Apple-format prefilter construction
2. `cfd31481fdcda71e251a5b3a17b47bb133608e7f` ios: portable runtime components for URL Filter and DNS proxy paths
3. `ce9ffeda1041d12f71a6aeff8d268804997d9d78` ios: URL Filter control provider and DNS proxy extension (Apple-only, uncompiled)
4. `0b80e03854dcdc4b1876b32d70b6814cc2bde081` tests: portable coverage for stage-10 runtime components
5. `89a898bde57370ab3b45a9a0971c6bffc3f333a6` control-plane: assert mint response carries expires_in_seconds
6. `f070ecc1afdca8232d5508c3f531a70a0068fa20` ios: application-blocking policy model and Screen Time shield controller
7. `ad64101f364cac09f7055811c31139a0aaf7d1d8` ios: pull-based app-policy fetch wired into the app lifecycle
8. `acfa56ccae8b066db74e94f170b5b2210d9200c7` docs: this report
**Report date:** 2026-11-17

Every "tested" claim below names the suite, the count and how to
reproduce it. Every claim about Apple-platform behavior is marked
UNCOMPILED/UNVERIFIED: no Apple SDK, device, signing identity or
entitlement exists in this environment, and none was used.

---

## 1. Executive summary

Stage 10 connects the iOS runtime to the control plane along four
paths, with the fail-closed posture preserved everywhere:

1. **Apple-format URL Filter prefilter.** The dataset server now
   builds the prefilter with Apple's documented construction
   (FNV-1a 32-bit + MurmurHash3-32 double hashing over Punycoded
   entries), replacing the SHA-256 Bloom construction. Python
   (builder) and Swift (on-device verifier) are pinned to
   byte-identical output by generated cross-language vectors, and
   the Swift Murmur3 is additionally verified against the reference
   `mmh3` package, so the vectors test agreement with an external
   ground truth, not merely self-consistency.
2. **URL Filter runtime path (iOS 26+).** A real
   `NEURLFilterManager` enable/disable wired to the managed
   configuration lifecycle (shouldFailClosed = true), an
   `NEURLFilterControlProvider` that serves the identity-bound,
   hash-verified prefilter, and a portable loader whose failure
   matrix is XCTested. Apple-only adapters are UNCOMPILED.
3. **Authenticated DoH proxy path.** A `NEDNSProxyProvider`
   (UNCOMPILED) that resolves DNS over the approved per-device
   authenticated DoH route: scoped `doh` tokens minted through the
   control plane with a memory-only cache, 75%-lifetime proactive
   refresh, single-flight minting, and session cookie read at mint
   time. Every failure answers SERVFAIL; there is no plaintext or
   system-resolver fallback.
4. **Application blocking.** Server side (policy storage, MDM
   `com.apple.applicationaccess` apply, install/remove/list
   commands, dashboard) already existed with 19 passing tests. This
   stage adds the iOS consumer: a portable policy model + client +
   identity-bound mirror, and a FamilyControls/ManagedSettings
   shield controller for the personally-owned route (UNCOMPILED),
   with the token-vs-bundle-ID capability split documented
   honestly (section 5).

Also in this stage: the control-plane mint response now carries
`expires_in_seconds` so native clients schedule renewal instead of
discovering expiry as a mid-use 401.

**Test totals at HEAD (all reproduced locally, commands in
section 4): url-filter-server 50 passed; control-plane 500 passed;
portable Swift 125 passed.**

## 2. Baseline test-evidence correction (environment vs code)

An earlier report attributed 3 control-plane test failures to the
published base commit. That was wrong: those failures were caused by
a missing `psycopg` package in the reporting environment, not by the
code. With dependencies installed and the suite run from the repo
root, the base commit's full control-plane suite is **499 passed,
0 failed** (the 500th test at HEAD is this stage's new
`expires_in_seconds` assertion). The published baseline has no known
test failures; treat any earlier claim of base-commit regressions as
an environment artifact, not a code regression.

## 3. What changed, and how real each piece is

| Area | Files | Status |
| --- | --- | --- |
| Apple prefilter builder | `url-filter-server/app/apple_prefilter.py` (new), `dataset.py`, `server.py`, deleted `bloom.py` | TESTED (50 passed) |
| Cross-language vectors | `tools/gen-apple-prefilter-vectors.py`, `tools/apple-prefilter-vectors.json` | TESTED from both languages |
| iOS portable runtime | `ios/Sources/URLFilter/ApplePrefilter.swift`, `DohTokenProvider.swift`, `DNSProxyRelay.swift`, `URLFilterPrefilterSource.swift`, `AppBlockingPolicy.swift`; updates to `PrefilterUpdater`, `AppConfiguration`, `CredentialIssuanceClient`, `URLFilterConfiguration` | COMPILED + XCTESTED on Linux Swift 6.0.3 (125 passed) |
| iOS Apple-only adapters | `ios/Sources/FilterExtension/URLFilterControlProvider.swift`, `ios/Sources/DNSProxyExtension/DNSProxyProvider.swift`, `ios/Sources/KosherGuard/AppShieldController.swift`, app wiring in `KosherGuardApp.swift` | UNCOMPILED - no Apple SDK. API names verified against Apple's documentation pages (section 6); device behavior unverified |
| Xcode project | `project.pbxproj`, `DNSProxyExtension-Info.plist`, `DNSProxyExtension.entitlements` | Statically guarded (membership closure + entitlement consistency tests); never opened in Xcode |
| Control plane | `app/main.py` (`expires_in_seconds`), `tests/test_filter_logs.py` | TESTED (500 passed) |

Nothing in `deploy/`, DNS infrastructure, `main`, or the published
baseline was modified.

## 4. Test evidence and reproduction

Environment: Linux, Swift 6.0.3 toolchain, Python 3 with the repo's
test dependencies (including `psycopg[binary]`, `pgserver`, `mmh3`).

- URL filter server: `cd url-filter-server && python3 -m pytest tests -q`
  -> **50 passed**
- Control plane (run from repo root; `test_ade_web` imports `mdm`):
  `python3 -m pytest control-plane/tests -q` -> **500 passed**
- Portable iOS logic (real SPM build, pinned swift-crypto, real
  XCTest - no API shims):
  `KG_REPO_ROOT=$PWD bash tools/run-swift-portable-tests.sh`
  -> **125 passed**, including:
  - Apple prefilter cross-language vectors: every FNV-1a, Murmur3
    (5 seeds), Punycode, per-item hash position, bit-array bytes and
    SHA-256 tag recomputed in Swift and required equal to the
    Python-generated vectors file; present/absent membership checked.
  - `DohTokenProvider`: cache reuse, renewal past 75% of lifetime,
    invalidation, single-flight under concurrency, no-session and
    401 fail closed.
  - `DNSProxyRelay`: rejects responses/truncated/oversized/question-
    less datagrams; SERVFAIL mirrors the transaction ID; a resolver
    answer under a foreign transaction ID is never relayed; upstream
    failure is SERVFAIL, never silence or fallback.
  - `URLFilterPrefilterSource`: valid artifact loads; unchanged tag
    means no update; missing file, foreign identity, wrong format,
    corrupt hash, tampered bytes and empty identity all fail closed.
  - `AppBlockingPolicy`: server contract decode, bundle-ID
    validation matching `mdm/app_management`, identity-bound store,
    client error mapping.
  - Static build guards: every type referenced by a target's member
    sources is defined by a member of the same target (private
    declarations correctly excluded); keychain/app-group entitlement
    literals match the code.

## 5. Application blocking: the honest capability split

Verified against Apple's documentation (sources in section 6):

- **Supervised devices (MDM route):** the bundle-ID allow/block
  policy is enforced by the `com.apple.applicationaccess`
  restrictions profile, queued through the existing MDM command
  lifecycle (`control-plane/app/app_ops.py`). This is the ONLY
  Apple-supported mechanism that blocks apps by bundle ID. Apple
  deprecated these keys in iOS/iPadOS 27 in favor of the App
  settings declarative configuration (supervision + Automated
  Device Enrollment required); the builder and its caveats are in
  `mdm/app_management.py`. On-device behavior of both mechanisms
  remains BUILT-UNVERIFIED until device testing.
- **Personally-owned devices (Screen Time route):**
  `FamilyControls` + `ManagedSettings` shield apps and categories
  identified by OPAQUE, DEVICE-LOCAL tokens
  (`ApplicationToken` / `ActivityCategoryToken`). No public API maps
  a bundle ID to a token, and tokens do not transfer between
  devices. Therefore remote "block app X by bundle ID" is
  IMPOSSIBLE on personally-owned devices; the route that exists is
  an on-device `FamilyActivityPicker` selection applied as a shield
  (`AppShieldController.swift`, UNCOMPILED, requires the
  `com.apple.developer.family-controls` entitlement). The control
  plane's policy is mirrored to the device
  (`AppBlockingPolicyClient`, pull-based) for dashboard visibility
  and consistency, not for token mapping.
- **Internet denial is not launch blocking.** DNS/filter rules stop
  an app's traffic; the app still launches offline. The two
  mechanisms are complementary and configured separately.

## 6. Apple sources used for API-surface verification

- `NEURLFilterControlProvider.fetchPrefilter(existingPrefilterTag:)`
  and `NEURLFilterPrefilter` documentation (prefilter construction:
  FNV-1a 32 + MurmurHash3-32 double hashing, Punycode, SHA-256 tag
  suggestion) - apple-docs mirror of the NetworkExtension
  documentation, read 2026-11-17.
- `developer.apple.com/documentation/managedsettings/shieldsettings`
  and `.../shieldsettings/activitycategorypolicy` (`.none`,
  `.all(except:)`, `.specific(_:)`; applications/webDomains token
  sets), read 2026-11-17.
- `developer.apple.com/documentation/familycontrols/
  authorizationcenter` (`AuthorizationCenter.shared`,
  `requestAuthorization(for:)`), read 2026-11-17.
- `com.apple.dnsSettings.managed` profile YAML (supervised:false,
  manual install allowed, deprecated iOS 27) -
  apple/device-management release branch.
- URL Filter overview (`url-filters.md`) and WWDC25 session 234
  (supervised-only system-wide filter; MDM URL Filter configuration
  requires supervision; CloudKit Identity & Trust registration).
- Prior grounded research in this repo:
  `docs/reviews/SUPERVISED_MANUAL_ENROLLMENT_REVIEW.md`,
  `docs/design/DOH_IOS_TRANSPORT.md`,
  `docs/reviews/IOS_FILTERING_IMPLEMENTATION_REVIEW.md`.

## 7. Apple-dependent work that remains (requirements, gates)

None of this was done or attempted; each item needs the listed
prerequisite and explicit approval where it touches the Apple
account or costs money.

| Task | Requires | Blocks |
| --- | --- | --- |
| Compile the iOS targets | A Mac with current Xcode | Any claim that the app builds |
| Run on a real device | Spare iPhone; supervision for the URL Filter / dns-proxy / MDM routes | Any claim of working on-device filtering |
| `dns-proxy` entitlement | Apple's managed-entitlement approval for the App ID | DNS proxy on any device |
| `family-controls` entitlement | App ID capability (account holder action) | Screen Time shields |
| URL Filter enablement | CloudKit Identity & Trust registration (`<bundle-id>.url.filtering`); tier unverified | System URL Filter serving the prefilter |
| MDM push certificate chain | Decision on customer-owned vs KosherGuard-owned vendor CSR (user's open question; the user has an active Apple Business org, no paid Developer Program, and declines paying for one) | Production MDM command delivery |
| Device testing phase | All of the above | Removing every UNCOMPILED/BUILT-UNVERIFIED marking |

## 8. Security posture (unchanged invariants)

- Fail closed everywhere: the URL Filter is enabled with
  `shouldFailClosed = true`; the prefilter source yields nil (->
  the control provider throws) on any invalid artifact; the DNS
  proxy refuses to start unconfigured and answers SERVFAIL on any
  failure; no plaintext/system-resolver fallback was added.
- Credentials: scoped `doh` tokens are memory-only on device; the
  session cookie is read at mint time so a sign-out can never be
  bypassed by a captured cookie; no long-lived bearer appears in any
  DoH URL (the approved authenticated per-device design).
- Privacy corpus: the licensed category expansions still ship only
  as the opaque prefilter; the rules export still carries explicit
  guardian domains only. No bulk export of category content was
  added anywhere (no guardian-facing corpus dump).
- Identity binding: prefilter artifacts and the app-policy mirror
  are bound to the endpoint fingerprint; a foreign server's data is
  never served as current policy.
- Publication binding: the device rules export remains sourced only
  from the last published immutable generation.
- No mocks, no as-if build success, no host bootstrap bypass, no
  default-allow weakening.

## 9. Known limitations

- All `ios/` Apple-only files are UNCOMPILED; API names are
  verified against documentation, not a compiler. First Xcode build
  will likely surface mechanical adjustments.
- The personally-owned app-blocking route cannot enforce a remote
  bundle-ID list (section 5). Dashboard "applied" state for that
  route would overstate reality and is deliberately not claimed.
- `expires_in_seconds` is advisory; token revocation distribution
  to edge verifiers remains the existing open work (unchanged by
  this stage).
- The iOS 27 App settings declarative configuration is not
  implemented; the legacy applicationaccess payload is the fallback
  pending device testing.

## 10. For the independent reviewer

- Verify the cross-language vectors are not self-consistent-but-
  wrong: the Murmur3 implementation is pinned against the reference
  `mmh3` package; the known-answer assertions are in
  `url-filter-server/tests/test_url_filter.py`
  (published FNV-1a and MurmurHash3 x86-32 reference values plus
  values cross-checked against `mmh3`); the FNV-1a constants/algorithm are the published
  standard; the seed (`0x4B470001`) and format identifier
  (`apple-fnv1a-murmur3-doublehash-v1`) are shared constants in
  `url-filter-server/app/apple_prefilter.py` and
  `ios/Sources/URLFilter/ApplePrefilter.swift`.
- Check the fail-closed matrix in section 8 against the code paths
  named there.
- Check that no Apple-only file is presented anywhere in the repo
  as compiled or device-verified.
- Full diff: `git diff e99a1a4c8a656c90ff6c34faeecbbe4473205ad0..
  acfa56ccae8b066db74e94f170b5b2210d9200c7` (8 commits).
