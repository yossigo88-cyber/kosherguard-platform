# Stage 13 review: Apple signing-readiness audit

Date: 2026-11-17. Branch: `stage-12-free-ios-build` (audit of head
`fde63a04aa803612251336d4c40357c663575e29`; the code it documents is
build-verified head `50573f04511ffcc614a7f1afe965e5553ea18c1d`).

SCOPE HONESTY: this stage is an AUDIT. Nothing was signed, no Apple
account was created or modified, no entitlement was requested, nothing
was purchased, no device was enrolled, supervised, erased or modified,
and no build was run (audit-only; the existing workflow was not
triggered - this commit is marked `[skip ci]`). The only verified
build evidence remains the free unsigned CI build (GitHub Actions run
44216829456, Xcode 26.6 / iPhoneOS 26.5 SDK, BUILD SUCCEEDED, app +
all four extensions, zero code/packaging warnings). Nothing in this
report claims working filtering on any device.

Every external claim below was re-verified against the cited Apple
source today (2026-11-17). Items that could not be confirmed from an
Apple source are marked UNVERIFIED rather than asserted. Stage 11
documents (docs/reviews/APPLE_CAPABILITY_MATRIX.md,
docs/setup/APPLE_ACCOUNT_SETUP_STEPS.md) were used as leads only;
this audit re-grounds their claims and corrects/extends them where
noted.

## 1. Every app and extension bundle ID

From `ios/KosherGuard.xcodeproj/project.pbxproj`
(PRODUCT_BUNDLE_IDENTIFIER per target) and the `Configuration/*-Info.plist`
extension-point declarations:

| Target | Bundle ID | Type / extension point | Min deployment target | Embed location |
| --- | --- | --- | --- | --- |
| KosherGuard (app) | `com.kosherguard.app` | iOS app (APPL) | iOS 17.0 | - |
| KosherGuardFilter | `com.kosherguard.app.FilterExtension` | `com.apple.networkextension.filter-data` (NEFilterDataProvider) | iOS 17.0 | PlugIns/ |
| KosherGuardFilterControl | `com.kosherguard.app.FilterControlExtension` | `com.apple.networkextension.filter-control` (NEFilterControlProvider) | iOS 17.0 | PlugIns/ |
| KosherGuardDNSProxy | `com.kosherguard.app.DNSProxyExtension` | `com.apple.networkextension.dns-proxy` (NEDNSProxyProvider) | iOS 17.0 | PlugIns/ |
| KosherGuardURLFilter | `com.kosherguard.app.URLFilterExtension` | ExtensionKit `com.apple.networkextension.url-filter-control` (NEURLFilterControlProvider) | iOS 26.0 | Extensions/ |

Verified in the raw run-5 build log (run 44216829456): the three
NetworkExtension appexes embed under PlugIns/ and the ExtensionKit
URL Filter appex under Extensions/, byte-matching Apple's official
"Filtering traffic by URL" sample project layout.

Status: none of the five bundle IDs is registered to any Apple
Developer team. The IDs are usable as-is once a team registers them;
they are not placeholders in syntax but are unregistered choices.

## 2. Required Apple capabilities and entitlements

Exactly as declared in `ios/Configuration/*.entitlements` (no target
carries any other entitlement):

| Entitlement | Targets | Purpose in this project |
| --- | --- | --- |
| `com.apple.developer.networking.networkextension` = `content-filter-provider` | app, FilterExtension, FilterControlExtension | NEFilterManager + filter data/control providers |
| `com.apple.developer.networking.networkextension` = `url-filter-provider` | app, URLFilterExtension | NEURLFilterManager + URL filter control provider (iOS 26+) |
| `com.apple.developer.networking.networkextension` = `dns-proxy` | DNSProxyExtension | NEDNSProxyProvider |
| `com.apple.developer.family-controls` | app | Screen Time APIs: AuthorizationCenter, FamilyActivityPicker, ManagedSettingsStore (app shielding UI) |
| `com.apple.security.application-groups` = `group.com.kosherguard.shared` | all 5 targets | Shared container: rule store, prefilter snapshot, policy mirror |
| `keychain-access-groups` = `TEAMIDPLACEHOLDER.com.kosherguard.shared` | app, FilterExtension, FilterControlExtension, DNSProxyExtension | Shared keychain for the session credential bundle. URLFilterExtension intentionally has no keychain group (it never reads credentials) |

The entitlement key is an array-of-strings per Apple's Network
Extensions Entitlement documentation
(https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension,
fetched 2026-11-17); all four provider kinds in use are documented
values of that one key.

No Push Notifications (`aps-environment`), no iCloud/CloudKit
container entitlement, and no Sign in with Apple entitlement are
currently declared. If server-triggered APNs pushes to the app (not
MDM) are added later, `aps-environment` would be a new row here.

## 3. Which entitlements require Apple's approval

Grounding for the approval mechanism: Apple states "Managed
capabilities require approval from Apple to use"
(https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities,
fetched 2026-11-17).

| Entitlement / item | Apple approval required? | Source |
| --- | --- | --- |
| `content-filter-provider`, `dns-proxy` (managed Network Extension values) | **Yes** - approval-gated managed values; must also be present in the provisioning profile in every configuration (there is no development waiver). Request route: capability request in Certificates, Identifiers & Profiles once the $99 program account exists. | Managed-capabilities doc (above); TN3134 deployment restrictions (below); request route per Stage 10/11 portal research - the exact current form name is UNVERIFIED until the portal is reachable with a paid account |
| `url-filter-provider` | **Yes for distribution; reported approval-gated.** The entitlement itself is added in Xcode (WWDC25 session 234, "Add the new Network Extension url-filter-provider entitlement"). Separately, URL Filter apps require onboarding to Apple's hosted OHTTP relay before distribution-signed use; **development-signed builds are exempt** from the relay requirement. Developer-forum reports (recorded Stage 10) say distribution export is rejected until the capability is granted. Exact portal grant flow: UNVERIFIED from Apple docs today; confirm in Certificates, Identifiers & Profiles at execution time. | WWDC25 session 234 transcript (https://developer.apple.com/videos/play/wwdc2025/234/): "URL filters use an Apple hosted OHTTP relay, which you must apply to configure and use for distribution-signed apps. Development-signed builds are exempt from this requirement." |
| Family Controls (`com.apple.developer.family-controls`) | **Development: no approval** (add the capability in Xcode and request user authorization at runtime). **Distribution: yes** - the Account Holder must request Family Controls (Distribution) before distributing; each Screen Time API app extension needs the same request. Not yet requested. | https://developer.apple.com/documentation/familycontrols/requesting-the-family-controls-entitlement (fetched 2026-11-17); TN3134: "Before submitting your app to the App Store, you must request permission to use the Family Controls entitlement for distribution." |
| App Groups (`group.com.kosherguard.shared`) | No approval; must be **registered** to the App IDs in the portal and the real value kept consistent everywhere | Apple standard capability (no managed gate) |
| Keychain access group | No approval; needs the real Team ID (section 5) | Apple standard capability |
| URL Filter PIR / OHTTP relay onboarding + DNS TXT proof | **Yes** - Apple onboards the PIR service to its hosted relay. Requires: working OHTTP gateway (HTTP/2), PIR service URL + Privacy Pass issuer URL (subdomains, no paths; enforced from iOS/macOS 27.3), a bearer token so Apple can validate the deployment, a test identity (`www.apple.com/url-filter-test` = 1) in the dataset, and a DNS TXT record `apple-url-filter=<app bundle id>` on the service host. Registration happens on the **Identity & Trust page in CloudKit Console**. Not required when the app is installed directly from Xcode (development exemption). | Apple's pir-service-example Onboarding.md (https://github.com/apple/pir-service-example/blob/main/Sources/PIRService/PIRService.docc/Onboarding.md, fetched 2026-11-17); https://developer.apple.com/documentation/networkextension/url-filters.md: "Register your Network Extension URL Filter configuration on the Identity & Trust page in the CloudKit Console." |
| CloudKit Identity & Trust registration (`.url.filtering`) | Registration step required before the URL Filter serves (same Identity & Trust page). **Tier/cost UNVERIFIED**: no Apple page found today states a fee or required account tier for Identity & Trust beyond CloudKit Console access. Flagged, not assumed free. | https://developer.apple.com/icloud/identity/ (fetched 2026-11-17) describes the program without pricing |
| MDM Vendor CSR Signing Certificate | **Yes** - Account Holder of the Apple Developer Program (or Enterprise Program) must contact Apple to request access | https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/ (fetched 2026-11-17) |
| Apple Business (organization account) | **Yes** - Apple verifies the organization; there is a 60-day verification window after sign-up and unverified organizations are deleted. No published fee on Apple's sign-up page. Verification is an approval step and is not guaranteed to pass. | https://support.apple.com/guide/business/sign-up-and-verify-your-organization-axm402206497/web (fetched 2026-11-17) |

## 4. Required provisioning profiles and signing certificates

Current project state: no `DEVELOPMENT_TEAM` and no `CODE_SIGN_STYLE`
in the pbxproj; no certificates or profiles exist anywhere in the
project or this repository. The unsigned CI build passes
`-allowProvisioningUpdates`-free unsigned flags by design.

Needed for a signed real-device build (all five targets):

1. **Apple Development certificate** - signs development builds;
   created via Xcode automatic signing or Certificates, Identifiers &
   Profiles. Included in the $99/yr program.
2. **Development provisioning profiles for all 5 App IDs**, each
   embedding the granted capabilities (Network Extensions values, App
   Groups, Family Controls on the app). Per the managed-capabilities
   doc, once a managed capability is assigned to an App ID, new
   profiles include its entitlements automatically; a profile without
   the managed Network Extension values makes the filter extensions
   unrunnable even in development. Signing the filter extensions
   **will fail until the approvals in section 3 land** - expected, not
   a project defect.
3. **Apple Distribution certificate + distribution profiles** - only
   when TestFlight/App Store/MDM distribution begins; additionally
   gated on the Family Controls (Distribution) grant and URL Filter
   OHTTP onboarding.
4. **MDM Vendor CSR Signing Certificate** (section 3) then the **MDM
   APNs push certificate** from identity.apple.com - required for the
   MDM server to wake managed devices; expires yearly and must be
   renewed with the same Apple Account and same push topic or
   enrolled devices lose MDM contact (renewal constraint recorded in
   docs/setup/APPLE_CREDENTIALS.md; third-party operational note:
   micromdm.io/blog/certificates/). A free interim route for the push
   certificate alone exists via mdmcert.download (organizations only).
5. **TLS certificates for the service hosts** (PIR/OHTTP gateway,
   control plane, MDM URL) - ordinary web PKI; the project already
   uses Caddy/Let's Encrypt on the staging host. The PIR/OHTTP hosts
   must be HTTPS on standard port with subdomain-style URLs
   (Onboarding.md; paths/custom ports accepted only for Xcode
   installs during development).

Free-account boundary (verified):
https://developer.apple.com/support/compare-memberships/ (fetched
2026-11-17): a free Apple Account gives a Personal Team in Xcode -
up to 10 App IDs, up to 3 registered devices, up to 3 apps per
device, all expiring after 7 days. Certificates, Identifiers &
Profiles (the portal where managed capabilities are requested and
explicit App IDs with capabilities live) is a program-member feature.
Therefore **no filter extension can be development-signed on a free
account**: the managed Network Extension values cannot be granted
there. A free account can only reproduce the already-completed
unsigned compile.

## 5. All remaining placeholders (exact inventory)

Verified today by running `tools/validate-ios-project.py` on this
head: PASS with exactly 14 informational placeholder notes. Every
placeholder in the iOS project:

| Placeholder | Where | Blocks |
| --- | --- | --- |
| `TEAMIDPLACEHOLDER` (literal) | `ios/Configuration/App.entitlements`, `FilterExtension.entitlements`, `FilterControlExtension.entitlements`, `DNSProxyExtension.entitlements` (keychain-access-groups); `ios/Sources/URLFilter/KeychainCredentialStore.swift` (sharedAccessGroup constant) | Any signed build that uses the shared keychain; must become the real 10-character Team ID. URLFilterExtension has no keychain group by design |
| App group `group.com.kosherguard.shared` unregistered | same four entitlements files + `URLFilterExtension.entitlements`; `ios/Sources/URLFilter/FilterRuleStore.swift` (`appGroupIdentifier`) | Cross-process rule/credential sharing until the group is registered to the App IDs. The name may be kept once registered |
| PIR hosts `https://pir.kosherguard.example.com` and `https://issuer.kosherguard.example.com` | `ios/Configuration/App-Info.plist` (`NSPIRConfiguration` dictionary) | All URL Filter enablement: NEURLFilterManager requires real PIR server + Privacy Pass issuer URLs; values must be host-only HTTPS subdomains and must match the runtime configuration from iOS/macOS 27.3 (Onboarding.md) |
| Bundle IDs `com.kosherguard.app*` unregistered | pbxproj (5 targets); referenced at `ios/Sources/URLFilter/URLFilterConfiguration.swift` (default `controlProviderBundleIdentifier`) | Signing, portal registration, DNS TXT record `apple-url-filter=com.kosherguard.app`, URLFilterManager `setConfiguration` must reference the real extension bundle ID |
| No `DEVELOPMENT_TEAM` / signing settings | pbxproj (absent, not a literal placeholder) | Any signed build; set by Xcode automatic signing once a program account exists |

Non-placeholder but related: 14 informational validator notes are
exactly the rows above (no other placeholder class exists in the
project; the sweep covers `TEAMIDPLACEHOLDER`, `example.com`,
`group.com.kosherguard.shared` and the bundle-ID prefix).

## 6. Personal vs supervised/managed iPhone features

Verified against TN3134
(https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
Apple's deployment guide "Filter content for Apple devices"
(https://support.apple.com/guide/deployment/filter-content-dep1129ff8d2/web,
published 2026-11-03), and WWDC25 session 234.

| Feature (this project) | Ordinary personal iPhone (unsupervised) | Supervised / managed iPhone | Source |
| --- | --- | --- | --- |
| **URL Filter** (NEURLFilterManager, system-wide full-URL filtering, iOS 26+) | **YES** - "URL filters are supported on both managed and unmanaged devices" (WWDC25 234); Apple's deployment table lists supervision as NOT required | Yes; an MDM-pushed URL Filter configuration profile additionally requires supervision (WWDC25 234: "MDM URL Filter configuration requires device supervision") | WWDC25 234; deployment guide URL filters row; TN3134 URL filter row (iOS 26.0 min) |
| **Content filter** (NEFilterDataProvider/ControlProvider, socket/flow filtering) | **NO system-wide** - "iOS system-wide content filter is supported on supervised devices only" (WWDC25 234; TN3134). Narrow exception: apps using Screen Time APIs may run a content filter on **child devices only** (signed in as an under-18 child member of an iCloud family, Family Controls capability, `.child` authorization approved by a parent) - TN3134 | Yes - supervised devices; per-app filtering on managed devices (iOS 16+) | WWDC25 234; TN3134 content filter row |
| **DNS proxy** (NEDNSProxyProvider) | **NO** - supervised devices only (TN3134). The MDM-delivered DNS Proxy payload itself no longer requires supervision on iOS 15+ but must be installed by a device management service (deployment guide DNS Proxy row) - i.e. a managed device, not a merely personal one | Yes | TN3134 DNS proxy row; deployment guide DNS Proxy row |
| **App blocking / shielding via Family Controls + ManagedSettings** (AuthorizationCenter, FamilyActivityPicker, ManagedSettingsStore) | **YES** - no supervision: `.individual` authorization lets the user authorize on their own device; `.child` authorization lets a parent/guardian approve a child's device in an iCloud family | Yes (also combinable with MDM restrictions) | https://developer.apple.com/documentation/familycontrols/familycontrolsmember and AuthorizationCenter docs (fetched 2026-11-17) |
| **MDM restrictions** (e.g. per-app install/launch restrictions pushed by the MDM server) | **NO** - restriction payloads require supervision | Yes - supervision via Automated Device Enrollment (Apple Business; devices purchased from Apple/participating resellers or added manually) or manual supervision with Apple Configurator for Mac, which **erases the device and all data is lost** | https://support.apple.com/guide/deployment/about-device-supervision-dep1d89f0bff/web (fetched 2026-11-17) |

Practical consequence for KosherGuard: the two features that work on
ordinary, non-supervised family iPhones are exactly the URL Filter
(iOS 26+) and Family Controls app shielding. The legacy content
filter and DNS proxy extensions only function on supervised/managed
devices, so their real-device testing requires the supervision lane
(section 8, lane B).

## 7. Exact Apple account requirements and costs

Money Apple itself charges (verified):

| Item | Cost | Source |
| --- | --- | --- |
| Apple Developer Program membership | **99 USD per membership year** (regional pricing may vary; fee waivers exist for nonprofits/accredited education/government) | https://developer.apple.com/programs/enroll/ (fetched 2026-11-17) |
| Apple Account with two-factor authentication | $0 | enrollment prerequisites (same page) |
| Apple Business organization account | No published fee on Apple's sign-up page; **requires Apple verification of the organization** (60-day window) | https://support.apple.com/guide/business/sign-up-and-verify-your-organization-axm402206497/web |
| Managed capabilities (Network Extension values, Family Controls Distribution), MDM Vendor CSR, URL Filter/OHTTP onboarding, MDM APNs push certificate | **$0 each** - approval-gated, not purchasable | pages cited in section 3 |
| CloudKit Identity & Trust registration tier/cost | **UNVERIFIED** - no Apple page found today states a fee or required tier; do not assume free or all-inclusive until the CloudKit Console shows the requirement with the paid account | https://developer.apple.com/icloud/identity/ |

Organization enrollment prerequisites if KosherGuard enrolls as an
organization rather than an individual (verified on the enroll page):
legal entity (no DBA/trade name), D-U-N-S Number, a public
organization website on the organization's domain, work email on that
domain, and legal binding authority. Commercial MDM vendor approval
(vendor CSR) expects an organization account; individual is
acceptable for ordinary development.

Non-Apple costs (out of Apple's scope, listed for completeness;
verify current prices before any purchase; nothing here is purchased
or recommended as a decision in this audit): a Mac capable of running
the required Xcode for signed builds and Apple Configurator
(alternatives priced in docs/setup/APPLE_BUILD_REQUIREMENTS.md), and
test iPhones (one running iOS 26+ for the URL Filter lane; a spare
erasable device for the supervision lane).

Total honest bottom line: the minimum Apple-paid spend to reach any
signed on-device test is **$99/year**, plus the UNVERIFIED CloudKit
Identity & Trust tier question, plus hardware. There is no legitimate
$0 path to a signed filter-extension build: managed entitlements
cannot be provisioned on a free Personal Team (section 4). This
audit does not recommend any bypass, and none exists in Apple's
documented model.

## 8. Minimum steps to a real-device test

Ordered. Each [GATE] is an external Apple dependency that cannot be
accelerated by code. Steps 1-2 are prerequisites for everything else.

1. **[GATE: purchase] Enroll in the Apple Developer Program** ($99/yr;
   organization account if the MDM vendor route is wanted). Wait for
   activation (hours to ~2 days).
2. **Portal setup (no cost, no approval wait):** note the Team ID;
   create the 5 App IDs with capabilities (Network Extensions on all
   5, App Groups on all 5 with `group.com.kosherguard.shared`
   registered, Family Controls on the app); replace
   `TEAMIDPLACEHOLDER` in the four entitlements files and
   KeychainCredentialStore.swift with the real Team ID; set
   DEVELOPMENT_TEAM / enable automatic signing in the pbxproj.

Lane A - first real filtering evidence on an ordinary personal
iPhone (URL Filter + app shielding; the cheapest meaningful test):

3. **[GATE: approval] Request the managed Network Extension values**:
   `url-filter-provider` (app + URLFilterExtension). For the shield
   UI alone, Family Controls works in development without approval.
   (`content-filter-provider` and `dns-proxy` are only needed for
   lane B; request them at the same time to overlap the wait.)
4. **Deploy a real PIR service**: replace the two
   `kosherguard.example.com` hosts in App-Info.plist with real HTTPS
   subdomains; run the PIR service + Privacy Pass issuer; include the
   test identity `www.apple.com/url-filter-test` = 1 (Onboarding.md).
   Development-signed/Xcode-installed builds are exempt from Apple's
   OHTTP relay onboarding and from HTTPS/subdomain URL checks, so
   lane A device testing can start before the onboarding form is
   filed.
5. **Sign and install on a registered personal iPhone running iOS
   26+** with Xcode automatic signing (development certificate +
   profiles covering all granted capabilities). Expected behavior to
   verify: URL Filter enable() succeeds, fail-closed behavior on
   unreachable PIR, Family Controls authorization prompt, shield
   apply/remove.
6. **[GATE: approval, distribution only]** Before any TestFlight/App
   Store or MDM-delivered distribution: Family Controls
   (Distribution) request, URL Filter OHTTP relay onboarding with DNS
   TXT `apple-url-filter=com.kosherguard.app`, Identity & Trust
   registration in CloudKit Console (tier UNVERIFIED), and the
   27.3-enforced Info.plist/runtime URL match.

Lane B - supervised-device features (content filter, DNS proxy, MDM
restrictions; needed to test the two remaining extensions):

7. **[GATE: approval]** Grants for `content-filter-provider` and
   `dns-proxy` (requested in step 3).
8. **[GATE: org verification] Apple Business** verified organization
   for Automated Device Enrollment - OR a spare iPhone supervised
   manually with Apple Configurator for Mac (**device is erased**;
   requires a Mac; explicit approval before any erase).
9. **[GATE: approval] MDM Vendor CSR** (Account Holder contacts
   Apple) -> MDM APNs push certificate (identity.apple.com; yearly
   renewal with the same account and topic) - or the free interim
   mdmcert.download route (organizations only).
10. **Supervised device test**: install via MDM; verify NEFilter and
    DNS proxy activation (supervised-only per TN3134) and MDM
    restriction payloads.

## 9. Honesty boundaries

- Verified by actual execution on this branch: unsigned compile/link
  of all five targets (run 44216829456), packaging layout, 136/136
  portable tests, static validator PASS with the 14 placeholder notes
  reproduced in section 5.
- NOT established: any signed build, any on-device run, any granted
  entitlement, any Apple account or organization in good standing,
  working URL Filter / content filter / DNS proxy / app shielding on
  hardware, CloudKit Identity & Trust tier and cost, the exact
  current portal request form names for the managed Network Extension
  values.
- This report changes no code, no signing configuration, no Apple
  state and no device state.
