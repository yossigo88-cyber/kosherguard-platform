# Apple capability matrix: every entitlement, certificate and profile

Stage 11 (2026-11-17). Inventory of every Apple-side item the iOS app
and its four extensions need, what each costs, and which ones need
Apple's explicit approval. Sources are cited per row; "verified" means
checked against the cited source today.

Targets (bundle IDs are placeholders until a team ID exists):
`com.kosherguard.app` (app), `.FilterExtension` (NEFilterDataProvider),
`.FilterControlExtension` (NEFilterControlProvider), `.DNSProxyExtension`
(NEDNSProxyProvider), `.URLFilterExtension` (NEURLFilterControlProvider).

## 1. Entitlements (as declared in ios/Configuration/*.entitlements)

| Entitlement | On targets | What it allows | Approval needed | Cost |
| --- | --- | --- | --- | --- |
| `com.apple.developer.networking.networkextension` = `content-filter-provider` | app, FilterExtension, FilterControlExtension | NEFilterManager + filter providers | **Yes - Apple-managed value; granted per App ID after a request. Must be present in the provisioning profile in EVERY configuration; no development waiver** (repo-verified in Stage 10 against Apple's Network Extensions Entitlement doc + TN3134) | $0 beyond program membership |
| `com.apple.developer.networking.networkextension` = `url-filter-provider` | app, URLFilterExtension | NEURLFilterManager + URL filter provider (iOS 26+) | **Yes** - Apple capability approval for the App ID; WWDC25 session 234 and 2026 developer-forum reports (cited in URLFilterExtension.entitlements) | $0 beyond membership |
| `com.apple.developer.networking.networkextension` = `dns-proxy` | DNSProxyExtension | NEDNSProxyProvider | **Yes** - Apple-managed value (same entitlement doc) | $0 beyond membership |
| `com.apple.developer.family-controls` | app | Screen Time APIs: AuthorizationCenter, FamilyActivityPicker, ManagedSettingsStore | Development: available in Xcode. **Distribution: requires Apple's approval**, requested by the Account Holder via the Family Controls distribution form or the Capability Requests tab in Certificates, Identifiers & Profiles; each Screen Time app extension needs the same request (developer.apple.com/documentation/familycontrols/requesting-the-family-controls-entitlement, fetched 2026-11-17). Not yet requested. | $0 beyond membership |
| `com.apple.security.application-groups` = `group.com.kosherguard.shared` | all 5 targets | Shared container for the rule store / prefilter / policy mirror | No approval; the group must be **registered** to the App IDs in the portal and the placeholder replaced with the real value | $0 |
| `keychain-access-groups` = `TEAMIDPLACEHOLDER.com.kosherguard.shared` | app, FilterExtension, FilterControlExtension, DNSProxyExtension | Shared keychain (session credential bundle) | No approval; the real 10-character Team ID must replace the placeholder. URLFilterExtension intentionally has no keychain group (it never reads credentials) | $0 |

Related non-entitlement Apple registration:

| Item | Why | Gate |
| --- | --- | --- |
| URL Filter PIR onboarding | `NSPIRConfiguration` in App-Info.plist declares `PIRServerURL` / `PrivacyPassIssuerURL` hosts (currently `.example.com` placeholders); Apple onboards the PIR service and requires a DNS TXT record `apple-url-filter=<app bundle id>` on the service host. From iOS/macOS 27.3 the system rejects mismatches between the plist values and `NEURLFilterManager.setConfiguration`. (Apple pir-service-example Onboarding.md, as recorded in App-Info.plist comments Stage 10.) | Apple onboarding approval; placeholders block any URL Filter enablement |
| CloudKit Identity & Trust registration `<bundle-id>.url.filtering` | Required before the URL Filter can serve (recorded as an open gate in the Stage 10 report section 7; tier/requirements unverified) | Unverified - confirm during URL Filter enablement |

## 2. Certificates

| Certificate | Purpose | How obtained | Cost |
| --- | --- | --- | --- |
| Apple Development | Sign development builds | Xcode automatic signing or developer.apple.com | included in $99/yr program |
| Apple Distribution | Sign TestFlight/App Store/MDM-distributed builds | Same | included |
| **MDM Vendor CSR Signing Certificate** | Lets KosherGuard sign customer CSRs to obtain MDM APNs push certificates from identity.apple.com | Account Holder of the **Apple Developer Program ($99/yr)** or Enterprise Program must **contact Apple** to request access (developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/, fetched 2026-11-17). Alternative routes for the push cert itself: Apple Profile Manager (macOS Server, $20, extracts a cert; test-grade) or mdmcert.download (free, organizations only) - micromdm.io/blog/certificates/ | program membership + Apple approval |
| MDM APNs push certificate (per environment) | Authenticates KosherGuard's MDM server to Apple Push | identity.apple.com, CSR signed by the vendor cert above; **expires yearly and must be renewed with the same Apple ID and same push topic or all enrolled devices lose MDM** (micromdm.io/blog/certificates/) | $0 once the vendor cert exists |
| TLS certificate for the MDM/filter endpoints | HTTPS on control-plane/mdm/url-filter hosts | Existing web PKI (the project already uses Caddy/Let's Encrypt on the staging host) | $0 |

## 3. Provisioning profiles and App IDs

- **5 App IDs** (one per target), each with its capabilities enabled:
  Network Extensions (with the approved values), App Groups
  (app + all extensions), Family Controls (app, distribution),
  plus the URL Filter / CloudKit registration for the app.
- **Development profiles** for all 5 targets and **distribution
  profiles** when distribution starts. Signed entitlements must match
  the portal-granted capabilities exactly - a profile without the
  managed Network Extension values makes the filter extensions
  unrunnable even in development.
- Automatic signing in Xcode can manage these once the capabilities
  are granted; until approvals land, signing the filter extensions
  will fail - expected, not a project defect.

## 4. Paid vs free summary

| Capability | Free Apple account | Paid Apple Developer Program ($99/yr) | Additional Apple approval |
| --- | --- | --- | --- |
| Unsigned SDK compile (CI route) | yes (no account at all) | yes | none |
| Dev-signed app on own devices | yes (7-day profiles, device/app-ID limits) | yes | none |
| Family Controls (Screen Time) development | yes | yes | distribution only |
| Network Extension managed values (content-filter, dns-proxy, url-filter) | **no** | only after approval | **required** |
| URL Filter PIR onboarding | no | required | **required** |
| App Store / TestFlight distribution | no | yes | App Review; Family Controls distribution grant |
| MDM Vendor CSR signing certificate | no | required, via "contact us" | **required** |
| Apple Business (ABM/ASM) account | **free** (no program membership needed) | - | organizational verification by Apple |
| Automated Device Enrollment (supervision) for owned devices | free via Apple Business, or Apple Configurator on a Mac (erases the device) | - | none |

Verified 2026-11-17: $99/yr membership figure (developer.apple.com/
programs/), Family Controls request flow, TN3134 deployment rows,
MDM vendor CSR requirement, GitHub Actions free-for-public-repos
billing, Xcode/macOS matrix. UNVERIFIED items are marked in their
rows above.
