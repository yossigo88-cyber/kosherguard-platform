# KosherGuard iOS (Swift sources)

STATUS: UNCOMPILED, UNSIGNED, UNTESTED. These sources are written for
review and future Xcode integration; no Swift toolchain exists in the
build environment, no Apple Developer account credentials exist, and no
device has run any of this code.

Entitlements/approvals these targets need before any real use (from
docs/GENTECH_TECHNICAL_INVESTIGATION.md sections 5.4 and 10):
- `com.apple.developer.networkextension.url-filter-provider` (Apple
  request + approval; development-signed testing exempt).
- Apple-hosted OHTTP Relay capability (approval required before any
  distribution build).
- For MDM-pushed URL Filter configuration on iOS 26: supervised device.
- Coverage honesty: NEURLFilter sees WebKit/URLSession traffic only;
  binary verdicts only; no per-device reporting by design.

## Layout

- `Sources/KosherGuard/` - the guardian-facing app: filter status,
  policy summary, enrollment state.
- `Sources/FilterExtension/` - the Network Extension content filter
  (NEFilterDataProvider + NEFilterControlProvider).
- `Sources/URLFilter/` - iOS 26 NEURLFilterManager integration:
  prefilter (Bloom) updates from our url-filter-server and
  configuration of the system's URL Filter.
- `Sources/URLFilter/CredentialIssuanceClient.swift` - STANDALONE
  SOURCE ONLY: requests short-lived scoped device credentials from the
  control plane's mint route. Server-side minting of dataset/proxy
  scopes is covered by control-plane tests, but this client has NO
  execution evidence (uncompiled, no call sites - see below), so
  dataset/proxy are not working iOS functionality. doh scope is
  declared but refused client-side until the held server change lands
  (the published server rejects it 400). Not wired into any app call
  site and not listed in KosherGuard.xcodeproj/project.pbxproj (the
  SwiftPM URLFilter target is directory-based and would pick it up;
  the Xcode project would not). Session acquisition is an open gap:
  the mint route requires a guardian session cookie + CSRF header and
  no native-app token exchange exists server-side. Credential storage
  is in-memory only; Keychain integration is not built.
- `Sources/URLFilter/DNSOverHTTPSClient.swift` - STANDALONE SOURCE
  ONLY (same call-site, Xcode-membership, and execution-evidence
  status as CredentialIssuanceClient): RFC 8484 DoH client attaching
  the scoped credential as an Authorization header, the app-mediated
  identity path from docs/design/DOH_IOS_TRANSPORT.md option 1. This does NOT give system-wide DNS interception: it
  resolves only for traffic the app routes itself, and an operational
  extension path stays gated on Apple entitlements, compilation,
  signing, and device validation. End-to-end use against dns-edge is
  additionally blocked until doh minting exists server-side; the
  client fails closed (401/403 surfaced) until then.
