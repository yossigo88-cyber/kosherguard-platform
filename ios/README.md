# KosherGuard iOS (Swift sources)

STATUS: UNCOMPILED FOR iOS, UNSIGNED, UNTESTED ON APPLE HARDWARE.
These sources are written for review and future Xcode integration; no
Apple SDK, Apple Developer account credentials, or device has run any
of this code. What DOES exist (2026-11-17): Linux logic-level portable
verification of the portable (non-NetworkExtension) URLFilter sources -
see tools/run-swift-portable-tests.sh and tools/swift-portable-tests.swift.
That verification compiled the Core sources with direct swiftc against a
test-only SHA-256 shim module (substituting the swift-crypto dependency;
shim matched on 3 NIST vectors only, not a validated crypto library) and
ran the portable test bodies with minimal XCTest assertion shims - NOT
the production SPM dependency build, NOT full XCTest execution, NOT an
iOS build. It proves nothing about Network Extension behavior, Apple
APIs, signing, or device behavior.

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
- `Sources/URLFilter/CredentialIssuanceClient.swift` - requests
  short-lived scoped device credentials from the control plane's mint
  route. Wired (2026-11-16): a real call site exists
  (CredentialController in KosherGuardApp.swift) and both clients are
  members of KosherGuard.xcodeproj (and the directory-based SwiftPM
  URLFilter target; Package.swift declares the KosherGuard ->
  URLFilter dependency). Still NO iOS execution evidence: uncompiled
  for iOS, unsigned, untested on device, so dataset/proxy/doh are not
  working iOS functionality - server-side minting is covered by
  control-plane tests only. The published control plane mints the doh
  scope, so the client no longer refuses it; end-to-end DoH use stays
  unproven until an iOS build exists. Session acquisition is now REAL CODE:
  AuthSessionClient signs in through the published /api/auth/login
  (JSON body + static CSRF marker header, MFA code when enrolled; the
  server's identical-401 anti-enumeration is honored) and captures the
  kg_session cookie (contract re-checked against the published server
  after an initial draft used the wrong cookie name). A reachable user
  action exists: CredentialSignInView's "Sign in and request
  credential" button runs CredentialController.signInAndIssue =
  sign-in -> dataset-scope mint -> Keychain save. Server URL and
  device ID come from MDM-managed App Configuration
  (AppConfiguration.swift, com.apple.configuration.managed), the real
  configuration mechanism - nothing fixture-baked; unconfigured
  devices show "Not configured by MDM". Keychain lifecycle: a 401 at
  mint deletes the stored session; signOut() calls the server logout
  and deletes both keys. STILL no execution evidence (uncompiled), so
  none of this is working iOS functionality.
- `Sources/URLFilter/DNSOverHTTPSClient.swift` - RFC 8484 DoH client
  attaching the scoped credential as an Authorization header, the
  app-mediated identity path from docs/design/DOH_IOS_TRANSPORT.md
  option 1. Same wiring status as CredentialIssuanceClient (Xcode
  member, no app call site beyond the controller, uncompiled). This does NOT give system-wide DNS interception: it
  resolves only for traffic the app routes itself, and an operational
  extension path stays gated on Apple entitlements, compilation,
  signing, and device validation. The published
  server mints doh-scoped credentials; the client surfaces 401/403
  (fails closed) on rejection, and end-to-end use against dns-edge
  remains unproven without an iOS build.
