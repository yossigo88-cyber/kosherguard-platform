# DoH per-device identity: iOS transport constraint (design)

STATUS: source-grounded design finding, 2026-11-16.

## Verified constraint

Apple's `com.apple.dnsSettings.managed` profile payload (the only
native, system-wide encrypted-DNS configuration on iOS) supports
exactly: `DNSProtocol` (HTTPS or TLS), `ServerURL` (RFC 8484 URI
template), `ServerName`, `ServerAddresses`, `SupplementalMatchDomains`,
`SupplementalMatchDomainsNoSearch`. There is NO field for HTTP headers,
client identity, or per-request credentials.

Sources:
- github.com/apple/device-management, release branch,
  mdm/profiles/com.apple.dnsSettings.managed.yaml
- developer.apple.com NEDNSOverHTTPSSettings.serverURL (RFC 8484 URI
  template only)

Consequence: a per-device credential in an Authorization header (the
mechanism in `dns-edge/doh_identity.py`) CANNOT be used by the native
iOS DNS path. It works only where we control the HTTP client - our own
app or proxy. Any design that assumes custom headers on the native
path is wrong; do not build or claim it.

## Options that remain (user decision required before production)

1. **App-mediated DNS** - our iOS app/extension performs resolution
   and attaches the scoped credential header. Full compliance with the
   approved design; limited to traffic we can route (needs the
   approved Network Extension entitlements).
2. **Mutual TLS at the DoH endpoint** - per-device client certificate
   as the identity. Feasibility on the native iOS DNS path is
   UNDOCUMENTED by Apple; must be verified on hardware before
   relying on it. No claim made here.
3. **MDM-rotated short-lived URL tokens (fallback)** - the
   ServerURL carries a per-device path token, redeployed by MDM
   profile updates before expiry. This is a bearer credential in a
   URL: it conflicts with the user's stated preference and is only
   acceptable as a limited, explicitly approved fallback with short
   rotation, single-device scope, and log redaction.

## What is built

- `dns-edge/doh_identity.py`: header-based per-device identity for
  transports that support it (option 1 and server-side verification).
- The native-profile gap above is a design input for the iOS app and
  MDM profile generation, both of which must read this document
  before choosing a transport.
