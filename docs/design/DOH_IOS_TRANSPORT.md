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
3. **MDM-rotated short-lived URL tokens** - the ServerURL carries a
   per-device path token, redeployed by MDM profile updates before
   expiry. This is a bearer credential in a URL and CONTRADICTS the
   user's explicit rule ("Do not put long-lived bearer credentials in
   DoH URLs or query strings"). It is NOT approved, NOT a default, and
   NOT built. It exists here only so the option is on record; using it
   would require the user to approve a new exception in writing.

The approved-design candidates are options 1 and 2. Option 2's
hardware behavior (does the native iOS DNS client present a client
certificate on the DoH TLS handshake?) is undocumented by Apple and
unknown until tested on a supervised device with development
signing - a hardware-only unknown, recorded here rather than assumed.

## What is built

- `dns-edge/doh_identity.py`: header-based per-device identity for
  transports that support it (option 1 and server-side verification).
- The native-profile gap above is a design input for the iOS app and
  MDM profile generation, both of which must read this document
  before choosing a transport.
