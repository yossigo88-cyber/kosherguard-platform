// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation

/// RFC 8484 DNS-over-HTTPS client that attaches a scoped per-device
/// credential as an Authorization header - the mechanism in
/// dns-edge/doh_identity.py, usable ONLY where we control the HTTP
/// client (this app). The native iOS DNS path
/// (com.apple.dnsSettings.managed) cannot carry headers; see
/// docs/design/DOH_IOS_TRANSPORT.md. Nothing here claims system-wide
/// DNS interception: this client resolves names for traffic the app
/// itself routes, and an operational Network Extension path remains
/// gated on Apple entitlements, compilation, signing, and device
/// validation.
///
/// Credential precondition: dns-edge verifies scope "doh" tokens, but
/// the published control plane does not mint them yet (held server
/// change pending the user's decision). Until then every query made
/// with this client against dns-edge will fail closed - that is the
/// correct failure mode and is surfaced, not bypassed.
struct DNSOverHTTPSClient {
    let serverURL: URL
    let session: URLSession

    enum DoHError: Error {
        case queryFailed(Int)
        case malformedResponse
    }

    /// Resolve a wire-format DNS query (RFC 1035 message bytes) via
    /// POST application/dns-message with the scoped credential in the
    /// Authorization header. The token is placed on the request only;
    /// it is never logged or persisted here.
    func resolve(queryMessage: Data,
                 credential: ScopedCredentialToken) async throws -> Data {
        var req = URLRequest(url: serverURL)
        req.httpMethod = "POST"
        req.setValue("application/dns-message",
                     forHTTPHeaderField: "Content-Type")
        req.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        req.setValue("Bearer \(credential.value)",
                     forHTTPHeaderField: "Authorization")
        req.httpBody = queryMessage

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw DoHError.malformedResponse
        }
        guard http.statusCode == 200 else {
            // 401/403 land here while doh minting is unavailable, and
            // on revocation once the held revocation feed exists.
            throw DoHError.queryFailed(http.statusCode)
        }
        return data
    }
}

/// Opaque token wrapper so call sites cannot accidentally interpolate
/// the raw secret into strings (e.g. log lines) without writing
/// `credential.value` deliberately.
struct ScopedCredentialToken {
    let value: String
    init(_ raw: String) { self.value = raw }
}
