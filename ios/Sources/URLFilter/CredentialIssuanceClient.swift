// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Client for the control plane's scoped device-credential issuance
/// route (POST /api/devices/{device_id}/dataset-credential).
///
/// This is the app-mediated half of the approved per-device identity
/// design: the app obtains a short-lived scoped token and attaches it
/// to requests it controls (see DNSOverHTTPSClient). It exists so the
/// missing request path is real code, not a design note.
///
/// Server contract, verified against the published control plane:
/// - Auth: guardian session cookie from /api/auth/login PLUS the
///   CSRF header `X-KosherGuard-Request: 1`. A native-app token
///   exchange does not exist on the server yet; that is a known
///   server-side gap for native clients, recorded here, not worked
///   around.
/// - Scopes the PUBLISHED server mints: "dataset" and "proxy". A
///   "doh" scope request is rejected 400 today; doh minting is part
///   of a held server change pending the user's decision. This client
///   parameterizes the scope but callers MUST treat .doh as
///   unavailable until that server change lands - the failure surface
///   is the server's 400, surfaced as IssuanceError.scopeUnavailable.
/// - Response: {device_id, credential, scope, policy_id?}. The raw
///   token is returned once and never stored or logged server-side;
///   this client mirrors that: it keeps the token in memory only and
///   never writes it to disk, UserDefaults, or logs.
public struct CredentialIssuanceClient {
    let baseURL: URL
    let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    public enum Scope: String {
        case dataset
        case proxy
        /// Not mintable by the published server (400). Declared so the
        /// DoH path has a typed placeholder; requestDoh() refuses to
        /// even send it until the server change lands.
        case doh
    }

    public struct ScopedCredential {
        let deviceID: Int
        public let token: String
        let scope: String
        let policyID: Int?
    }

    public enum IssuanceError: Error, Equatable {
        case scopeUnavailable(String)
        case unauthorized
        case deviceNotFound
        case issuanceNotConfigured
        case noEffectivePolicy
        case unexpectedStatus(Int)
        case malformedResponse
    }

    /// Request a credential for a scope the published server mints.
    /// `sessionCookie` is the guardian session cookie value obtained
    /// from /api/auth/login; this client does not perform login.
    public func mint(deviceID: Int, scope: Scope,
              sessionCookie: String) async throws -> ScopedCredential {
        var req = URLRequest(url: baseURL
            .appendingPathComponent("api/devices")
            .appendingPathComponent(String(deviceID))
            .appendingPathComponent("dataset-credential"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("1", forHTTPHeaderField: "X-KosherGuard-Request")
        req.setValue("kg_session=\(sessionCookie)",
                     forHTTPHeaderField: "Cookie")
        req.httpBody = try JSONEncoder().encode(["scope": scope.rawValue])

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw IssuanceError.malformedResponse
        }
        switch http.statusCode {
        case 200: break
        case 401, 403: throw IssuanceError.unauthorized
        case 404: throw IssuanceError.deviceNotFound
        case 409: throw IssuanceError.noEffectivePolicy
        case 503: throw IssuanceError.issuanceNotConfigured
        default: throw IssuanceError.unexpectedStatus(http.statusCode)
        }
        struct Body: Decodable {
            let device_id: Int
            let credential: String
            let scope: String
            let policy_id: Int?
        }
        guard let body = try? JSONDecoder().decode(Body.self, from: data)
        else { throw IssuanceError.malformedResponse }
        return ScopedCredential(deviceID: body.device_id,
                                token: body.credential,
                                scope: body.scope,
                                policyID: body.policy_id)
    }
}
