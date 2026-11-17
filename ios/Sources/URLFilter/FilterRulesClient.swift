// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). Network behavior
// against a live control plane is UNVERIFIED - no iOS build exists.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Client for GET /api/devices/{device_id}/filter-rules - the control
/// plane's export of the guardian's OWN explicit allow/block domains
/// for the device's effective policy. Category expansions are never
/// in this feed (they ship only as the opaque Bloom prefilter), so
/// receiving it does not hand the device the licensed blocklist.
///
/// Auth is the guardian session cookie from /api/auth/login plus the
/// static CSRF marker header - the same contract AuthSessionClient
/// and CredentialIssuanceClient already use.
public struct FilterRulesClient {
    let baseURL: URL
    let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }



    public struct RulesResponse: Equatable {
        public let deviceID: Int
        public let tenantID: Int
        public let policyID: Int?
        public let generation: Int
        public let defaultPolicy: String?
        public let rules: [String: Bool]

        /// True when the server reports an effective published policy.
        /// When false the caller CLEARS the store: rules from an
        /// unassigned policy must not keep filtering. The client
        /// already rejected inconsistent mixes (policy id without a
        /// positive generation or vice versa) as invalidPayload, so
        /// this is a clean signal, never a malformed-response fallback.
        public var hasEffectivePolicy: Bool {
            policyID != nil && generation >= 1
        }
    }

    public enum RulesError: Error, Equatable {
        case unauthorized
        case deviceNotFound
        /// 409: the device is offboarded/inactive - authoritative
        /// invalidation, never a transient failure.
        case deviceInactive
        case unexpectedStatus(Int)
        case malformedResponse
        case invalidPayload
    }

    private struct Body: Decodable {
        let device_id: Int
        let tenant_id: Int
        let policy_id: Int?
        let generation: Int
        let default_policy: String?
        let rules: [String: Bool]
    }

    public func fetch(deviceID: Int,
                      sessionCookie: String) async throws -> RulesResponse {
        var req = URLRequest(url: baseURL
            .appendingPathComponent("api/devices")
            .appendingPathComponent(String(deviceID))
            .appendingPathComponent("filter-rules"))
        req.httpMethod = "GET"
        req.setValue("1", forHTTPHeaderField: "X-KosherGuard-Request")
        req.setValue("kg_session=\(sessionCookie)",
                     forHTTPHeaderField: "Cookie")
        req.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw RulesError.malformedResponse
        }
        switch http.statusCode {
        case 200: break
        case 401, 403: throw RulesError.unauthorized
        case 404: throw RulesError.deviceNotFound
        case 409: throw RulesError.deviceInactive
        default: throw RulesError.unexpectedStatus(http.statusCode)
        }
        guard let body = try? JSONDecoder().decode(Body.self, from: data),
              body.device_id == deviceID,
              body.tenant_id > 0,
              body.generation >= 0,
              // Consistency: a policy id and a positive generation are
              // either both present (effective policy) or both absent
              // (no effective policy). A mix is a contract violation -
              // never let it become a clear-store or persist action.
              (body.policy_id != nil) == (body.generation >= 1)
        else { throw RulesError.invalidPayload }
        if let policy = body.default_policy,
           policy != "allow", policy != "block" {
            throw RulesError.invalidPayload
        }
        // Reuse the store's schema invariants: every key must already
        // be a normalized host.
        for host in body.rules.keys {
            guard FilterRuleStore.normalizedHost(host) == host else {
                throw RulesError.invalidPayload
            }
        }
        return RulesResponse(deviceID: body.device_id,
                             tenantID: body.tenant_id,
                             policyID: body.policy_id,
                             generation: body.generation,
                             defaultPolicy: body.default_policy,
                             rules: body.rules)
    }
}
