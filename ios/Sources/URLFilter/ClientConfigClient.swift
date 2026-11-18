// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). Network behavior
// against a live control plane is UNVERIFIED - no signed iOS build
// exists. See ios/README.md.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Client for GET /api/client-config - the control plane's native-client
/// service discovery. The personal lane (no MDM) learns where the
/// deployment's supporting services are from the server it just signed
/// in to; every value comes straight from server configuration and a
/// null means "not deployed". Nothing here invents or assumes an
/// endpoint: an absent dataset server means the category prefilter is
/// unavailable, an absent PIR pair means the URL Filter cannot be
/// enabled, and the app says exactly that.
///
/// Auth is the guardian session cookie from /api/auth/login - the same
/// contract as the other control-plane clients.
public struct ClientConfigClient {
    let baseURL: URL
    let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    public struct ServiceConfig: Equatable {
        public let datasetBaseURL: URL?
        public let dohServerURL: URL?
        public let pirServerURL: URL?
        public let pirPrivacyPassIssuerURL: URL?
        /// Human-readable per-key problems (a configured-but-invalid
        /// value is dropped, never used, and named here).
        public let issues: [String]

        public init(datasetBaseURL: URL?, dohServerURL: URL?,
                    pirServerURL: URL?, pirPrivacyPassIssuerURL: URL?,
                    issues: [String]) {
            self.datasetBaseURL = datasetBaseURL
            self.dohServerURL = dohServerURL
            self.pirServerURL = pirServerURL
            self.pirPrivacyPassIssuerURL = pirPrivacyPassIssuerURL
            self.issues = issues
        }
    }

    public enum ClientConfigError: Error, Equatable {
        case unauthorized
        case unexpectedStatus(Int)
        case malformedResponse
    }

    private struct ConfigBody: Decodable {
        let dataset_base_url: String?
        let doh_server_url: String?
        let pir_server_url: String?
        let pir_privacy_pass_issuer_url: String?
    }

    public func fetch(sessionCookie: String) async throws -> ServiceConfig {
        var req = URLRequest(url: baseURL
            .appendingPathComponent("api/client-config"))
        req.httpMethod = "GET"
        req.setValue("1", forHTTPHeaderField: "X-KosherGuard-Request")
        req.setValue("kg_session=\(sessionCookie)",
                     forHTTPHeaderField: "Cookie")
        req.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw ClientConfigError.malformedResponse
        }
        switch http.statusCode {
        case 200: break
        case 401, 403: throw ClientConfigError.unauthorized
        default: throw ClientConfigError.unexpectedStatus(http.statusCode)
        }
        guard let body = try? JSONDecoder().decode(ConfigBody.self,
                                                        from: data)
        else { throw ClientConfigError.malformedResponse }

        var issues: [String] = []
        func validated(_ value: String?, _ key: String) -> URL? {
            guard let value else { return nil }
            guard let url = PersonalConfiguration.validatedHTTPSURL(value)
            else {
                issues.append("\(key) is not a plain https URL; ignored")
                return nil
            }
            return url
        }
        let dataset = validated(body.dataset_base_url,
                                "dataset_base_url")
        let doh = validated(body.doh_server_url, "doh_server_url")
        var pir = validated(body.pir_server_url, "pir_server_url")
        var issuer = validated(body.pir_privacy_pass_issuer_url,
                               "pir_privacy_pass_issuer_url")
        // The PIR pair is jointly optional (same rule as the managed
        // configuration and the server settings): exactly one present
        // is a configuration error, surfaced, with both dropped.
        if (pir == nil) != (issuer == nil) {
            issues.append("pir_server_url and "
                + "pir_privacy_pass_issuer_url must both be set")
            pir = nil
            issuer = nil
        }
        return ServiceConfig(datasetBaseURL: dataset, dohServerURL: doh,
                             pirServerURL: pir,
                             pirPrivacyPassIssuerURL: issuer,
                             issues: issues)
    }
}
