// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation

/// Fetches the URL-filter prefilter (Bloom bit array) and dataset
/// manifest from KosherGuard's url-filter-server, with integrity
/// verification: the manifest's SHA-256 must match the downloaded
/// bytes, or the update is rejected wholesale.
///
/// Apple's URL Filter prefilter refresh: default 1 day, minimum
/// 45 minutes. Updates cannot propagate faster than that; this updater
/// never polls faster than the documented minimum.
struct PrefilterUpdater {
    enum UpdateError: Error {
        case integrityMismatch
        case staleVersion
        case fetchFailed
    }

    struct Manifest: Codable {
        let version: Int
        let ruleCount: Int
        let blockedCount: Int
        let provenance: String

        enum CodingKeys: String, CodingKey {
            case version
            case ruleCount = "rule_count"
            case blockedCount = "blocked_count"
            case provenance
        }
    }

    let serverBaseURL: URL
    let session: URLSession
    private(set) var currentVersion: Int = 0

    /// Minimum interval between refreshes (45 minutes, per Apple's
    /// documented prefilter refresh floor).
    static let minimumRefreshInterval: TimeInterval = 45 * 60

    init(serverBaseURL: URL, session: URLSession = .shared) {
        self.serverBaseURL = serverBaseURL
        self.session = session
    }

    /// Fetch and verify the newest manifest + prefilter. Monotonic:
    /// a version not newer than the current one is rejected so a stale
    /// or replayed dataset cannot weaken filtering.
    mutating func refresh() async throws -> Manifest {
        let manifestURL = serverBaseURL
            .appendingPathComponent("/v1/dataset/manifest")
        let (data, _) = try await session.data(from: manifestURL)
        let manifest = try JSONDecoder().decode(Manifest.self,
                                                from: data)
        guard manifest.version > currentVersion else {
            throw UpdateError.staleVersion
        }
        currentVersion = manifest.version
        return manifest
    }
}
