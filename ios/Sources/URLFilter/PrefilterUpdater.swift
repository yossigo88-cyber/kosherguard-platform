// STATUS: Not validated on Apple hardware. Portable integrity/download logic
// is exercised separately; this is NOT Apple's on-device Bloom serialization.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Fetch the authenticated dataset distribution surface. SHA-256 detects a
/// corrupt or mixed-generation download; it is NOT a digital signature.
/// Authenticity comes from HTTPS to the configured server. Never advance
/// the active version unless both manifest and prefilter verify.
struct PrefilterUpdater {
    enum UpdateError: Error {
        case integrityMismatch
        case staleVersion
        case fetchFailed
        case invalidServer
        case tooSoon
    }

    struct Manifest: Codable {
        struct Prefilter: Codable {
            let bytes: Int
            let sha256: String
        }
        let version: Int
        let ruleCount: Int
        let blockedCount: Int
        let provenance: String
        let prefilter: Prefilter
        enum CodingKeys: String, CodingKey {
            case version, provenance, prefilter
            case ruleCount = "rule_count"
            case blockedCount = "blocked_count"
        }
    }

    struct Snapshot: Codable {
        let manifest: Manifest
        let prefilter: Data
    }

    let serverBaseURL: URL
    let session: URLSession
    private(set) var currentVersion: Int = 0
    private(set) var activeSnapshot: Snapshot?
    private var lastAttempt: Date?
    static let minimumRefreshInterval: TimeInterval = 45 * 60

    init(serverBaseURL: URL, session: URLSession = .shared) {
        self.serverBaseURL = serverBaseURL
        self.session = session
    }

    mutating func refresh(credential: String, persistTo: URL? = nil,
                          now: Date = Date()) async throws -> Manifest {
        guard serverBaseURL.scheme?.lowercased() == "https",
              serverBaseURL.host != nil, serverBaseURL.user == nil,
              serverBaseURL.password == nil, !credential.isEmpty else {
            throw UpdateError.invalidServer
        }
        if let lastAttempt, now.timeIntervalSince(lastAttempt) < Self.minimumRefreshInterval {
            throw UpdateError.tooSoon
        }
        lastAttempt = now
        func fetch(_ path: String) async throws -> Data {
            var req = URLRequest(url: serverBaseURL.appendingPathComponent(path))
            req.setValue("Bearer \(credential)", forHTTPHeaderField: "Authorization")
            req.cachePolicy = .reloadIgnoringLocalCacheData
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw UpdateError.fetchFailed
            }
            return data
        }
        let manifestData = try await fetch("v1/dataset/manifest")
        let manifest = try JSONDecoder().decode(Manifest.self, from: manifestData)
        guard manifest.version > currentVersion else { throw UpdateError.staleVersion }
        guard manifest.prefilter.bytes > 0, manifest.prefilter.bytes <= 64 * 1024 * 1024,
              manifest.prefilter.sha256.count == 64 else { throw UpdateError.integrityMismatch }
        let bits = try await fetch("v1/dataset/prefilter")
        let digest = SHA256.hash(data: bits).map { String(format: "%02x", $0) }.joined()
        guard bits.count == manifest.prefilter.bytes,
              digest == manifest.prefilter.sha256 else { throw UpdateError.integrityMismatch }
        let snapshot = Snapshot(manifest: manifest, prefilter: bits)
        // One atomic document: no manifest/version can outlive its bytes.
        if let persistTo {
            try JSONEncoder().encode(snapshot).write(to: persistTo,
                                                     options: [.atomic, .completeFileProtection])
        }
        activeSnapshot = snapshot
        currentVersion = manifest.version
        return manifest
    }

    mutating func restore(from url: URL) throws {
        let candidate = try JSONDecoder().decode(Snapshot.self,
            from: Data(contentsOf: url))
        let digest = SHA256.hash(data: candidate.prefilter)
            .map { String(format: "%02x", $0) }.joined()
        guard candidate.manifest.version >= currentVersion,
              candidate.manifest.version > 0,
              candidate.prefilter.count == candidate.manifest.prefilter.bytes,
              digest == candidate.manifest.prefilter.sha256 else {
            throw UpdateError.integrityMismatch
        }
        activeSnapshot = candidate
        currentVersion = candidate.manifest.version
    }
}
