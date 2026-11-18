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
        /// 401/403: the device credential was rejected - an
        /// authoritative invalidation (revoked/offboarded), not a
        /// transient fetch problem.
        case unauthorized
        case invalidServer
        case tooSoon
    }

    struct Manifest: Codable {
        struct Prefilter: Codable {
            let format: String
            let bitCount: Int
            let hashCount: Int
            let murmurSeed: UInt32
            let bytes: Int
            let sha256: String
            enum CodingKeys: String, CodingKey {
                case format, bytes, sha256
                case bitCount = "bit_count"
                case hashCount = "hash_count"
                case murmurSeed = "murmur_seed"
            }
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

        /// The validated Apple-format parameter set for the system
        /// URL Filter call. Wrong-format or malformed manifests fail
        /// closed here: the system is never handed parameters from an
        /// unvalidated document.
        func appleParameters() throws -> ApplePrefilterParameters {
            try ApplePrefilterParameters(
                format: prefilter.format, bitCount: prefilter.bitCount,
                hashCount: prefilter.hashCount,
                murmurSeed: prefilter.murmurSeed,
                byteCount: prefilter.bytes, sha256: prefilter.sha256)
        }
    }

    struct Snapshot: Codable {
        let manifest: Manifest
        let prefilter: Data
        /// The endpoint fingerprint of the identity that downloaded
        /// this snapshot. The cache is IDENTITY-BOUND: a restored
        /// version from a DIFFERENT server/identity must never
        /// suppress the first download from the current one
        /// (restore rejects it, the sync does a full download).
        let endpointFingerprint: String
        /// When this snapshot was downloaded. Bounds the artifact's
        /// lifetime AT USE TIME: URLFilterPrefilterSource refuses an
        /// artifact older than maxArtifactAge even when no refresh
        /// ever runs (the OS is never obliged to wake the app), so
        /// stale policy can never be enforced without bound.
        /// Required on decode: a legacy artifact without it cannot
        /// prove its age and is treated as corrupt (full re-download,
        /// never silently trusted).
        let fetchedAt: Date

        enum CodingKeys: String, CodingKey {
            case manifest, prefilter, endpointFingerprint, fetchedAt
        }

        init(manifest: Manifest, prefilter: Data,
             endpointFingerprint: String, fetchedAt: Date) {
            self.manifest = manifest
            self.prefilter = prefilter
            self.endpointFingerprint = endpointFingerprint
            self.fetchedAt = fetchedAt
        }

        /// Explicit seconds-since-1970 encoding: the artifact crosses
        /// encoders (written by JSONEncoder, hand-written by tests,
        /// read on any platform), so the date must not depend on a
        /// coder's default date strategy.
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            manifest = try c.decode(Manifest.self, forKey: .manifest)
            prefilter = try c.decode(Data.self, forKey: .prefilter)
            endpointFingerprint = try c.decode(String.self,
                                               forKey: .endpointFingerprint)
            fetchedAt = Date(timeIntervalSince1970:
                try c.decode(Double.self, forKey: .fetchedAt))
        }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(manifest, forKey: .manifest)
            try c.encode(prefilter, forKey: .prefilter)
            try c.encode(endpointFingerprint, forKey: .endpointFingerprint)
            try c.encode(fetchedAt.timeIntervalSince1970,
                         forKey: .fetchedAt)
        }
    }

    let serverBaseURL: URL
    let session: URLSession
    let endpointFingerprint: String
    private(set) var currentVersion: Int = 0
    private(set) var activeSnapshot: Snapshot?
    private var lastCheck: Date?
    private var lastFailure: Date?
    static let minimumRefreshInterval: TimeInterval = 45 * 60
    // A failed attempt may retry after this short backoff: a transient
    // error must not suppress updates for the whole cadence, but the
    // server is still never hammered.
    static let failureRetryInterval: TimeInterval = 60

    init(serverBaseURL: URL, endpointFingerprint: String = "",
         session: URLSession = .shared) {
        self.serverBaseURL = serverBaseURL
        self.endpointFingerprint = endpointFingerprint
        self.session = session
    }

    mutating func refresh(credential: String, persistTo: URL? = nil,
                          now: Date = Date()) async throws -> Manifest {
        guard serverBaseURL.scheme?.lowercased() == "https",
              serverBaseURL.host != nil, serverBaseURL.user == nil,
              serverBaseURL.password == nil, !credential.isEmpty else {
            throw UpdateError.invalidServer
        }
        if let lastCheck, now.timeIntervalSince(lastCheck) < Self.minimumRefreshInterval {
            throw UpdateError.tooSoon
        }
        if let lastFailure, now.timeIntervalSince(lastFailure) < Self.failureRetryInterval {
            throw UpdateError.tooSoon
        }
        // Stamped up front: every throwing exit before a completed check
        // counts as a failure and gets the short backoff, not the cadence.
        lastFailure = now
        func fetch(_ path: String) async throws -> Data {
            var req = URLRequest(url: serverBaseURL.appendingPathComponent(path))
            req.setValue("Bearer \(credential)", forHTTPHeaderField: "Authorization")
            req.cachePolicy = .reloadIgnoringLocalCacheData
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else {
                throw UpdateError.fetchFailed
            }
            if http.statusCode == 401 || http.statusCode == 403 {
                throw UpdateError.unauthorized
            }
            guard http.statusCode == 200 else {
                throw UpdateError.fetchFailed
            }
            return data
        }
        let manifestData = try await fetch("v1/dataset/manifest")
        let manifest = try JSONDecoder().decode(Manifest.self, from: manifestData)
        guard manifest.version > currentVersion else {
            // A completed check with nothing new: full cadence applies.
            lastCheck = now
            lastFailure = nil
            throw UpdateError.staleVersion
        }
        guard manifest.prefilter.bytes > 0, manifest.prefilter.bytes <= 64 * 1024 * 1024,
              manifest.prefilter.sha256.count == 64,
              // The Apple-format parameters must validate before any
              // byte is trusted (wrong format, inconsistent sizing,
              // out-of-range counts all fail closed).
              (try? manifest.appleParameters()) != nil else { throw UpdateError.integrityMismatch }
        let bits = try await fetch("v1/dataset/prefilter")
        let digest = SHA256.hash(data: bits).map { String(format: "%02x", $0) }.joined()
        guard bits.count == manifest.prefilter.bytes,
              digest == manifest.prefilter.sha256 else { throw UpdateError.integrityMismatch }
        let snapshot = Snapshot(manifest: manifest, prefilter: bits,
                                endpointFingerprint: endpointFingerprint,
                                fetchedAt: now)
        // One atomic document: no manifest/version can outlive its bytes.
        if let persistTo {
            try JSONEncoder().encode(snapshot).write(to: persistTo,
                                                     options: [.atomic, .completeFileProtection])
        }
        activeSnapshot = snapshot
        currentVersion = manifest.version
        lastCheck = now
        lastFailure = nil
        return manifest
    }

    /// Authenticated readback of GET /v1/dataset/status: which
    /// generation is served, whether the publication root advertises
    /// a newer one (behind) and the last activation error. Same
    /// credential and server guards as the dataset fetch. Best-effort:
    /// a failure here must never disturb filtering state, so callers
    /// use try?.
    public func fetchStatus(credential: String) async throws -> DatasetStatus {
        guard serverBaseURL.scheme?.lowercased() == "https",
              serverBaseURL.host != nil, serverBaseURL.user == nil,
              serverBaseURL.password == nil, !credential.isEmpty else {
            throw UpdateError.invalidServer
        }
        var req = URLRequest(
            url: serverBaseURL.appendingPathComponent(
                "v1/dataset/status"))
        req.setValue("Bearer \(credential)",
                     forHTTPHeaderField: "Authorization")
        req.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw UpdateError.fetchFailed
        }
        if http.statusCode == 401 || http.statusCode == 403 {
            throw UpdateError.unauthorized
        }
        guard http.statusCode == 200 else {
            throw UpdateError.fetchFailed
        }
        return try JSONDecoder().decode(DatasetStatus.self, from: data)
    }

    mutating func restore(from url: URL) throws {
        let candidate = try JSONDecoder().decode(Snapshot.self,
            from: Data(contentsOf: url))
        let digest = SHA256.hash(data: candidate.prefilter)
            .map { String(format: "%02x", $0) }.joined()
        guard candidate.endpointFingerprint == endpointFingerprint,
              candidate.manifest.version >= currentVersion,
              candidate.manifest.version > 0,
              candidate.prefilter.count == candidate.manifest.prefilter.bytes,
              digest == candidate.manifest.prefilter.sha256 else {
            throw UpdateError.integrityMismatch
        }
        activeSnapshot = candidate
        currentVersion = candidate.manifest.version
    }
}


/// Freshness/error readback from GET /v1/dataset/status (same device
/// credential as the dataset). Lets the app - and through it the
/// dashboard - show when the served dataset is behind the last
/// publish or the last activation failed, instead of the failure
/// living only in an operator log.
public struct DatasetStatus: Codable, Equatable {
    public struct Watcher: Codable, Equatable {
        public let generation: Int
        public let publishedGeneration: Int?
        /// true when the publication root advertises a generation the
        /// service has not activated (failed or in flight).
        public let behind: Bool
        /// Seconds since 1970 of the last successful activation.
        public let lastBuiltAt: Double?
        public let buildCount: Int
        public let lastError: String?
        enum CodingKeys: String, CodingKey {
            case generation, behind
            case publishedGeneration = "published_generation"
            case lastBuiltAt = "last_built_at"
            case buildCount = "build_count"
            case lastError = "last_error"
        }
    }
    public let servedGeneration: Int
    /// nil when the server runs without a publication watcher (manual
    /// operation only).
    public let watcher: Watcher?
    enum CodingKeys: String, CodingKey {
        case watcher
        case servedGeneration = "served_generation"
    }
}
