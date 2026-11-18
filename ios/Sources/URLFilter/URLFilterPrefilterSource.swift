// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The
// NEURLFilterControlProvider adapter that consumes this is UNCOMPILED
// (no Apple SDK) - see ios/README.md.
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Reads the synced dataset prefilter artifact (written by
/// FilterSyncController through PrefilterUpdater) and hands the
/// system's URL Filter a VALIDATED parameter set.
///
/// Fail closed, always: a missing, corrupt, foreign-identity,
/// hash-mismatched or wrong-format artifact yields nil (the control
/// provider throws, the system keeps no prefilter, and with
/// shouldFailClosed = true filtering does not silently open).
///
/// Identity binding matches the rest of the store: the snapshot
/// records the endpoint fingerprint of the identity that downloaded
/// it; a foreign (or legacy, unbound) cache is refused so a previous
/// server's data can never be served as current policy.
struct URLFilterPrefilterSource {

    /// Everything NEURLFilterPrefilter needs, pre-validated.
    struct Artifact: Equatable {
        let data: Data
        /// SHA-256 of data - Apple's suggested tag ("such as the
        /// SHA-256 hash of the Bloom filter data").
        let tag: String
        let bitCount: Int
        let hashCount: Int
        let murmurSeed: UInt32
        let datasetVersion: Int
    }

    let artifactFile: URL
    /// The endpoint fingerprint of the CURRENT configuration
    /// identity; the artifact is bound to it.
    let endpointFingerprint: String

    init(artifactFile: URL, endpointFingerprint: String) {
        self.artifactFile = artifactFile
        self.endpointFingerprint = endpointFingerprint
    }

    /// A prefilter artifact older than this is refused at use time.
    /// Same policy choice as the explicit-rule layer
    /// (FilterVerdictEngine.maxSnapshotAge): background refresh is
    /// OS-DISCRETIONARY - the system is never obliged to wake the
    /// app - so freshness can never be a precondition enforced by a
    /// timer. When no refresh runs, enforcement fails closed at this
    /// horizon instead of filtering on unboundedly stale data.
    static let maxArtifactAge: TimeInterval = 7 * 24 * 3600
    /// Tolerance for device clock adjustments: a download timestamp
    /// slightly in the future is still accepted, but a far-future
    /// timestamp would pin the artifact's age near zero forever and
    /// is refused like any other unprovable freshness claim.
    static let futureTimestampTolerance: TimeInterval = 300

    /// Load and fully validate the artifact, or nil (fail closed).
    /// `existingTag` is the system's current prefilter tag: when it
    /// matches the artifact's tag the system needs no update and the
    /// caller returns nil-for-no-change instead.
    /// AGE is validated here, per use: `now` against the artifact's
    /// download timestamp. An expired artifact is .invalid, so the
    /// control provider fails closed (system keeps no prefilter with
    /// shouldFailClosed = true) rather than enforce stale policy.
    /// The tri-state the control provider needs: a valid artifact,
    /// an explicitly-unchanged tag (Apple's nil-for-no-change), or an
    /// INVALID state (missing, corrupt, foreign identity, wrong
    /// format, hash mismatch, expired or unprovable age). Callers
    /// must never collapse .invalid into "no change": that would
    /// silently retain a previous identity's prefilter as current
    /// policy.
    enum LoadResult: Equatable {
        case artifact(Artifact)
        case unchanged
        case invalid
    }

    func loadResult(existingTag: String? = nil,
                    now: Date = Date()) -> LoadResult {
        guard let raw = try? Data(contentsOf: artifactFile),
              let snapshot = try? JSONDecoder().decode(
                  PrefilterUpdater.Snapshot.self, from: raw),
              !endpointFingerprint.isEmpty,
              snapshot.endpointFingerprint == endpointFingerprint,
              snapshot.manifest.version > 0,
              let params = try? snapshot.manifest.appleParameters(),
              snapshot.prefilter.count == params.byteCount
        else { return .invalid }
        // Freshness at use time: within the expiry horizon, and not
        // dated implausibly far in the future.
        let age = now.timeIntervalSince(snapshot.fetchedAt)
        guard age <= Self.maxArtifactAge,
              age >= -Self.futureTimestampTolerance
        else { return .invalid }
        let digest = SHA256.hash(data: snapshot.prefilter)
            .map { String(format: "%02x", $0) }.joined()
        guard digest == params.sha256 else { return .invalid }
        guard existingTag != params.sha256 else { return .unchanged }
        return .artifact(Artifact(data: snapshot.prefilter,
                        tag: params.sha256,
                        bitCount: params.bitCount,
                        hashCount: params.hashCount,
                        murmurSeed: params.murmurSeed,
                        datasetVersion: snapshot.manifest.version))
    }

    /// Convenience for callers that only need pass/fail-closed:
    /// nil for BOTH unchanged and invalid. The control provider uses
    /// loadResult so it can fail closed on .invalid instead.
    func load(existingTag: String? = nil,
              now: Date = Date()) -> Artifact? {
        if case .artifact(let artifact) = loadResult(
            existingTag: existingTag, now: now) {
            return artifact
        }
        return nil
    }
}
