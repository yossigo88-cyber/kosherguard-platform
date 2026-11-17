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

    /// Load and fully validate the artifact, or nil (fail closed).
    /// `existingTag` is the system's current prefilter tag: when it
    /// matches the artifact's tag the system needs no update and the
    /// caller returns nil-for-no-change instead.
    func load(existingTag: String? = nil) -> Artifact? {
        guard let raw = try? Data(contentsOf: artifactFile),
              let snapshot = try? JSONDecoder().decode(
                  PrefilterUpdater.Snapshot.self, from: raw),
              !endpointFingerprint.isEmpty,
              snapshot.endpointFingerprint == endpointFingerprint,
              snapshot.manifest.version > 0,
              let params = try? snapshot.manifest.appleParameters(),
              snapshot.prefilter.count == params.byteCount
        else { return nil }
        let digest = SHA256.hash(data: snapshot.prefilter)
            .map { String(format: "%02x", $0) }.joined()
        guard digest == params.sha256 else { return nil }
        guard existingTag != params.sha256 else { return nil }
        return Artifact(data: snapshot.prefilter,
                        tag: params.sha256,
                        bitCount: params.bitCount,
                        hashCount: params.hashCount,
                        murmurSeed: params.murmurSeed,
                        datasetVersion: snapshot.manifest.version)
    }
}
