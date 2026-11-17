// STATUS: UNCOMPILED, UNSIGNED, UNTESTED ON APPLE PLATFORMS.
// NEURLFilterControlProvider / NEURLFilterPrefilter symbols are
// written against Apple's iOS 26 URL Filter documentation
// (developer.apple.com/documentation/networkextension/url-filters and
// NEURLFilterControlProvider fetchPrefilter(existingPrefilterTag:),
// read 2026-11-17); no Apple SDK has compiled this file. All decision
// logic lives in URLFilterPrefilterSource, which IS compiled and
// XCTested portably - see ios/README.md.
import NetworkExtension
import Foundation

/// The URL Filter control provider: the system asks this extension
/// for the Bloom prefilter at `prefilterFetchInterval` cadence.
///
/// The prefilter NEVER comes from a network fetch inside this
/// callback: it is read from the validated, identity-bound artifact
/// the rule sync already persisted (PrefilterUpdater verified the
/// manifest hash and Apple-format parameters at download time, and
/// URLFilterPrefilterSource re-validates them here). If the artifact
/// is missing, foreign, corrupt or unchanged, the behavior follows
/// Apple's contract:
///
/// - Initial fetch (existingPrefilterTag == nil) with no valid
///   artifact: throw. The system gets NO prefilter; with
///   `shouldFailClosed = true` (URLFilterConfiguration) filtering does
///   not silently open. Retries are the system's cadence.
/// - Subsequent fetch with an unchanged artifact: return nil -
///   Apple's documented "no update necessary" signal.
///
/// PACKAGING: this class is compiled into the SAME control-provider
/// extension target as FilterControlProvider
/// (com.apple.networkextension.filter-control extension point);
/// `NEURLFilterManager.setConfiguration(...controlProviderBundleIdentifier:)`
/// points at that target's bundle identifier.
@available(iOS 26.0, *)
final class URLFilterControlProvider: NEURLFilterControlProvider {

    /// Where the sync persists the prefilter snapshot, relative to
    /// the shared app-group store.
    private static func artifactURL() -> URL? {
        FilterRuleStore.appGroupStore()?.configurationFile
            .deletingLastPathComponent()
            .appendingPathComponent("prefilter-snapshot.json")
    }

    /// Apple: "The system calls this method at the frequency specified
    /// by prefilterFetchInterval." "The initial fetch must return a
    /// non-nil Bloom filter." "Returning nil for subsequent fetches
    /// indicates no change."
    override func fetchPrefilter(
        existingPrefilterTag: String?
    ) async throws -> NEURLFilterPrefilter? {
        guard let store = FilterRuleStore.appGroupStore(),
              let artifactURL = Self.artifactURL(),
              let configuration = store.mirroredConfiguration(),
              let fingerprint = FilterSyncController.bootstrap(
                  for: configuration, tenantID: nil)?.endpointFingerprint
        else {
            // Not configured or no shared store: fail closed. There
            // is no configuration-free prefilter we could serve.
            throw NSError(domain: "com.kosherguard.urlfilter",
                          code: 1,
                          userInfo: [NSLocalizedDescriptionKey:
                "URL Filter prefilter unavailable: not configured"])
        }
        let source = URLFilterPrefilterSource(
            artifactFile: artifactURL,
            endpointFingerprint: fingerprint)
        guard let artifact = source.load(existingTag: existingPrefilterTag)
        else {
            if existingPrefilterTag != nil {
                return nil // unchanged (or gone: system keeps current)
            }
            throw NSError(domain: "com.kosherguard.urlfilter",
                          code: 2,
                          userInfo: [NSLocalizedDescriptionKey:
                "URL Filter prefilter unavailable: no valid synced dataset"])
        }
        // The artifact is small (sized for the corpus at ~0.1% FP);
        // hand the bytes directly. Apple's alternative
        // (temporaryFilepath) is for very large filters.
        return NEURLFilterPrefilter(
            data: .bytes(artifact.data),
            tag: artifact.tag,
            bitCount: artifact.bitCount,
            hashCount: artifact.hashCount,
            murmurSeed: artifact.murmurSeed)
    }
}
