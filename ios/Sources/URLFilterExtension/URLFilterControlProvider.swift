// STATUS: UNCOMPILED, UNSIGNED, UNTESTED ON APPLE PLATFORMS.
// NEURLFilterControlProvider / NEURLFilterPrefilter symbols are
// written against Apple's documentation: NEURLFilterControlProvider
// is a PROTOCOL conforming to AppExtension (apple-docs mirror of
// developer.apple.com/documentation/networkextension/
// neurlfiltercontrolprovider, read 2026-11-17), implemented as the
// extension's entry point per WWDC25 session 234 and Apple's
// pir-service-example TestingInstructionsNEURLFilter.md. No Apple
// SDK has compiled this file. All decision logic lives in
// URLFilterPrefilterSource, which IS compiled and XCTested portably.
//
// PACKAGING (corrected in review): this provider is the entry point
// of its OWN app-extension target (KosherGuardURLFilter), created in
// Xcode from the "URL Filter app extension template". It is NOT part
// of the NEFilterControlProvider extension - a principal class can
// only conform to one extension contract.
// NEURLFilterManager.setConfiguration(...controlProviderBundleIdentifier:)
// in URLFilterConfiguration points at THIS target's bundle ID.
import NetworkExtension
import Foundation

/// The URL Filter control provider: the system asks this extension
/// for the Bloom prefilter at `prefilterFetchInterval` cadence.
///
/// The prefilter NEVER comes from a network fetch inside this
/// callback: it is read from the validated, identity-bound artifact
/// the rule sync already persisted (PrefilterUpdater verified the
/// manifest hash and Apple-format parameters at download time, and
/// URLFilterPrefilterSource re-validates them here). Behavior
/// follows Apple's contract plus fail-closed:
///
/// - Any fetch with NO VALID artifact (missing, foreign-identity,
///   corrupt, wrong format): throw, on initial AND subsequent
///   fetches. A stale artifact from a previous identity is never
///   silently retained as "unchanged". Revocation of the URL Filter
///   itself is the app lifecycle's job (KosherGuardApp disables the
///   filter when the managed configuration is invalidated or its PIR
///   pair disappears); this provider never serves stale data in the
///   meantime.
/// - Subsequent fetch whose tag matches the current valid artifact:
///   return nil - Apple's documented "no update necessary" signal.
/// Entry-point shape matches Apple's official "Filtering traffic by
/// URL" sample (SimpleURLFilterExtension, docs-assets.developer.apple.
/// com/published/ab6517c07cf8/FilteringTrafficByURL.zip, fetched
/// 2026-11-17): @main class with required init, protocol conformance
/// in an extension, EXAppExtensionAttributes in the Info.plist (no
/// NSExtensionPrincipalClass).
@available(iOS 26.0, *)
@main
class URLFilterControlProvider {

    required init() {
    }

    /// Where the sync persists the prefilter snapshot, relative to
    /// the shared app-group store (same location KosherGuardApp
    /// passes to FilterSyncController as prefilterFile).
    private static func artifactURL() -> URL? {
        FilterRuleStore.appGroupStore()?.snapshotFile
            .deletingLastPathComponent()
            .appendingPathComponent("prefilter-snapshot.json")
    }
}

@available(iOS 26.0, *)
extension URLFilterControlProvider: NEURLFilterControlProvider {

    func start() async throws {
        // No per-launch state; the artifact is read per fetch.
    }

    func stop(reason: NEProviderStopReason) async throws {
        // Nothing to tear down; no caches are held.
    }

    /// Apple: "The system calls this method at the frequency
    /// specified by prefilterFetchInterval." "The initial fetch must
    /// return a non-nil Bloom filter." "Returning nil for subsequent
    /// fetches indicates no change."
    func fetchPrefilter(
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
        switch source.loadResult(existingTag: existingPrefilterTag) {
        case .unchanged:
            return nil
        case .invalid:
            throw NSError(domain: "com.kosherguard.urlfilter",
                          code: 2,
                          userInfo: [NSLocalizedDescriptionKey:
                "URL Filter prefilter unavailable: no valid synced "
                + "dataset for the current identity"])
        case .artifact(let artifact):
            // The artifact is small (sized for the corpus at ~0.1%
            // FP), so it uses Apple's documented .smallFilter(Data)
            // case; .temporaryFilepath(URL) - the sample's choice -
            // is for very large filters.
            return NEURLFilterPrefilter(
                data: .smallFilter(artifact.data),
                tag: artifact.tag,
                bitCount: artifact.bitCount,
                hashCount: artifact.hashCount,
                murmurSeed: artifact.murmurSeed)
        }
    }
}
