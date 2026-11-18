// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The full flow
// (managed config -> keychain -> server -> app-group store) has never
// run on an Apple device - see ios/README.md.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Read access to stored credentials. KeychainCredentialStore conforms
/// on Apple platforms (the conformance lives in
/// KeychainCredentialStore.swift, which imports Security and is not
/// part of the portable build); tests supply a fake.
public protocol CredentialReading {
    func read(key: String) throws -> String?
}

/// Orchestrates on-device filter data sync, using only the
/// configuration and credentials that actually exist:
///
/// 1. Explicit rules: GET /api/devices/{id}/filter-rules with the
///    guardian session cookie, bound to the current managed
///    configuration + tenant/device identity, written to the shared
///    FilterRuleStore the filter extension reads (monotonic
///    generations enforced by the store).
/// 2. Bloom prefilter: PrefilterUpdater against the url-filter-server
///    with the dataset-scoped device credential, persisted to the
///    app-group snapshot file for the iOS 26 URL Filter track.
///
/// LIFECYCLE / BINDING (fail closed; the extension drops traffic when
/// the store has no valid snapshot, so clearing NEVER weakens
/// filtering):
/// - 401/403 from the rules endpoint: the store is CLEARED and the
///   status sidecar records why; stale rules must not survive a
///   rejected session.
/// - Managed configuration change (endpoint hosts, tenant or device
///   identity): detected by config fingerprint; the old snapshot is
///   cleared before any new write so rules never cross an identity
///   boundary.
/// - Server reports no effective policy: stale rules are cleared.
///
/// Honesty rules: a missing managed configuration, missing session,
/// or missing dataset credential each produce a distinct state -
/// never a silent skip presented as success.
public final class FilterSyncController {
    public enum State: Equatable {
        case notConfigured(String)
        case signedOut
        case ready
        case syncing
        case synced(prefilterVersion: Int?, rulesGeneration: Int?)
        /// Sync ran but at least one result had no persistence
        /// destination (app-group container or prefilter file
        /// unavailable). NEVER reported as synced: nothing was
        /// installed, so nothing may claim otherwise.
        case persistenceUnavailable(String)
        /// AUTHORITATIVE invalidation: the server rejected the session
        /// or device identity, or the guardian signed out. The shared
        /// store was CLEARED; the extension fails closed. Distinct
        /// from .failed (transient), which never clears.
        case invalidated(String)
        case failed(String)
    }

    public private(set) var state: State
    /// UI hook: the app's @Observable wrapper mirrors state changes.
    /// Called from whichever task/queue syncNow runs on.
    public var onStateChange: ((State) -> Void)?

    private let configuration: AppConfiguration
    private let credentials: CredentialReading
    private let session: URLSession
    private let ruleStore: FilterRuleStore?
    private let prefilterFile: URL?

    public init(configuration: AppConfiguration,
                credentials: CredentialReading,
                session: URLSession = .shared,
                ruleStore: FilterRuleStore?,
                prefilterFile: URL?) {
        self.configuration = configuration
        self.credentials = credentials
        self.session = session
        self.ruleStore = ruleStore
        self.prefilterFile = prefilterFile
        // The prefilter destination is a lifecycle-owned artifact:
        /// invalidations remove it UNDER the store lock.
        if let prefilterFile {
            ruleStore?.registerArtifact(prefilterFile)
        }
        if let problem = Self.configurationProblem(configuration) {
            self.state = .notConfigured(problem)
        } else {
            self.state = .ready
            // Coherent bootstrap identity across app launches:
            // - no record: write the tenant-independent placeholder
            //   (fresh install fails closed without deadlocking sync);
            // - same endpoints+device: LEAVE the record alone - never
            //   overwrite a tenant-pinned identity with a placeholder
            //   (a plain app reopen must not invalidate the pinned
            //   snapshot);
            // - different endpoints/device: the managed configuration
            //   changed - clear rules, fail closed, re-bootstrap.
            // Mirror the managed configuration into the shared store
            // so the filter CONTROL provider (which cannot read the
            // app's com.apple.configuration.managed defaults) can run
            // the supported rule-maintenance sync itself.
            if let store = ruleStore {
                // INVALIDATED store (tombstone): the managed
                // configuration was removed/invalidated. Only the
                // app's atomic adoption may create a new mirror;
                // this instance touches NOTHING and stays inert.
                if store.isTombstoned() {
                    self.state = .notConfigured("awaiting configuration "
                        + "re-adoption")
                    return
                }
                if let mirrored = store.mirroredConfiguration(),
                   !FilterRuleStore.sameIdentity(mirrored, configuration) {
                    // STALE PROCESS: this instance holds an older
                    // managed configuration than the one adopted into
                    // the shared store. Touch NOTHING - a stale writer
                    // must never clear or resurrect the identity.
                    self.state = .notConfigured("configuration "
                        + "superseded by a newer configuration")
                    return
                }
                if store.mirroredConfiguration() == nil {
                    // First install only; a DIFFERENT existing mirror
                    // is the superseded case handled above.
                    try? store.mirrorConfiguration(configuration)
                }
                if let current = Self.bootstrap(for: configuration,
                                                tenantID: nil) {
                    switch store.readBootstrap() {
                    case .none:
                        try? store.saveBootstrap(current)
                    case .some(let existing):
                        if existing.endpointFingerprint
                            != current.endpointFingerprint {
                            // The mirror matches THIS configuration,
                            // so a mismatched bootstrap is damaged
                            // state, not a newer identity: clear
                            // (authority rotated) and re-pin. STRICT:
                            /// a partial clear must surface, never be
                            /// swallowed.
                            do {
                                try store.clear()
                                store.recordStatus("rules cleared: "
                                    + "identity record damaged")
                                try store.saveBootstrap(current)
                            } catch {
                                self.state = .persistenceUnavailable(
                                    "identity reset failed: \(error)")
                                return
                            }
                        }
                    }
                }
            }
        }
    }

    private func transition(_ next: State) {
        state = next
        onStateChange?(next)
    }

    /// Required keys for a sync: control plane URL (rules + session),
    /// dataset URL (prefilter) and device identity. Per-key detail
    /// comes from AppConfiguration.issues.
    public static func configurationProblem(_ config: AppConfiguration) -> String? {
        var missing: [String] = []
        if config.controlPlaneBaseURL == nil { missing.append("controlPlaneBaseURL") }
        if config.datasetBaseURL == nil { missing.append("datasetBaseURL") }
        if config.deviceID == nil { missing.append("deviceID") }
        guard missing.isEmpty else {
            // Source-neutral: the keys come from the MDM-managed
            // configuration on the managed lane, or from the
            // in-app personal setup on the personal lane.
            return "device configuration missing: "
                + missing.joined(separator: ", ")
        }
        return nil
    }

    /// Minimal infrastructure exception for the fail-closed state:
    /// EXACT, validated, lowercased endpoint hosts only. Without a
    /// tenant id the fingerprint covers the endpoints + device only;
    /// the post-sync rewrite pins the full identity.
    static func bootstrap(for config: AppConfiguration,
                          tenantID: Int?) -> FilterBootstrap? {
        guard let control = config.controlPlaneBaseURL,
              let dataset = config.datasetBaseURL,
              let deviceID = config.deviceID
        else { return nil }
        let endpointFP = FilterRuleStore.configFingerprint(
            controlPlane: control, dataset: dataset,
            doh: config.dohServerURL,
            tenantID: 0, deviceID: deviceID)
        let full = tenantID.map {
            FilterRuleStore.configFingerprint(
                controlPlane: control, dataset: dataset,
                doh: config.dohServerURL,
                tenantID: $0, deviceID: deviceID)
        } ?? endpointFP
        return FilterBootstrap(configFingerprint: full,
                               endpointFingerprint: endpointFP)
    }

    /// Clear the shared store and say why (status sidecar for the
    /// UI). Fail closed by construction: the extension drops traffic
    /// when no valid snapshot exists.
    ///
    /// expectedEpoch: when given, the invalidation runs ONLY if the
    /// durable epoch still equals the session's captured epoch,
    /// atomically under the store lock - a delayed error response
    /// from an old session can never clear a NEWER identity. Returns
    /// true when the invalidation actually ran.
    /// ALWAYS conditioned on the session's admitted authority and
    /// ALWAYS strict: there is no unconditional clear path (a missing
    /// or unbound credential must never wipe a store another session
    /// owns), and a failed marker write THROWS so the caller can
    /// surface persistenceUnavailable instead of pretending signedOut.
    @discardableResult
    private func invalidateStore(_ reason: String,
                                 expectedEpoch: String?) throws -> Bool {
        guard let store = ruleStore, let expectedEpoch
        else { return false }
        guard try store.invalidateIfCurrent(expectedEpoch: expectedEpoch)
        else { return false }
        store.recordStatus("rules cleared: \(reason)")
        return true
    }

    public func syncNow(now: Date = Date()) async {
        if case .syncing = state { return } // one sync at a time
        // Cancellation BEFORE any work: never fetch, never commit.
        // (Deterministically portable-tested; the mid-flight checks
        // below cover cancellation during network awaits on Apple
        // platforms.)
        guard !Task.isCancelled else {
            transition(.failed("sync cancelled"))
            return
        }
        guard let controlPlane = configuration.controlPlaneBaseURL,
              let datasetBase = configuration.datasetBaseURL,
              let deviceID = configuration.deviceID else {
            transition(.notConfigured(
                Self.configurationProblem(configuration) ?? "not configured"))
            return
        }
        // ADMISSION (single transactional authority check): the
        // mirrored-configuration identity and the durable session
        // nonce are captured under ONE store lock. A controller
        // holding a superseded configuration - whatever init's state
        /// label says - is refused BEFORE any network request, so it
        /// can never capture a current nonce and spend it with old
        /// credentials.
        let admittedEpoch: String?
        if let store = ruleStore {
            guard let nonce = store.admit(configuration: configuration)
            else {
                transition(.notConfigured("configuration superseded "
                    + "by a newer managed configuration"))
                return
            }
            admittedEpoch = nonce
        } else {
            admittedEpoch = nil
        }
        // The admitted nonce is this session's ONLY authority,
        // captured before ANY network request and never refreshed.
        /// Every commit, artifact install and invalidation re-checks
        /// it under the store lock.
        let sessionEpoch = admittedEpoch
        // Credentials live in ONE atomically-written bundle: a
        /// partially-written or mixed session/dataset pair cannot
        /// exist.
        let bundle = CredentialBundle.load(from: credentials)
        // AUTHORITY BINDING, BEFORE ANY REQUEST: the bundle must have
        // been committed under the nonce we just admitted. A bundle
        /// written in the rotation gap (sign-out/adoption between
        /// rotation and the vault write) is stale and never sent.
        /// (No ruleStore: no lifecycle authority exists to bind.)
        let authorityBound = sessionEpoch == nil
            || bundle?.authority == sessionEpoch
        guard authorityBound,
              let cookie = bundle?.session, !cookie.isEmpty else {
            // No session is an authoritative boundary (signed out or
            // never signed in on this launch): rules from any earlier
            // session must not keep filtering. CONDITIONAL + STRICT:
            // if the store cannot durably record the invalidation,
            // that is a persistence failure, not "signed out".
            do {
                _ = try invalidateStore(
                    bundle == nil ? "signed out"
                        : "stale credential authority",
                    expectedEpoch: sessionEpoch)
            } catch {
                transition(.persistenceUnavailable(
                    "rule-store invalidation failed: \(error)"))
                return
            }
            transition(.signedOut)
            return
        }
        // CREDENTIAL ORIGIN BINDING: a stored session/dataset
        // credential is only usable against the exact managed
        // configuration that minted it. The metadata key is written
        // by the sign-in flow; absent (legacy/unbound) or mismatched
        // metadata means the credential's origin cannot be proven -
        // fail closed and NEVER send the old bearer token to the
        // newly configured origin.
        let expectedOrigin = Self.bootstrap(for: configuration,
                                            tenantID: nil)?
            .endpointFingerprint
        func boundCredential(_ key: String) -> String? {
            guard let bundle else { return nil }
            switch key {
            case "session":
                return bundle.sessionOrigin == expectedOrigin
                    && !bundle.session.isEmpty ? bundle.session : nil
            case "credential.dataset":
                return bundle.datasetOrigin == expectedOrigin
                    && !bundle.datasetCredential.isEmpty
                    ? bundle.datasetCredential : nil
            default:
                return nil
            }
        }
        guard boundCredential("session") != nil else {
            do {
                _ = try invalidateStore(
                    "credential origin unbound or changed",
                    expectedEpoch: sessionEpoch)
            } catch {
                transition(.persistenceUnavailable(
                    "rule-store invalidation failed: \(error)"))
                return
            }
            transition(.signedOut)
            return
        }
        transition(.syncing)

        // 1. Explicit rules for the extension's list layer.
        var rulesGeneration: Int?
        var persistenceProblems: [String] = []
        do {
            let response = try await FilterRulesClient(
                baseURL: controlPlane, session: session)
                .fetch(deviceID: deviceID, sessionCookie: cookie)
            // EXPLICIT cancellation check IMMEDIATELY after the fetch
            // await, BEFORE apply() can commit: a stopFilter-
            // cancelled sync must not commit rules it fetched.
            // (Cancellation of the in-flight network call itself
            // surfaces as a normal fetch error above.)
            if Task.isCancelled {
                transition(.failed("sync cancelled before rules commit"))
                return
            }
            if let store = ruleStore {
                try apply(response: response, to: store,
                          deviceID: deviceID, now: now,
                          cookie: cookie,
                          expectedEpoch: sessionEpoch)
            } else {
                persistenceProblems.append(
                    "app-group rule store unavailable; "
                    + "fetched rules were NOT persisted")
            }
            rulesGeneration = response.hasEffectivePolicy
                ? response.generation : nil
        } catch FilterRulesClient.RulesError.unauthorized {
            do {
                _ = try invalidateStore("session rejected",
                                        expectedEpoch: sessionEpoch)
            } catch {
                transition(.persistenceUnavailable(
                    "rule-store invalidation failed: \(error)"))
                return
            }
            transition(.invalidated("session rejected; sign in again"))
            return
        } catch FilterRulesClient.RulesError.deviceNotFound {
            do {
                _ = try invalidateStore("device removed from account",
                                        expectedEpoch: sessionEpoch)
            } catch {
                transition(.persistenceUnavailable(
                    "rule-store invalidation failed: \(error)"))
                return
            }
            transition(.invalidated("device removed from account"))
            return
        } catch FilterRulesClient.RulesError.deviceInactive {
            do {
                _ = try invalidateStore("device is inactive",
                                        expectedEpoch: sessionEpoch)
            } catch {
                transition(.persistenceUnavailable(
                    "rule-store invalidation failed: \(error)"))
                return
            }
            transition(.invalidated("device is inactive"))
            return
        } catch FilterRuleStoreError.identityConflict {
            // The response's identity differs from the persisted one:
            // refuse to clear-and-rewrite (a delayed old response
            // would destroy a newer synced identity). Invalidate ONLY
            /// if this session is still the current authority.
            do {
                _ = try invalidateStore("device identity changed",
                                        expectedEpoch: sessionEpoch)
            } catch {
                transition(.persistenceUnavailable(
                    "rule-store invalidation failed: \(error)"))
                return
            }
            transition(.invalidated("device identity changed; "
                + "sign in again"))
            return
        } catch FilterRuleStoreError.staleSessionEpoch {
            // A sign-out/invalidation/config adoption landed while
            // the request was in flight; the newer authority already
            // cleared the store. Do NOT commit the stale response.
            transition(.invalidated("session superseded by a newer "
                + "configuration or sign-out"))
            return
        } catch {
            transition(.failed("rules sync failed: \(error)"))
            return
        }

        // 2. Bloom prefilter for the URL Filter track. A signed-in
        // guardian without a minted dataset credential is a real
        // intermediate state (sign-in happens first), surfaced as
        // failed-with-reason rather than silently skipped.
        guard let datasetToken = boundCredential("credential.dataset") else {
            transition(.failed("no dataset credential; sign in and "
                + "request a device credential first"))
            return
        }
        var prefilterVersion: Int?
        var updater = PrefilterUpdater(
            serverBaseURL: datasetBase,
            endpointFingerprint: expectedOrigin ?? "",
                                       session: session)
        if let file = prefilterFile,
           FileManager.default.fileExists(atPath: file.path) {
            // A corrupt cache must not block a fresh fetch: restore
            // failure just means a full download.
            try? updater.restore(from: file)
        }
        if prefilterFile == nil {
            persistenceProblems.append(
                "prefilter persistence unavailable; downloaded data "
                + "was NOT persisted")
        }
        // STAGED WRITE: the download lands in a scratch file first and
        // is moved to its destination ONLY by the same-epoch atomic
        // commit below - a sign-out/adoption landing mid-fetch must
        // not let this stale response recreate the old artifact.
        let stagingFile = prefilterFile?
            .deletingLastPathComponent()
            .appendingPathComponent(
                "prefilter-staging-\(UUID().uuidString).json")
        do {
            let manifest = try await updater.refresh(
                credential: datasetToken, persistTo: stagingFile,
                now: now)
            prefilterVersion = manifest.version
        } catch PrefilterUpdater.UpdateError.staleVersion {
            // Already current: report the restored active version.
            prefilterVersion = updater.currentVersion > 0
                ? updater.currentVersion : nil
        } catch PrefilterUpdater.UpdateError.unauthorized {
            // The device's dataset credential was rejected: the device
            // identity is no longer accepted. Fail closed EVERYWHERE -
            // but CONDITIONALLY: a delayed rejection from an old
            // session must not clear a NEWER identity.
            do {
                _ = try invalidateStore("device credential rejected",
                                        expectedEpoch: sessionEpoch)
            } catch {
                if let stagingFile {
                    try? FileManager.default.removeItem(at: stagingFile)
                }
                transition(.persistenceUnavailable(
                    "rule-store invalidation failed: \(error)"))
                return
            }
            if let stagingFile {
                try? FileManager.default.removeItem(at: stagingFile)
            }
            transition(.invalidated("device credential rejected; "
                + "sign in and request a new credential"))
            return
        } catch {
            if let stagingFile {
                try? FileManager.default.removeItem(at: stagingFile)
            }
            transition(.failed("prefilter sync failed: \(error)"))
            return
        }
        guard persistenceProblems.isEmpty else {
            transition(.persistenceUnavailable(
                persistenceProblems.joined(separator: "; ")))
            return
        }
        // Final authority check + staged-artifact commit, atomically
        // under the store lock: the epoch must not have advanced
        // since the session started (sign-out / invalidation /
        // configuration adoption during the dataset phase), and the
        // staged prefilter only becomes durable in that case.
        // EXPLICIT cancellation check before the artifact commit.
        if Task.isCancelled {
            if let stagingFile {
                try? FileManager.default.removeItem(at: stagingFile)
            }
            transition(.failed("sync cancelled before artifact commit"))
            return
        }
        if let store = ruleStore {
            if let stagingFile,
               FileManager.default.fileExists(atPath: stagingFile.path),
               let destination = prefilterFile, let sessionEpoch {
                do {
                    try store.commitArtifact(from: stagingFile,
                                             to: destination,
                                             expectedEpoch: sessionEpoch)
                } catch FilterRuleStoreError.staleSessionEpoch {
                    try? FileManager.default.removeItem(at: stagingFile)
                    transition(.invalidated("session superseded by a "
                        + "newer configuration or sign-out"))
                    return
                } catch {
                    try? FileManager.default.removeItem(at: stagingFile)
                    transition(.persistenceUnavailable(
                        "prefilter commit failed: \(error)"))
                    return
                }
            } else if store.currentEpoch() != sessionEpoch {
                if let stagingFile {
                    try? FileManager.default.removeItem(at: stagingFile)
                }
                transition(.invalidated("session superseded by a newer "
                    + "configuration or sign-out"))
                return
            }
        }
        transition(.synced(prefilterVersion: prefilterVersion,
                           rulesGeneration: rulesGeneration))
    }

    /// Persist the fetched rules with full identity binding. Throws on
    /// any contract violation; the caller maps those to .failed (or
    /// .invalidated for a stale session).
    @discardableResult
    private func apply(response: FilterRulesClient.RulesResponse,
                       to store: FilterRuleStore,
                       deviceID: Int, now: Date,
                       cookie: String,
                       expectedEpoch: String?) throws -> String? {
        let tenantID = response.tenantID
        let fingerprint = FilterRuleStore.configFingerprint(
            controlPlane: configuration.controlPlaneBaseURL!,
            dataset: configuration.datasetBaseURL!,
            doh: configuration.dohServerURL,
            tenantID: tenantID, deviceID: deviceID)
        // Identity boundary: NEVER clear-and-rewrite here. The
        // captured epoch is this session's only authority; refreshing
        // it after a local clear would let a delayed OLD response
        // destroy a NEWER fully-synced identity and install itself.
        // A persisted snapshot whose identity differs from the
        // response's identity is refused outright - only the app's
        // atomic adoption path may switch identity.
        // A CORRUPT persisted file throws on load (try? -> nil): the
        // store's locked recovery path verifies the fresh snapshot
        // against the current bootstrap identity and floor instead.
        let epoch = expectedEpoch
        if let persisted = try? store.load(),
           persisted.configFingerprint != fingerprint {
            throw FilterRuleStoreError.identityConflict
        }
        guard let boot = Self.bootstrap(for: configuration,
                                        tenantID: tenantID)
        else { return expectedEpoch }
        // The response arrived AFTER an awaited network round-trip:
        // re-read the session credential. If sign-out raced us, the
        // stored cookie changed (or vanished) and this response is
        // stale - never commit it.
        guard CredentialBundle.load(from: credentials)?.session
            == cookie else {
            throw FilterRuleStoreError.staleSessionEpoch
        }
        let snapshot = response.hasEffectivePolicy
            ? FilterRuleSnapshot(
                generation: response.generation,
                policyID: response.policyID,
                defaultPolicy: response.defaultPolicy,
                rules: response.rules,
                tenantID: tenantID,
                deviceID: deviceID,
                configFingerprint: fingerprint,
                fetchedAt: now)
            : nil
        if let epoch {
            // Epoch check + bootstrap + rules commit under ONE lock.
            try store.commit(snapshot: snapshot, bootstrap: boot,
                             expectedEpoch: epoch)
        } else {
            try store.saveBootstrap(boot)
            if let snapshot {
                try store.save(snapshot)
            } else {
                try store.clear()
            }
        }
        store.recordStatus(snapshot != nil
            ? "rules synced generation=\(response.generation)"
            : "rules cleared: no effective policy")
        return epoch
    }
}

/// Bounded-rate maintenance policy for the filter CONTROL provider's
/// rule-database upkeep (Apple's documented maintenance role: the
/// control provider maintains the on-disk rules the data provider
/// reads). Pure computation, portable-XCTested; the provider wires
/// it with a dispatch timer (hardware behavior UNVERIFIED).
public enum MaintenancePolicy {
    /// Routine re-check cadence. Hourly is enough: rule generations
    /// carry an expiry horizon, and more frequent polling from every
    /// device would hammer the control plane.
    public static let routineInterval: TimeInterval = 3600
    /// First retry after a failed sync.
    public static let minBackoff: TimeInterval = 300
    /// Backoff never exceeds the routine interval.
    public static let maxBackoff: TimeInterval = 3600

    /// Delay until the next maintenance sync. After a success
    /// (failures == 0): the routine interval. After consecutive
    /// failures: exponential backoff doubling from 5 minutes, capped
    /// at the routine interval - bounded rate in every state, so the
    /// maintenance loop can never storm the server.
    public static func nextInterval(failures: Int) -> TimeInterval {
        guard failures > 0 else { return routineInterval }
        let shift = min(failures - 1, 10)
        let backoff = minBackoff * pow(2.0, Double(shift))
        return min(backoff, maxBackoff)
    }
}
