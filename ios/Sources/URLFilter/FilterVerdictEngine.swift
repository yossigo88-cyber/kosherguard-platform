// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The providers
// that embed it are UNCOMPILED (no Apple SDK) - see ios/README.md.
import Foundation

/// The on-device filtering decision core, shared by the filter-data
/// and filter-control providers. THREAD-SAFE: providers may receive
/// concurrent flow callbacks; every public entry point serializes on
/// an internal lock.
///
/// FAILURE MODEL (fail closed, NO exceptions):
/// - notReady: no valid, current, identity-bound snapshot exists -
///   or the identity record itself is missing. EVERY identified host
///   is BLOCKED. There is deliberately no infrastructure-host
///   exception: review rejected it as a broad bypass (all
///   apps/ports/protocols to the configured host). Rule sync runs on
///   the supported channel instead: the filter CONTROL provider
///   maintains the rules database (Apple, NEFilterControlProvider),
///   outside the data provider's filtered flow path.
///   Hostless flows fail closed at the caller.
/// - ready: verdicts come from the current snapshot (engine order:
///   explicit allow beats block, then suffix-matched blocks). The
///   snapshot's defaultPolicy is ENFORCED for unmatched hosts:
///   defaultPolicy "block" blocks them; "allow" lets them past THIS
///   layer (the DNS layer remains the system-wide policy engine) -
///   but ONLY with a valid, current, identity-bound snapshot in hand.
/// - degraded: the on-disk snapshot turned corrupt/unreadable while a
///   previously loaded snapshot is still inside its OWN expiry window
///   and identity binding. The last-known-good rules stay in force
///   until that window closes; corruption never extends a snapshot's
///   life and never crosses a tenant/device/config boundary.
///
/// FRESHNESS: the providers call reloadIfChanged on every flow; the
/// file stamp (mtime + size + inode) catches atomic replacements, so
/// rules written by an app sync apply to new flows immediately.
final class FilterVerdictEngine {

    enum Readiness: Equatable {
        case notReady(reason: String)
        case ready(generation: Int)
        case degraded(generation: Int, reason: String)
    }

    enum Verdict: Equatable {
        case allow
        case block
        /// No host to match - only the control provider can answer.
        case askControl
    }

    /// A snapshot older than this is expired and never applied.
    /// Policy choice (7 days): bounded staleness for the explicit-rule
    /// layer while tolerating ordinary offline periods; the app
    /// re-syncs far more often in normal operation. Revocation and
    /// identity changes are handled by clearing/binding, not expiry.
    static let maxSnapshotAge: TimeInterval = 7 * 24 * 3600

    private let store: FilterRuleStore
    private let lock = NSLock()
    private var rules: [String: Bool] = [:]
    /// defaultPolicy of the in-force snapshot; enforced for unmatched
    /// hosts so a persisted "block" default is never silently ignored.
    private var defaultBlock = false
    private var lkg: FilterRuleSnapshot?   // last-known-good snapshot
    /// The lifecycle-authority nonce the in-memory policy was
    /// committed under. Checked PER FLOW: a rotated invalidation
    /// marker revokes loaded policy immediately, even when the
    /// snapshot file's deletion failed or never ran and no reload
    /// has happened yet.
    private var loadedAuthority: String?
    private var readiness: Readiness = .notReady(reason: "never loaded")
    private var lastStamp: FilterRuleStore.FileStamp?
    private var lastBootstrapStamp: FilterRuleStore.FileStamp?
    private var lastEpochStamp: FilterRuleStore.FileStamp?
    private var stampKnown = false
    private var bootstrap: FilterBootstrap?

    init(store: FilterRuleStore) {
        self.store = store
        self.bootstrap = store.readBootstrap()
    }

    func currentReadiness() -> Readiness {
        lock.lock()
        defer { lock.unlock() }
        return readiness
    }

    /// Re-read the store when the file changed (mtime+size+inode).
    /// Returns true when the in-memory rules were reloaded from disk.
    @discardableResult
    func reloadIfChanged(now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let stamp = store.snapshotStamp()
        let bootStamp = store.bootstrapStamp()
        let epochStamp = store.epochStamp()
        // ALL THREE files participate in change detection: a
        // bootstrap / managed-config change alone must invalidate
        // loaded policy even when the snapshot file itself is
        // untouched, and a rotated lifecycle-authority marker must
        // revoke a snapshot whose deletion failed or never ran (the
        // envelope authority check in load() does the revoking).
        if stampKnown && stamp == lastStamp
            && bootStamp == lastBootstrapStamp
            && epochStamp == lastEpochStamp {
            return false // unchanged; expiry is checked per verdict
        }
        stampKnown = true
        lastStamp = stamp
        lastBootstrapStamp = bootStamp
        lastEpochStamp = epochStamp
        bootstrap = store.readBootstrap()
        reloadLocked(now: now)
        return true
    }

    /// Per-flow verdict. Expiry is evaluated on every call, so an
    /// aging snapshot flips to fail-closed even with zero disk events.
    func verdict(forHost rawHost: String?, now: Date = Date()) -> Verdict {
        lock.lock()
        defer { lock.unlock() }
        guard let host = FilterRuleStore.normalizedHost(rawHost) else {
            return .askControl
        }
        enforceExpiryLocked(now: now)
        // AUTHORITY PIN, per flow: loaded policy is valid only while
        // the store's lifecycle authority still equals the nonce the
        // policy was committed under. Marker-first invalidation with
        // a FAILED identity-file delete is still fully revoking.
        guard let authority = loadedAuthority,
              store.currentEpoch() == authority
        else { return .block }
        switch readiness {
        case .notReady:
            return .block // fail closed, no exceptions
        case .ready, .degraded:
            switch FilterRuleStore.verdict(for: host, in: rules) {
            case .some(true): return .block
            case .some(false): return .allow
            case .none: return defaultBlock ? .block : .allow
            }
        }
    }

    /// Whether the engine holds a valid, current snapshot (used by the
    /// control provider to answer hostless flows).
    var isReady: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let authority = loadedAuthority,
              store.currentEpoch() == authority
        else { return false }
        switch readiness {
        case .ready, .degraded: return true
        case .notReady: return false
        }
    }

    // MARK: - Internals (lock held)

    private func reloadLocked(now: Date) {
        do {
            // Missing identity record: reject outright. A snapshot
            // without its current binding must never be applied, and
            // no LKG may survive it.
            guard let bootstrap else {
                rules = [:]
                defaultBlock = false
                lkg = nil
                readiness = .notReady(reason: "no identity record")
                return
            }
            guard let loaded = try store.loadWithAuthority() else {
                // No snapshot: a cleared store means intentionally no
                // policy (401, identity change, no effective policy) or
                // a fresh install. Fail closed - and drop any
                // last-known-good: a cleared store is an explicit
                // boundary, not a transient read error.
                rules = [:]
                defaultBlock = false
                lkg = nil
                loadedAuthority = nil
                readiness = .notReady(reason: "no rules synced")
                return
            }
            let snapshot = loaded.snapshot
            // Identity boundary: the bootstrap the app wrote for the
            // CURRENT managed configuration must match the snapshot's
            // binding. A config change without an app-side clear still
            // cannot leak old rules into a new identity.
            if let fp = snapshot.configFingerprint,
               fp != bootstrap.configFingerprint {
                rules = [:]
                defaultBlock = false
                lkg = nil
                readiness = .notReady(reason: "configuration changed")
                return
            }
            if isExpired(snapshot, now: now) {
                rules = [:]
                defaultBlock = false
                lkg = nil
                readiness = .notReady(reason: "rules expired")
                return
            }
            rules = snapshot.rules
            defaultBlock = snapshot.defaultPolicy == "block"
            lkg = snapshot
            loadedAuthority = loaded.authority
            readiness = .ready(generation: snapshot.generation)
        } catch FilterRuleStoreError.invalidSnapshot {
            // REVOCATION, not a read error: the lifecycle authority
            // rotated (invalidation) or the snapshot is invalid. LKG
            // must NOT survive it - the store explicitly rejected
            // this content under the current authority.
            rules = [:]
            defaultBlock = false
            lkg = nil
            loadedAuthority = nil
            readiness = .notReady(
                reason: "policy revoked or invalid")
        } catch FilterRuleStoreError.unreadableSnapshot {
            // Read failure is DISTINCT from corruption: the file is
            // present but cannot be read (permissions, protection
            // class, I/O). Same fail-safe policy: last-known-good
            // only inside its own expiry window, else fail closed.
            applyReadFailure(reason: "rules unreadable", now: now)
        } catch {
            applyReadFailure(reason: "corrupt rules", now: now)
        }
    }

    /// Lock held. A read failure never extends a snapshot's life and
    /// never crosses an identity boundary: only the in-memory
    /// last-known-good (already bound and unexpired) may carry over.
    private func applyReadFailure(reason: String, now: Date) {
        // The last-known-good must still match the CURRENT bootstrap
        // identity: after a configuration switch an old LKG is never
        // reused, even while the new snapshot is corrupt/unreadable.
        let identityCurrent = bootstrap != nil
            && lkg?.configFingerprint == bootstrap?.configFingerprint
        if let good = lkg, !isExpired(good, now: now), identityCurrent {
            rules = good.rules
            defaultBlock = good.defaultPolicy == "block"
            readiness = .degraded(
                generation: good.generation,
                reason: "\(reason); using last-known-good")
        } else {
            rules = [:]
            defaultBlock = false
            readiness = .notReady(reason: reason)
        }
    }

    private func enforceExpiryLocked(now: Date) {
        guard let current = lkg, isExpired(current, now: now) else { return }
        rules = [:]
        defaultBlock = false
        lkg = nil
        readiness = .notReady(reason: "rules expired")
    }

    private func isExpired(_ snapshot: FilterRuleSnapshot, now: Date) -> Bool {
        guard let fetched = snapshot.fetchedAt else { return false }
        return now.timeIntervalSince(fetched) > Self.maxSnapshotAge
    }

}
