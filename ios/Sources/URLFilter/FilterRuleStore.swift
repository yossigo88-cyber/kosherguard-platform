// STATUS: portable logic (everything outside the #if canImport(Darwin)
// resolver) is compiled and XCTested with the real Swift toolchain on
// Linux - see tools/run-swift-portable-tests.sh and ios/README.md.
// The app-group container resolver itself is Apple-only, UNCOMPILED
// and UNTESTED: no Apple SDK, signing identity or device has run it.
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

/// One immutable generation of the on-device explicit filter rules.
///
/// `rules` maps a normalized host (lowercase, no trailing dot, no
/// scheme/port/path) to a verdict: true = block, false = explicit
/// allow. Matching follows the filtering engine's semantics
/// (filtering-engine/src/policy_engine.py): an explicit allow beats
/// every block, then blocks match by host-or-parent-suffix.
///
/// `generation` is monotonic within one `policyID` namespace (the
/// server exports the policy's version count). A switch to a
/// different policyID starts a new namespace and may replace the
/// persisted snapshot regardless of generation.
///
/// BINDING: `tenantID`, `deviceID` and `configFingerprint` bind the
/// snapshot to the identity and MDM-managed server configuration that
/// produced it; `fetchedAt` bounds its lifetime (see
/// FilterVerdictEngine.maxSnapshotAge). A snapshot must never be
/// applied across a tenant, device or server-configuration change.
public struct FilterRuleSnapshot: Codable, Equatable {
    public var generation: Int
    public var policyID: Int?
    public var defaultPolicy: String?
    public var rules: [String: Bool]
    public var tenantID: Int?
    public var deviceID: Int?
    public var configFingerprint: String?
    public var fetchedAt: Date?

    public init(generation: Int, policyID: Int?, defaultPolicy: String?,
                rules: [String: Bool], tenantID: Int? = nil,
                deviceID: Int? = nil, configFingerprint: String? = nil,
                fetchedAt: Date? = nil) {
        self.generation = generation
        self.policyID = policyID
        self.defaultPolicy = defaultPolicy
        self.rules = rules
        self.tenantID = tenantID
        self.deviceID = deviceID
        self.configFingerprint = configFingerprint
        self.fetchedAt = fetchedAt
    }
}

/// Identity record written by the APP or control provider (never the
/// data provider) so the filter can bind a snapshot to the managed
/// configuration + tenant + device that produced it.
///
/// DESIGN RESOLUTION (independent review): this record grants NO
/// network exception. An earlier draft exempted the exact
/// infrastructure hosts while no policy existed; review rejected it
/// because it let ALL apps/ports/protocols reach the configured host
/// unfiltered - a broad bypass, never approved. Rule synchronization
/// instead runs where Apple supports it: the filter CONTROL provider
/// maintains the rules database (Apple, NEFilterControlProvider:
/// "the Filter Control Provider can maintain a database of filtering
/// rules on disk in a location where the Filter Data Provider can
/// read from the database"), and that channel is outside the data
/// provider's filtered flow path. The data path therefore fails
/// closed with NO exceptions.
public struct FilterBootstrap: Codable, Equatable {
    /// Full identity binding (endpoints + tenant + device) when pinned
    /// by a successful sync; the tenant-0 placeholder before that.
    public var configFingerprint: String
    /// Tenant-INDEPENDENT endpoint+device fingerprint. The app uses it
    /// to detect a managed-configuration change WITHOUT overwriting a
    /// tenant-pinned record on every launch: same endpoints -> leave
    /// the pinned identity alone; different endpoints -> fail closed
    /// and re-bootstrap.
    public var endpointFingerprint: String

    public init(configFingerprint: String, endpointFingerprint: String) {
        self.configFingerprint = configFingerprint
        self.endpointFingerprint = endpointFingerprint
    }
}

public enum FilterRuleStoreError: Error, Equatable {
    /// File exists on disk but cannot be read at all (permissions,
    /// data-protection lock, I/O error). DISTINCT from absent: a
    /// caller must not collapse a read failure into "no snapshot".
    case unreadableSnapshot
    /// File exists but fails decode, integrity or validation.
    case corruptSnapshot
    /// Same policy namespace, lower generation than persisted.
    case staleGeneration
    /// A published generation is immutable: the write re-asserted a
    /// published generation with DIFFERENT content.
    case revisionConflict
    /// Same policy namespace, same generation, different content.
    case conflictingGeneration
    /// A staged artifact could not be atomically installed (rename
    /// failed); the PREVIOUS destination is preserved.
    case artifactInstallFailed
    /// Snapshot violates schema invariants (bad host key, bad
    /// generation, unknown defaultPolicy, bad binding fields).
    case invalidSnapshot
    /// The durable generation-floor file EXISTS but cannot be read
    /// or decoded. DISTINCT from absent: a corrupt floor must fail
    /// every write closed - treating it as "no floor" would permit
    /// a rollback past the highest revision ever persisted.
    case unreadableFloor
    /// The writer's session epoch is behind the store's durable
    /// epoch: a sign-out, invalidation or configuration adoption
    /// landed while its network requests were in flight. The stale
    /// response must NOT be committed.
    case staleSessionEpoch
    /// A stale process tried to overwrite the mirrored managed
    /// configuration with a different (older) one.
    case configurationSuperseded
    /// The persisted snapshot's identity differs from the identity a
    /// sync response claims. The sync path must NEVER clear-and-
    /// rewrite across identities (a delayed old response would
    /// destroy a newer synced identity); only the app's atomic
    /// adoption path may switch identity.
    case identityConflict
}

/// Shared, integrity-checked persistence for on-device filter rules.
///
/// WRITERS: the app (FilterSyncController) and, once its extension
/// target exists in Xcode, the filter-control provider. READERS: the
/// filter-data provider is strictly read-only against this store
/// (Apple's content-filter model: the data provider reads the
/// database; it does not maintain it).
///
/// The SHA-256 envelope detects corruption and torn writes; it is NOT
/// a signature - authenticity comes from the container being reachable
/// only by our app and extensions plus after-first-unlock data protection at rest.
/// Writes are atomic (single-file replace) so a crashed writer never
/// leaves a half-written generation.
public struct FilterRuleStore {
    public let directory: URL
    public var snapshotFile: URL {
        directory.appendingPathComponent("filter-rules.json")
    }
    public var bootstrapFile: URL {
        directory.appendingPathComponent("filter-bootstrap.json")
    }
    /// Device-local mirror of the control plane's application policy
    /// (including the personal-shield remote gate). Identity data:
    /// removed with every identity teardown so a signed-out or
    /// re-anchored device never keeps a stale gate.
    public var appPolicyMirrorFile: URL {
        directory.appendingPathComponent("app-policy.json")
    }
    /// Independent monotonic floor: survives corruption of the main
    /// snapshot file so a corrupt store can be safely replaced ONLY
    /// by a same-identity snapshot at or above the highest generation
    /// ever persisted for that identity (never a replayed older one).
    public var floorFile: URL {
        directory.appendingPathComponent("filter-rules-floor.json")
    }
    /// Small sidecar the APP writes so its own UI can surface honest
    /// state (e.g. a removed corrupt snapshot, a session rejection).
    public var statusFile: URL {
        directory.appendingPathComponent("filter-extension-status.json")
    }

    private struct Envelope: Codable {
        let sha256: String
        let snapshot: FilterRuleSnapshot
        /// The lifecycle-authority nonce this write was committed
        /// under. Readers require it to equal the store's CURRENT
        /// nonce: a rotated marker (invalidation) revokes every
        /// previously written snapshot even if its file deletion
        /// failed or never ran.
        let authority: String
    }

    public init(directory: URL) {
        self.directory = directory
    }

    #if canImport(Darwin)
    /// Must match all targets' entitlements
    /// (com.apple.security.application-groups). The name is a
    /// placeholder pending the real Apple Developer team/bundle IDs -
    /// see ios/README.md.
    public static let appGroupIdentifier = "group.com.kosherguard.shared"

    /// Resolve the shared App Group container. Returns nil when the
    /// entitlement/provisioning does not grant the group (the honest
    /// "persistence unavailable" state; callers must not fall back to
    /// a private container silently because the extension would then
    /// read a different file than the app writes).
    public static func appGroupStore(
        fileManager: FileManager = .default) -> FilterRuleStore? {
        guard let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier)
        else { return nil }
        return FilterRuleStore(directory: container)
    }
    #endif

    // MARK: - Host normalization and verdicts

    /// Normalize a host for rule storage/lookup. Returns nil for
    /// anything that is not a plain DNS name (schemes, ports, paths,
    /// credentials, whitespace, empty labels after dot-trimming).
    public static func normalizedHost(_ raw: String?) -> String? {
        guard var host = raw?.lowercased() else { return nil }
        while host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty,
              !host.contains("/"), !host.contains(" "),
              !host.contains("@"), !host.contains(":"),
              !host.hasPrefix("."),
              // No empty labels: "bad..example" is not a DNS name.
              host.split(separator: ".", omittingEmptySubsequences: false)
                  .allSatisfy({ !$0.isEmpty })
        else { return nil }
        return host
    }

    /// Engine-order verdict for a normalized host:
    /// 1. any matching explicit allow (host or parent suffix) -> allow
    /// 2. any matching block (host or parent suffix) -> block
    /// 3. nil (unknown - the layer contributes no verdict)
    public static func verdict(for host: String,
                               in rules: [String: Bool]) -> Bool? {
        for wanted in [false, true] {
            var candidate = host
            while true {
                if rules[candidate] == wanted { return wanted }
                guard let dot = candidate.firstIndex(of: ".") else { break }
                candidate = String(candidate[candidate.index(after: dot)...])
            }
        }
        return nil
    }

    // MARK: - Config fingerprint

    /// Full binding of a snapshot/bootstrap to the managed server
    /// configuration and identity that produced it. Covers ALL
    /// configured endpoints (control plane, dataset, DoH when
    /// present) plus tenant and device identity - changing any of
    /// them changes the fingerprint.
    public static func configFingerprint(controlPlane: URL,
                                         dataset: URL,
                                         doh: URL?,
                                         tenantID: Int,
                                         deviceID: Int) -> String {
        func normalized(_ url: URL) -> String {
            var s = (url.scheme?.lowercased() ?? "") + "://"
                + (url.host?.lowercased() ?? "")
            if let port = url.port, port != 443 { s += ":\(port)" }
            let path = url.path.hasSuffix("/") && url.path.count > 1
                ? String(url.path.dropLast()) : url.path
            if path != "/" { s += path }
            return s
        }
        let material = "v1\n" + normalized(controlPlane) + "\n"
            + normalized(dataset) + "\n"
            + (doh.map(normalized) ?? "-") + "\n"
            + String(tenantID) + "\n" + String(deviceID)
        return digestHex(Data(material.utf8))
    }

    // MARK: - Load / save

    /// Load the persisted snapshot, or nil when none was ever written.
    /// Throws corruptSnapshot for any unreadable, tampered or invalid
    /// content. Callers decide the degraded state; the data provider
    /// is read-only and never repairs the file itself.
    public func load() throws -> FilterRuleSnapshot? {
        try loadWithAuthority()?.snapshot
    }

    /// load() plus the exact lifecycle authority the snapshot was
    /// committed under, so an in-memory reader can PIN its policy to
    /// that authority and re-check it per flow (a rotated marker then
    /// revokes the loaded policy immediately, reload or not).
    func loadWithAuthority() throws
        -> (snapshot: FilterRuleSnapshot, authority: String)? {
        // Absent and unreadable are DIFFERENT states: contents(atPath:)
        // returns nil for both, so check existence first.
        guard FileManager.default.fileExists(atPath: snapshotFile.path)
        else { return nil }
        guard let data = FileManager.default.contents(
            atPath: snapshotFile.path)
        else { throw FilterRuleStoreError.unreadableSnapshot }
        // JSON must be valid UTF-8; check BEFORE decoding because
        // swift-corelibs-foundation's JSONDecoder traps (fatal error)
        // on non-UTF-8 input instead of throwing - a corrupt file must
        // never be able to crash the filter extension.
        guard String(data: data, encoding: .utf8) != nil else {
            throw FilterRuleStoreError.corruptSnapshot
        }
        let envelope: Envelope
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = Self.dateDecoding
            envelope = try decoder.decode(Envelope.self, from: data)
        } catch {
            throw FilterRuleStoreError.corruptSnapshot
        }
        let payload = try Self.canonicalBytes(envelope.snapshot)
        guard Self.digestHex(payload) == envelope.sha256 else {
            throw FilterRuleStoreError.corruptSnapshot
        }
        // AUTHORITY BINDING (reader side): the snapshot is only valid
        // under the lifecycle authority that committed it. A rotated
        /// or corrupt epoch record revokes it - readers never ignore
        /// the invalidation marker, even when identity-file deletion
        /// failed after the marker landed.
        guard envelope.authority == currentEpoch(),
              currentEpoch() != nil
        else { throw FilterRuleStoreError.invalidSnapshot }
        try Self.validate(envelope.snapshot)
        return (envelope.snapshot, envelope.authority)
    }

    /// Persist a new generation atomically.
    ///
    /// Monotonicity within a policy namespace: an older generation
    /// never replaces a newer one, and the same generation may only be
    /// rewritten with identical content (a replayed sync is a no-op,
    /// a mutated one is rejected). A different policyID is a new
    /// namespace and replaces freely. A different configFingerprint is
    /// NOT written here: the caller must clear() first so no reader
    /// ever observes a cross-identity mix.
    public func save(_ snapshot: FilterRuleSnapshot) throws {
        try Self.validate(snapshot)
        // Cross-process compare-and-replace: the generation check and
        // the write run under ONE flock, so a concurrent app and
        // control-provider write serialize and an older generation can
        // never overwrite a newer one (an atomic rename alone is last
        // -writer-wins, NOT monotonic).
        try withLockedStore {
            try saveLocked(snapshot)
        }
    }

    /// MUST be called inside withLockedStore.
    private func saveLocked(_ snapshot: FilterRuleSnapshot) throws {
        // DURABLE FLOOR, checked first and independent of the
        // snapshot file's policy namespace: published generations are
        // monotonic per identity ACROSS policies (the control plane's
        // published revision is tenant-wide), so a policy switch can
        // never roll the device back to a lower generation. A CORRUPT
        // floor fails the write closed - it is not "no floor".
        switch floorStatus() {
        case .corrupt:
            throw FilterRuleStoreError.unreadableFloor
        case .floor(let floor):
            if floor.configFingerprint == snapshot.configFingerprint {
                if snapshot.generation < floor.generation {
                    throw FilterRuleStoreError.staleGeneration
                }
                if snapshot.generation == floor.generation {
                    // IMMUTABLE PUBLISHED REVISION: the same
                    // generation under the same identity may only
                    // re-assert the IDENTICAL content (a freshness
                    // refresh). Any content change at a published
                    // generation - a different policyID, rules or
                    // default policy - is a conflict, never a write.
                    guard try Self.contentDigest(snapshot) == floor.digest
                    else {
                        throw FilterRuleStoreError.revisionConflict
                    }
                }
            }
        case .absent:
            break
        }
        var persisted: FilterRuleSnapshot?
        do {
            persisted = try load()
        } catch {
            // CORRUPTION RECOVERY: the persisted file carries no
            // trustworthy identity or generation. Replacement is
            // allowed ONLY by a fresh snapshot bound to the CURRENT
            // bootstrap identity (the app/control provider verified
            // it against an authenticated published response) AND
            // at/above the floor enforced above. A corrupt file can
            // never vouch for an identity switch.
            guard let boot = readBootstrap(),
                  snapshot.configFingerprint == boot.configFingerprint
            else { throw FilterRuleStoreError.invalidSnapshot }
            // A corrupt snapshot with an ABSENT floor has no
            // trustworthy monotonic history: nothing proves this
            // "fresh" response is not a rollback. Refuse recovery;
            /// the fail-closed path is re-adoption/re-sign-in.
            /// (A CORRUPT floor already threw unreadableFloor above.)
            guard case .floor = floorStatus()
            else { throw FilterRuleStoreError.invalidSnapshot }
            // Floor FIRST (durable highest revision), then envelope.
            try writeFloor(for: snapshot)
            try writeEnvelope(snapshot)
            return
        }
        if let persisted {
            if persisted.policyID == snapshot.policyID {
                if snapshot.generation < persisted.generation {
                    throw FilterRuleStoreError.staleGeneration
                }
                if snapshot.generation == persisted.generation {
                    // Same generation: immutable content must be
                    // identical EXCLUDING the fetch timestamp. A
                    // re-sync re-asserts the same generation and
                    // legitimately refreshes freshness (fetchedAt);
                    // a mutated body is still rejected.
                    var incoming = snapshot
                    var current = persisted
                    incoming.fetchedAt = nil
                    current.fetchedAt = nil
                    guard incoming == current else {
                        throw FilterRuleStoreError.conflictingGeneration
                    }
                    // Fall through to the write: refreshes fetchedAt
                    // for the same immutable content.
                }
            }
        }
        try writeFloor(for: snapshot)
        try writeEnvelope(snapshot)
    }

    /// Atomic session commit for the sync controller. The epoch check
    /// runs UNDER THE SAME LOCK as the writes: a sign-out,
    /// invalidation or configuration adoption that landed while the
    /// network requests were in flight advanced the durable epoch, the
    /// captured expectedEpoch no longer matches, and the stale
    /// response is refused instead of resurrecting the old identity.
    public func commit(snapshot: FilterRuleSnapshot?,
                       bootstrap: FilterBootstrap,
                       expectedEpoch: String) throws {
        if let snapshot { try Self.validate(snapshot) }
        try withLockedStore {
            guard currentEpoch() == expectedEpoch else {
                throw FilterRuleStoreError.staleSessionEpoch
            }
            try saveBootstrapLocked(bootstrap)
            if let snapshot {
                try saveLocked(snapshot)
            } else if FileManager.default.fileExists(
                atPath: snapshotFile.path) {
                // No effective policy: rules from an unassigned policy
                // must not keep filtering.
                try FileManager.default.removeItem(at: snapshotFile)
            }
        }
    }

    /// Remove the persisted snapshot (no-op when absent). Used when
    /// the session is rejected (401), the managed configuration or
    /// tenant/device identity changes, or the server reports no
    /// effective policy. Because the reader FAILS CLOSED when no
    /// snapshot exists, clearing never weakens filtering.
    public func clear() throws {
        try withLockedStore {
            // Invalidation marker FIRST: rotating the authority nonce
            /// before touching files means a failure part-way can only
            /// leave dead writers (their captured nonce is already
            /// invalid), never a usable old authority. All errors are
            /// strict - a "cleared" report on a partial state is a lie.
            try rotateEpochLocked()
            try removeIdentityFilesLocked()
            try removeArtifactsLocked()
        }
    }

    // MARK: - Invalidation tombstone

    public var tombstoneFile: URL {
        directory.appendingPathComponent("filter-tombstone.json")
    }

    struct Tombstone: Codable, Equatable {
        let reason: String
    }

    /// Durable distinction between FRESH INSTALL (nothing written
    /// yet) and INVALIDATED (managed config removed/invalid). Only
    /// the app's atomic adoption may clear it; a stale instance can
    /// never re-mirror or re-admit itself past a tombstone.
    public func isTombstoned() -> Bool {
        FileManager.default.fileExists(atPath: tombstoneFile.path)
    }

    /// MUST be called inside withLockedStore.
    private func writeTombstoneLocked(_ reason: String) throws {
        let data = try JSONEncoder().encode(Tombstone(reason: reason))
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        options.insert(.completeUntilFirstUserAuthentication)
        #endif
        try data.write(to: tombstoneFile, options: options)
    }

    // MARK: - Durable session epoch

    public var epochFile: URL {
        directory.appendingPathComponent("filter-epoch.json")
    }

    /// The session authority is a random NONCE, not a counter: a new
    /// nonce can never collide with one a stale writer captured, and
    /// there is no "reset to 1" failure mode. A corrupt/unreadable
    /// epoch file reads as nil and fails every epoch-gated operation
    /// closed.
    struct EpochRecord: Codable, Equatable {
        let nonce: String
    }

    /// The durable session-authority nonce. "" when none was ever
    /// written (fresh install), nil when the file EXISTS but is
    /// corrupt/unreadable.
    public func currentEpoch() -> String? {
        guard FileManager.default.fileExists(atPath: epochFile.path)
        else { return "" }
        guard let data = FileManager.default.contents(
            atPath: epochFile.path),
              String(data: data, encoding: .utf8) != nil,
              let record = try? JSONDecoder().decode(
                EpochRecord.self, from: data),
              !record.nonce.isEmpty
        else { return nil }
        return record.nonce
    }

    /// MUST be called inside withLockedStore. Strict: a failed write
    /// throws - invalidation is never reported on a partial state.
    private func rotateEpochLocked() throws {
        let data = try JSONEncoder().encode(
            EpochRecord(nonce: UUID().uuidString))
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        options.insert(.completeUntilFirstUserAuthentication)
        #endif
        try data.write(to: epochFile, options: options)
    }

    /// THE single lifecycle-admission transaction: under one lock,
    /// verify this configuration is the store's current authority
    /// (mirror identity) and return the durable session nonce the
    /// caller must present at every later commit. Returns nil when
    /// the configuration is superseded or the epoch record is
    /// corrupt - no network request may be made without admission.
    /// On a fresh install the initial nonce is established here.
    public func admit(configuration: AppConfiguration) -> String? {
        try? withLockedStore {
            // An invalidated (tombstoned) store admits NO ONE until
            // the app adopts a new configuration.
            guard !isTombstoned() else { return nil }
            // An EXACT, valid mirror is required: absent (post-
            // invalidation or pre-install) or different (stale
            // process) both refuse.
            guard let mirrored = mirroredConfiguration(),
                  Self.sameIdentity(mirrored, configuration)
            else { return nil }
            guard let nonce = currentEpoch() else { return nil }
            // "" (fresh install, never rotated) is a VALID authority:
            // content committed under it must stay valid for the
            // first sync session. Real rotations (sign-in, sign-out,
            // invalidation, adoption) replace it with a random nonce.
            return nonce
        }
    }

    /// Sign-in session rotation: a NEW authenticated session gets a
    /// NEW lifecycle authority, conditional on the attempt's captured
    /// nonce still being current (a concurrent sign-out, adoption or
    /// competing sign-in makes this attempt stale). Returns the new
    /// nonce, or nil when the attempt is no longer authoritative.
    public func rotateAuthority(expectedEpoch: String) -> String? {
        try? withLockedStore {
            guard currentEpoch() == expectedEpoch else { return nil }
            try rotateEpochLocked()
            return currentEpoch()
        } ?? nil
    }

    /// MUST be called inside withLockedStore.
    private func removeIdentityFilesLocked() throws {
        for file in [snapshotFile, floorFile, bootstrapFile,
                     appPolicyMirrorFile] {
            if FileManager.default.fileExists(atPath: file.path) {
                try FileManager.default.removeItem(at: file)
            }
        }
    }

    /// Conditional tombstone: clear ONLY if the durable epoch still
    /// equals the caller's captured session epoch, atomically under
    /// one lock. A delayed error response (401/404/409) from an old
    /// session can never clear a NEWER identity that a sign-in or
    /// adoption committed after the capture. Returns true when the
    /// invalidation ran.
    public func invalidateIfCurrent(expectedEpoch: String) throws -> Bool {
        try withLockedStore {
            guard currentEpoch() == expectedEpoch else { return false }
            // Marker first, then the identity files AND the prefilter
            // cache, all under this lock: a part-way failure leaves
            // dead writers, never a usable authority.
            try rotateEpochLocked()
            try removeIdentityFilesLocked()
            try removeArtifactsLocked()
            return true
        }
    }

    /// Commit a staged artifact (e.g. a freshly downloaded prefilter)
    /// to its destination ONLY if the captured epoch is still current,
    /// atomically under the store lock: a sign-out or adoption that
    /// landed while the bytes were in flight makes the commit fail,
    /// so a stale fetch can never recreate an old durable artifact
    /// after the invalidation removed it.
    public func commitArtifact(from staged: URL, to destination: URL,
                               expectedEpoch: String) throws {
        try withLockedStore {
            guard currentEpoch() == expectedEpoch else {
                throw FilterRuleStoreError.staleSessionEpoch
            }
            // ATOMIC REPLACE: rename(2) installs the staged artifact
            // atomically on the same filesystem - a failure preserves
            // the PREVIOUS destination instead of leaving nothing
            // behind (remove+move loses the old artifact between the
            // two steps). The controller stages into the destination's
            // own directory, so same-filesystem rename always holds.
            guard rename(staged.path, destination.path) == 0 else {
                throw FilterRuleStoreError.artifactInstallFailed
            }
        }
    }

    // MARK: - Monotonic floor

    struct GenerationFloor: Codable, Equatable {
        let configFingerprint: String
        let policyID: Int?
        let generation: Int
        /// Canonical digest of the published revision. A published
        /// generation is IMMUTABLE: a later snapshot re-asserting the
        /// same generation under the same identity must carry the
        /// identical content digest (freshness-only re-delivery); any
        /// identity-bound content change at the same generation is a
        /// conflict and is rejected. The digest lives HERE (not only
        /// in the envelope) so a corrupt snapshot file cannot take
        /// the immutable proof down with it.
        let digest: String
    }

    /// Three-way floor state: ABSENT (never written or cleared with
    /// its identity), a valid floor, or CORRUPT (exists but
    /// unreadable/undecodable/invalid). Corrupt is NOT absent: it
    /// fails writes closed.
    enum FloorStatus: Equatable {
        case absent
        case floor(GenerationFloor)
        case corrupt
    }

    func floorStatus() -> FloorStatus {
        guard FileManager.default.fileExists(atPath: floorFile.path)
        else { return .absent }
        guard let data = FileManager.default.contents(
            atPath: floorFile.path),
              String(data: data, encoding: .utf8) != nil,
              let floor = try? JSONDecoder().decode(
                GenerationFloor.self, from: data),
              Self.isHexDigest(floor.configFingerprint),
              Self.isHexDigest(floor.digest),
              floor.generation >= 1
        else { return .corrupt }
        return .floor(floor)
    }

    func readFloor() -> GenerationFloor? {
        if case .floor(let floor) = floorStatus() { return floor }
        return nil
    }

    /// Content digest for immutable-revision comparison. fetchedAt is
    /// EXCLUDED: a re-sync legitimately refreshes the fetch timestamp
    /// of an unchanged published revision, so freshness is not part
    /// of the immutable content.
    static func contentDigest(_ snapshot: FilterRuleSnapshot) throws
        -> String {
        var content = snapshot
        content.fetchedAt = nil
        return digestHex(try canonicalBytes(content))
    }

    /// NOT best-effort: the floor is the durable anti-rollback
    /// record. It is written BEFORE the envelope so an interruption
    /// can only leave the floor AHEAD of the snapshot (rejects
    /// replays; a fresh higher generation still recovers) - never
    /// behind it (which would lose the highest revision and permit
    /// rollback recovery). A failed floor write fails the save.
    private func writeFloor(for snapshot: FilterRuleSnapshot) throws {
        let floor = GenerationFloor(
            configFingerprint: snapshot.configFingerprint ?? "",
            policyID: snapshot.policyID,
            generation: snapshot.generation,
            digest: try Self.contentDigest(snapshot))
        let data = try JSONEncoder().encode(floor)
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        options.insert(.completeUntilFirstUserAuthentication)
        #endif
        try data.write(to: floorFile, options: options)
    }

    /// Serialize store mutations across processes (app + extensions)
    /// with an flock on a sibling lock file. flock is POSIX and
    /// available on both Linux (Glibc) and Apple platforms (Darwin);
    /// it is advisory, and every writer in this codebase goes through
    /// this path.
    /// flock is NOT reentrant across file descriptors even in one
    /// process, so instance-level recursion is tracked explicitly
    /// (reference box: the store is a struct). Nested calls on the
    /// same store skip the flock - they already run inside the
    /// outermost critical section; other instances and processes
    /// still serialize on the flock.
    final class LockState {
        let recursive = NSRecursiveLock()
        var depth = 0
        var artifacts: [URL] = []
    }
    let lockState = LockState()

    private func withLockedStore<T>(_ body: () throws -> T) throws -> T {
        lockState.recursive.lock()
        defer { lockState.recursive.unlock() }
        if lockState.depth > 0 {
            lockState.depth += 1
            defer { lockState.depth -= 1 }
            return try body()
        }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let lockURL = directory.appendingPathComponent("filter-rules.lock")
        let fd = open(lockURL.path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw FilterRuleStoreError.unreadableSnapshot }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else {
            throw FilterRuleStoreError.unreadableSnapshot
        }
        lockState.depth = 1
        defer {
            lockState.depth = 0
            flock(fd, LOCK_UN)
        }
        return try body()
    }

    /// Conditional session rotation AND the gated write of the new
    /// session's artifacts as ONE lifecycle transaction: the
    /// authority check, the rotation, and the caller's write all run
    /// under the same store lock, so a sign-out or adoption can never
    /// land between the rotation and the write. Returns nil when the
    /// expected authority is no longer current. Errors from the body
    /// propagate (strict): the rotation has already happened
    /// (marker-first), leaving NO usable credentials - fail closed.
    public func rotateAuthorityAndCommit(
        expectedEpoch: String,
        _ body: (String) throws -> Void
    ) throws -> String? {
        try withLockedStore {
            guard currentEpoch() == expectedEpoch else { return nil }
            try rotateEpochLocked()
            let nonce = currentEpoch()!
            try body(nonce)
            return nonce
        }
    }

    // MARK: - Lifecycle-owned artifacts (prefilter cache)

    /// The canonical prefilter cache path for this store.
    public var canonicalPrefilterFile: URL {
        directory.appendingPathComponent("prefilter-snapshot.json")
    }

    /// Register a non-canonical artifact path (the sync controller's
    /// configured prefilter destination) so lifecycle invalidations
    /// remove it UNDER THE SAME LOCK as the authority rotation - an
    /// old catch can never delete a new identity's committed cache.
    public func registerArtifact(_ url: URL) {
        lockState.recursive.lock()
        defer { lockState.recursive.unlock() }
        if !lockState.artifacts.contains(url) {
            lockState.artifacts.append(url)
        }
    }

    /// MUST be called inside withLockedStore. STRICT: a failed
    /// removal fails the lifecycle operation.
    private func removeArtifactsLocked() throws {
        for file in [canonicalPrefilterFile] + lockState.artifacts
        where FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.removeItem(at: file)
        }
    }

    /// Saves the app-policy mirror ONLY if the store's current
    /// identity still equals the fingerprint the policy was fetched
    /// under, atomically under the store lock. A fetch that was in
    /// flight across a sign-out or identity change loses the race:
    /// teardown removes the bootstrap under the same lock, so the
    /// stale save observes the missing/foreign identity and is
    /// dropped instead of resurrecting the old gate. Returns true
    /// when the mirror was written.
    public func saveAppPolicyMirrorIfCurrent(
        _ data: Data, endpointFingerprint: String
    ) throws -> Bool {
        try withLockedStore {
            guard !endpointFingerprint.isEmpty,
                  let boot = readBootstrap(),
                  boot.endpointFingerprint == endpointFingerprint
            else { return false }
            let tmp = appPolicyMirrorFile.appendingPathExtension("tmp")
            try data.write(to: tmp, options: .atomic)
            if FileManager.default.fileExists(
                atPath: appPolicyMirrorFile.path) {
                _ = try? FileManager.default.replaceItemAt(
                    appPolicyMirrorFile, withItemAt: tmp)
            }
            if FileManager.default.fileExists(atPath: tmp.path) {
                try FileManager.default.moveItem(
                    at: tmp, to: appPolicyMirrorFile)
            }
            return true
        }
    }

    // MARK: - Bootstrap (app writes, extension reads)

    public func saveBootstrap(_ bootstrap: FilterBootstrap) throws {
        try withLockedStore {
            try saveBootstrapLocked(bootstrap)
        }
    }

    /// MUST be called inside withLockedStore.
    private func saveBootstrapLocked(_ bootstrap: FilterBootstrap) throws {
        guard Self.isHexDigest(bootstrap.configFingerprint),
              Self.isHexDigest(bootstrap.endpointFingerprint)
        else { throw FilterRuleStoreError.invalidSnapshot }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        // completeUntilFirstUserAuthentication: filtering must keep
        // working on a LOCKED device; .completeFileProtection would
        // make the rules unreadable after lock and silently disable
        // this layer. Lock-time accessibility on real hardware is
        // UNVERIFIED (no device build) - documented in ios/README.md.
        options.insert(.completeUntilFirstUserAuthentication)
        #endif
        try JSONEncoder().encode(bootstrap).write(to: bootstrapFile,
                                                  options: options)
    }

    public func readBootstrap() -> FilterBootstrap? {
        guard let data = FileManager.default.contents(
            atPath: bootstrapFile.path),
              String(data: data, encoding: .utf8) != nil,
              let bootstrap = try? JSONDecoder().decode(
                FilterBootstrap.self, from: data),
              Self.isHexDigest(bootstrap.configFingerprint),
              Self.isHexDigest(bootstrap.endpointFingerprint)
        else { return nil }
        return bootstrap
    }

    // MARK: - Mirrored managed configuration (app writes, control provider reads)

    /// The app mirrors its (validated) managed configuration here so
    /// the filter CONTROL provider - which cannot read the app's
    /// com.apple.configuration.managed defaults - can run the
    /// supported rule-maintenance sync itself. Values only; secrets
    /// never pass through this file.
    public var configurationFile: URL {
        directory.appendingPathComponent("managed-config.json")
    }

    private struct MirroredConfiguration: Codable {
        let controlPlaneBaseURL: String?
        let datasetBaseURL: String?
        let dohServerURL: String?
        let deviceID: Int?
    }

    /// Best-effort mirror write; a status note must not break the app.
    /// First-install mirror write only. Writing is refused (throwing
    /// configurationSuperseded) when a DIFFERENT configuration is
    /// already mirrored: switching identity must go through
    /// adoptConfiguration so the epoch advance and the identity
    /// clear are atomic with the mirror write, and a stale process
    /// holding an older managed configuration can never overwrite
    /// the current one.
    public func mirrorConfiguration(_ config: AppConfiguration) throws {
        try withLockedStore {
            if let existing = mirroredConfiguration(),
               !Self.sameIdentity(existing, config) {
                throw FilterRuleStoreError.configurationSuperseded
            }
            try writeMirrorLocked(config)
        }
    }

    /// The ONLY supported configuration switch. Under ONE lock: the
    /// durable epoch advances (every in-flight sync of the old
    /// session becomes stale), the old identity's rules/floor/
    /// bootstrap are removed, and the new mirror is written.
    public func adoptConfiguration(_ config: AppConfiguration) throws {
        try withLockedStore {
            try rotateEpochLocked()
            try removeIdentityFilesLocked()
            try removeArtifactsLocked()
            try writeMirrorLocked(config)
            // The app is the only authority that may lift a
            // tombstone, and only with a valid new configuration.
            // LAST and strict: a failure leaves the tombstone in
            // place (fail closed), never a half-adopted state.
            if FileManager.default.fileExists(atPath: tombstoneFile.path) {
                try FileManager.default.removeItem(at: tombstoneFile)
            }
        }
    }

    /// Atomic invalidation for a managed configuration that is now
    /// INVALID or absent: tombstone the old identity AND remove the
    /// mirror, so the old control plane, policy and bootstrap cannot
    /// stay live (the control provider can no longer sync and the
    /// engine has no rules - fail closed).
    public func invalidateConfiguration() throws {
        try withLockedStore {
            try rotateEpochLocked()
            // Tombstone marker immediately after the authority
            /// rotation: even if a later step fails, admission and
            /// re-mirroring stay blocked (fail closed).
            try writeTombstoneLocked("managed configuration invalid "
                + "or removed")
            try removeIdentityFilesLocked()
            try removeArtifactsLocked()
            if FileManager.default.fileExists(
                atPath: configurationFile.path) {
                try FileManager.default.removeItem(at: configurationFile)
            }
        }
    }

    /// Identity-relevant fields only (never `issues`, which is
    /// recomputed on every read and not mirrored).
    public static func sameIdentity(_ a: AppConfiguration,
                                    _ b: AppConfiguration) -> Bool {
        a.controlPlaneBaseURL == b.controlPlaneBaseURL
            && a.datasetBaseURL == b.datasetBaseURL
            && a.dohServerURL == b.dohServerURL
            && a.deviceID == b.deviceID
    }

    /// MUST be called inside withLockedStore.
    private func writeMirrorLocked(_ config: AppConfiguration) throws {
        let mirrored = MirroredConfiguration(
            controlPlaneBaseURL: config.controlPlaneBaseURL?.absoluteString,
            datasetBaseURL: config.datasetBaseURL?.absoluteString,
            dohServerURL: config.dohServerURL?.absoluteString,
            deviceID: config.deviceID)
        let data = try JSONEncoder().encode(mirrored)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        options.insert(.completeUntilFirstUserAuthentication)
        #endif
        try data.write(to: configurationFile, options: options)
    }

    /// The mirrored configuration, or nil when absent/corrupt (the
    /// control provider then cannot sync and the filter stays
    /// fail-closed - an honest state, not a silent fallback).
    public func mirroredConfiguration() -> AppConfiguration? {
        guard let data = FileManager.default.contents(
            atPath: configurationFile.path),
              String(data: data, encoding: .utf8) != nil,
              let mirrored = try? JSONDecoder().decode(
                MirroredConfiguration.self, from: data)
        else { return nil }
        return AppConfiguration(
            controlPlaneBaseURL: mirrored.controlPlaneBaseURL
                .flatMap(URL.init(string:)),
            deviceID: mirrored.deviceID,
            datasetBaseURL: mirrored.datasetBaseURL
                .flatMap(URL.init(string:)),
            dohServerURL: mirrored.dohServerURL.flatMap(URL.init(string:)))
    }

    // MARK: - Status sidecar (app writes, app UI reads)

    /// Best-effort status write. Never throws: a status note must not
    /// break filtering.
    public func recordStatus(_ state: String) {
        let payload = ["state": state,
                       "at": ISO8601DateFormatter().string(from: Date())]
        guard let data = try? JSONEncoder().encode(payload) else { return }
        try? FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        try? data.write(to: statusFile, options: [.atomic])
    }

    public func readStatus() -> [String: String]? {
        guard let data = FileManager.default.contents(atPath: statusFile.path),
              String(data: data, encoding: .utf8) != nil,
              let object = try? JSONDecoder().decode([String: String].self,
                                                     from: data)
        else { return nil }
        return object
    }

    // MARK: - File change detection

    /// Cheap identity of the on-disk snapshot file: modification time
    /// + size + inode. An atomic replacement changes the inode even
    /// when mtime and size collide; all three must match for the
    /// reader to skip a reload.
    public struct FileStamp: Equatable {
        public let mtime: TimeInterval
        public let size: Int
        /// st_ino (FileAttributeKey.systemFileNumber) - NOT
        /// .systemNumber, which is the filesystem DEVICE id and would
        /// be identical for every file on the volume.
        public let inode: UInt64
    }

    public func snapshotStamp() -> FileStamp? {
        stamp(of: snapshotFile)
    }

    public func epochStamp() -> FileStamp? {
        stamp(of: epochFile)
    }

    public func bootstrapStamp() -> FileStamp? {
        stamp(of: bootstrapFile)
    }

    func stamp(of url: URL) -> FileStamp? {
        guard let attrs = try? FileManager.default.attributesOfItem(
            atPath: url.path),
              let mtime = (attrs[.modificationDate] as? Date)?
                .timeIntervalSince1970,
              let size = (attrs[.size] as? NSNumber)?.intValue,
              let inode = (attrs[.systemFileNumber] as? NSNumber)?
                .uint64Value
        else { return nil }
        return FileStamp(mtime: mtime, size: size, inode: inode)
    }

    // MARK: - Internals

    private func writeEnvelope(_ snapshot: FilterRuleSnapshot) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true)
        let payload = try Self.canonicalBytes(snapshot)
        // MUST be called inside withLockedStore: the authority stamp
        // and the write are one transaction.
        let envelope = Envelope(sha256: Self.digestHex(payload),
                                snapshot: snapshot,
                                authority: currentEpoch()
                                    ?? "corrupt-epoch-sentinel")
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        // See saveBootstrap: locked-device filtering requires the
        // after-first-unlock protection class, not completeFileProtection.
        options.insert(.completeUntilFirstUserAuthentication)
        #endif
        // Same date strategy as canonicalBytes/load: mixed strategies
        // would make every saved snapshot undecodable.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = Self.dateEncoding
        try encoder.encode(envelope).write(to: snapshotFile,
                                           options: options)
    }

    static func validate(_ snapshot: FilterRuleSnapshot,
                         now: Date = Date()) throws {
        // MANDATORY full binding: no optional/legacy unbound snapshot
        // is ever accepted (an unbound snapshot would be applicable
        // across tenants/devices/configs and could never expire).
        // Positive tenant/device/policy identity, full config
        // fingerprint, a known default policy, and a finite fetch
        // time that is not in the future (60s clock-skew tolerance).
        guard snapshot.generation >= 1,
              let policyID = snapshot.policyID, policyID > 0,
              let tenantID = snapshot.tenantID, tenantID > 0,
              let deviceID = snapshot.deviceID, deviceID > 0,
              let fp = snapshot.configFingerprint, Self.isHexDigest(fp),
              let policy = snapshot.defaultPolicy,
              policy == "allow" || policy == "block",
              let fetched = snapshot.fetchedAt,
              fetched.timeIntervalSince1970.isFinite,
              fetched.timeIntervalSince(now) <= 60
        else {
            throw FilterRuleStoreError.invalidSnapshot
        }
        for host in snapshot.rules.keys {
            guard normalizedHost(host) == host else {
                throw FilterRuleStoreError.invalidSnapshot
            }
        }
    }

    static func isHexDigest(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy {
            $0.isHexDigit && !$0.isUppercase
        }
    }

    /// Deterministic encoding for the integrity digest. The same
    /// encoder writes and verifies, so the digest is stable across
    /// launches and processes. Dates encode as whole MILLISECONDS:
    /// iso8601 truncates to seconds, which silently corrupted the
    /// digest on decode-verify round trips (the decoded date no
    /// longer matched the digested bytes).
    static func canonicalBytes(_ snapshot: FilterRuleSnapshot) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = Self.dateEncoding
        return try encoder.encode(snapshot)
    }

    static let dateEncoding = JSONEncoder.DateEncodingStrategy.custom {
        date, encoder in
        var container = encoder.singleValueContainer()
        try container.encode(
            Int64((date.timeIntervalSince1970 * 1000).rounded()))
    }

    static let dateDecoding = JSONDecoder.DateDecodingStrategy.custom {
        decoder in
        let container = try decoder.singleValueContainer()
        return Date(timeIntervalSince1970:
            Double(try container.decode(Int64.self)) / 1000)
    }

    static func digestHex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
