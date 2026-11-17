// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The
// ManagedSettings/FamilyControls application of a policy is
// UNCOMPILED (no Apple SDK) - see AppShieldController.swift.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The control plane's per-device application policy
/// (GET/PUT /api/devices/{id}/app-policy: {"mode", "bundle_ids",
/// "saved", "updated_at?"}), mirrored on device.
///
/// HONEST CAPABILITY SPLIT (verified against Apple's documentation,
/// 2026-11-17):
///
/// - SUPERVISED (MDM): the bundle-ID list is applied by the
///   com.apple.applicationaccess restrictions profile queued through
///   the MDM command lifecycle (control-plane/app/app_ops.py). This
///   is the only Apple-supported mechanism that blocks apps BY BUNDLE
///   ID. Deprecated in iOS 27 in favor of the App settings
///   declaration (ADE + supervised); see mdm/app_management.py.
///
/// - PERSONALLY-OWNED (Screen Time API): FamilyControls +
///   ManagedSettings shield apps identified by OPAQUE
///   ApplicationToken / ActivityCategoryToken values. No public API
///   maps a bundle ID to a token, and tokens are DEVICE-LOCAL: a
///   selection made on one device is meaningless on another. So on
///   personally-owned devices the bundle-ID list can drive only the
///   supervised route; launch-blocking there comes from an on-device
///   FamilyActivityPicker selection (see AppShieldController), which
///   this policy record does not and cannot replace.
///
/// Internet denial (DNS/filter rules) is NOT launch blocking: a
/// blocked app still opens offline. The two mechanisms are
/// complementary and are configured separately.
struct AppBlockingPolicy: Codable, Equatable {

    enum Mode: String, Codable {
        /// Block exactly the listed apps (supervised MDM route).
        case blocklist
        /// Allow ONLY the listed apps; everything else is blocked
        /// (supervised MDM route).
        case allowlist
    }

    let mode: Mode
    let bundleIDs: [String]
    /// Server "saved" flag: false means the server has no stored
    /// policy for this device (nothing to apply; fail safe = no
    /// shield changes, NOT an unblock of a previous local state).
    let saved: Bool
    /// Remote ACTIVATION gate for the personal (unsupervised) Screen
    /// Time shield. The server can only gate whether this device's
    /// own locally consented FamilyActivitySelection is activated;
    /// it cannot see, choose or widen which apps are shielded (the
    /// selection's tokens are opaque and device-local and are never
    /// uploaded). Missing in older payloads decodes to false - the
    /// pre-feature behavior where the server gates nothing.
    let shieldActive: Bool

    private enum CodingKeys: String, CodingKey {
        case mode, saved
        case bundleIDs = "bundle_ids"
        case shieldActive = "shield_active"
    }

    enum PolicyError: Error, Equatable {
        case invalidBundleID(String)
        case duplicateBundleID(String)
    }

    /// Same contract as mdm/app_management.validate_bundle_ids:
    /// reverse-DNS form, deduplicated, order preserved.
    static let bundleIDPattern =
        #"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"#

    init(mode: Mode, bundleIDs: [String], saved: Bool = true,
         shieldActive: Bool = false) throws {
        var seen = Set<String>()
        for raw in bundleIDs {
            guard raw.range(of: Self.bundleIDPattern,
                            options: .regularExpression) != nil else {
                throw PolicyError.invalidBundleID(raw)
            }
            guard seen.insert(raw).inserted else {
                throw PolicyError.duplicateBundleID(raw)
            }
        }
        self.mode = mode
        self.bundleIDs = bundleIDs
        self.saved = saved
        self.shieldActive = shieldActive
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let mode = try container.decode(Mode.self, forKey: .mode)
        let ids = try container.decode([String].self,
                                       forKey: .bundleIDs)
        let saved = try container.decodeIfPresent(Bool.self,
                                                  forKey: .saved)
            ?? true
        let shieldActive = try container.decodeIfPresent(
            Bool.self, forKey: .shieldActive) ?? false
        try self.init(mode: mode, bundleIDs: ids, saved: saved,
                      shieldActive: shieldActive)
    }
}

/// Identity-bound persistence for the last fetched application
/// policy, next to the filter-rule snapshot in the app group. Same
/// binding rule as the rest of the store: a policy fetched under one
/// server/endpoint identity is never applied under another.
struct AppBlockingPolicyStore {

    struct AppPolicySnapshot: Codable, Equatable {
        let policy: AppBlockingPolicy
        let endpointFingerprint: String
        let fetchedAt: Date
    }

    let snapshotFile: URL

    init(snapshotFile: URL) {
        self.snapshotFile = snapshotFile
    }

    /// The exact bytes save() would persist. Callers that must
    /// write under an external lock (FilterRuleStore's
    /// saveAppPolicyMirrorIfCurrent) encode first, then hand the
    /// bytes over so the identity check and the write are atomic.
    func encodedSnapshot(_ policy: AppBlockingPolicy,
                         endpointFingerprint: String) throws -> Data {
        guard !endpointFingerprint.isEmpty else {
            throw FilterRuleStoreError.invalidSnapshot
        }
        let snapshot = AppPolicySnapshot(policy: policy,
                                endpointFingerprint: endpointFingerprint,
                                fetchedAt: Date())
        return try JSONEncoder().encode(snapshot)
    }

    func save(_ policy: AppBlockingPolicy,
              endpointFingerprint: String) throws {
        let data = try encodedSnapshot(
            policy, endpointFingerprint: endpointFingerprint)
        let tmp = snapshotFile.appendingPathExtension("tmp")
        try data.write(to: tmp, options: .atomic)
        if FileManager.default.fileExists(atPath: snapshotFile.path) {
            _ = try? FileManager.default.replaceItemAt(snapshotFile,
                                                       withItemAt: tmp)
        }
        if FileManager.default.fileExists(atPath: tmp.path) {
            try FileManager.default.moveItem(at: tmp, to: snapshotFile)
        }
    }

    /// The stored policy for the CURRENT identity, or nil (missing,
    /// corrupt or foreign - all fail safe: caller makes no shield
    /// change).
    func load(endpointFingerprint: String) -> AppBlockingPolicy? {
        guard !endpointFingerprint.isEmpty,
              let raw = try? Data(contentsOf: snapshotFile),
              let snapshot = try? JSONDecoder().decode(
                  AppPolicySnapshot.self, from: raw),
              snapshot.endpointFingerprint == endpointFingerprint,
              snapshot.policy.saved
        else { return nil }
        return snapshot.policy
    }

    func clear() {
        try? FileManager.default.removeItem(at: snapshotFile)
    }
}

/// Pull-based remote policy updates: the device polls the control
/// plane's per-device application policy with the guardian session
/// (same auth pattern as FilterRulesClient). The personally-owned
/// route can only MIRROR this for visibility; enforcement of the
/// bundle-ID list is the supervised MDM route (see the capability
/// split above).
struct AppBlockingPolicyClient {

    enum FetchError: Error, Equatable {
        case unauthorized
        case deviceNotFound
        case unexpectedStatus(Int)
        case malformedResponse
    }

    let baseURL: URL
    let session: URLSession

    init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    func fetch(deviceID: Int,
               sessionCookie: String) async throws -> AppBlockingPolicy {
        var req = URLRequest(url: baseURL
            .appendingPathComponent("api/devices")
            .appendingPathComponent(String(deviceID))
            .appendingPathComponent("app-policy"))
        req.httpMethod = "GET"
        req.setValue("1", forHTTPHeaderField: "X-KosherGuard-Request")
        req.setValue("kg_session=\(sessionCookie)",
                     forHTTPHeaderField: "Cookie")
        req.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw FetchError.malformedResponse
        }
        switch http.statusCode {
        case 200: break
        case 401, 403: throw FetchError.unauthorized
        case 404: throw FetchError.deviceNotFound
        default: throw FetchError.unexpectedStatus(http.statusCode)
        }
        guard let policy = try? JSONDecoder().decode(
            AppBlockingPolicy.self, from: data)
        else { throw FetchError.malformedResponse }
        return policy
    }
}
