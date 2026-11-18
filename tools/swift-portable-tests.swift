import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import Core

final class FixtureProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, [String: String], Data))!
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let (status, headers, data) = try Self.handler(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: status,
                                           httpVersion: nil, headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}

final class PortableTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: config)
    }
    let manifest = Data(#"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#.utf8)

    func testManagedDictionaryAndHTTPS() {
        let name = "kg-test-\(UUID())"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        defaults.set(["controlPlaneBaseURL":"https://fixture.example", "deviceID":7],
                     forKey:"com.apple.configuration.managed")
        let config = AppConfiguration.managed(defaults: defaults)
        XCTAssertEqual(config.deviceID,7)
        XCTAssertEqual(config.controlPlaneBaseURL,base)
        defaults.set(["controlPlaneBaseURL":"http://fixture.example", "deviceID":7],
                     forKey:"com.apple.configuration.managed")
        XCTAssertNil(AppConfiguration.managed(defaults: defaults).controlPlaneBaseURL)
    }

    func testCookieHeaderCaseAndMultipleCookies() async throws {
        FixtureProtocol.handler = { request in
            XCTAssertEqual(request.url?.path,"/api/auth/login")
            return (200,["set-cookie":"kg_session=fixture-session; HttpOnly; Path=/"],Data("{}".utf8))
        }
        let auth = AuthSessionClient(baseURL:base,session:session())
        let cookie = try await auth.signIn(.init(email:"fixture@example.test",password:"fixture password",totpCode:"123456"))
        XCTAssertEqual(cookie,"fixture-session")
    }

    func testDohScopeReachesExistingServerContract() async throws {
        FixtureProtocol.handler = { request in
            XCTAssertEqual(request.url?.path,"/api/devices/7/dataset-credential")
            XCTAssertEqual(request.value(forHTTPHeaderField:"Cookie"),"kg_session=fixture")
            // URLProtocol may expose the body as an input stream on Linux.
            return (200,[:],Data(#"{"device_id":7,"credential":"fixture-token","scope":"doh","policy_id":1}"#.utf8))
        }
        let issuer = CredentialIssuanceClient(baseURL:base,session:session())
        let token = try await issuer.mint(deviceID:7,scope:.doh,sessionCookie:"fixture")
        XCTAssertEqual(token.token,"fixture-token")
    }

    func testVerifiedPrefilterPersistsAndRestores() async throws {
        FixtureProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField:"Authorization"),"Bearer fixture")
            return (200,[:],request.url!.path.hasSuffix("manifest") ? self.manifest : Data("abc".utf8))
        }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at:file) }
        var updater = PrefilterUpdater(serverBaseURL:base,session:session())
        let result = try await updater.refresh(credential:"fixture",persistTo:file)
        XCTAssertEqual(result.version,2)
        XCTAssertEqual(updater.activeSnapshot?.prefilter,Data("abc".utf8))
        var restored = PrefilterUpdater(serverBaseURL:base,session:session())
        try restored.restore(from:file)
        XCTAssertEqual(restored.currentVersion,2)
        XCTAssertEqual(restored.activeSnapshot?.prefilter,Data("abc".utf8))
    }

    func testCorruptPrefilterDoesNotAdvanceVersionOrOverwriteFile() async throws {
        FixtureProtocol.handler = { request in
            (200,[:],request.url!.path.hasSuffix("manifest") ? self.manifest : Data("bad".utf8))
        }
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("previous".utf8).write(to:file)
        defer { try? FileManager.default.removeItem(at:file) }
        var updater = PrefilterUpdater(serverBaseURL:base,session:session())
        do { _ = try await updater.refresh(credential:"fixture",persistTo:file); XCTFail("accepted corrupt bits") }
        catch PrefilterUpdater.UpdateError.integrityMismatch {}
        XCTAssertEqual(updater.currentVersion,0)
        XCTAssertNil(updater.activeSnapshot)
        XCTAssertEqual(try Data(contentsOf:file),Data("previous".utf8))
    }

    func testFailedHTTPDoesNotActivateAndCadenceIsEnforced() async throws {
        FixtureProtocol.handler = { _ in (401,[:],Data()) }
        var updater = PrefilterUpdater(serverBaseURL:base,session:session())
        let now = Date()
        // 401/403 is an authoritative credential rejection, distinct
        // from a transient fetch failure.
        do { _ = try await updater.refresh(credential:"fixture",now:now); XCTFail("accepted 401") }
        catch PrefilterUpdater.UpdateError.unauthorized {}
        XCTAssertEqual(updater.currentVersion,0)
        do { _ = try await updater.refresh(credential:"fixture",now:now.addingTimeInterval(1)); XCTFail("polled too soon") }
        catch PrefilterUpdater.UpdateError.tooSoon {}
    }

    func testSuccessEnforcesFortyFiveMinuteCadence() async throws {
        FixtureProtocol.handler = { request in
            (200,[:],request.url!.path.hasSuffix("manifest") ? self.manifest : Data("abc".utf8))
        }
        var updater = PrefilterUpdater(serverBaseURL:base,session:session())
        let t0 = Date()
        _ = try await updater.refresh(credential:"fixture",now:t0)
        // Re-check inside the cadence is refused before any fetch.
        do { _ = try await updater.refresh(credential:"fixture",now:t0.addingTimeInterval(60)); XCTFail("polled too soon after success") }
        catch PrefilterUpdater.UpdateError.tooSoon {}
        // After the cadence the check really happens; an unchanged
        // version surfaces as staleVersion, proving the fetch ran.
        do { _ = try await updater.refresh(credential:"fixture",now:t0.addingTimeInterval(45*60)); XCTFail("expected staleVersion") }
        catch PrefilterUpdater.UpdateError.staleVersion {}
    }

    func testTransientFailureRetriesAfterShortBackoff() async throws {
        var fail = true
        FixtureProtocol.handler = { request in
            if fail { return (500,[:],Data()) }
            return (200,[:],request.url!.path.hasSuffix("manifest") ? self.manifest : Data("abc".utf8))
        }
        var updater = PrefilterUpdater(serverBaseURL:base,session:session())
        let t0 = Date()
        do { _ = try await updater.refresh(credential:"fixture",now:t0); XCTFail("accepted 401") }
        catch PrefilterUpdater.UpdateError.fetchFailed {}
        // Inside the short backoff the retry is refused before any fetch.
        do { _ = try await updater.refresh(credential:"fixture",now:t0.addingTimeInterval(30)); XCTFail("retry storm: polled inside backoff") }
        catch PrefilterUpdater.UpdateError.tooSoon {}
        // After the backoff - far inside the old 45-minute suppression -
        // the retry is attempted and succeeds.
        fail = false
        let result = try await updater.refresh(credential:"fixture",now:t0.addingTimeInterval(61))
        XCTAssertEqual(result.version,2)
        XCTAssertEqual(updater.currentVersion,2)
    }
}

final class FakeCredentials: CredentialVault {
    var values: [String: String]
    init(_ values: [String: String]) { self.values = values }
    func read(key: String) throws -> String? { values[key] }
    func save(key: String, value: String) throws { values[key] = value }
    func delete(key: String) throws { values.removeValue(forKey: key) }
}

func makeBundle(session: String = "fixture", origin: String,
                dataset: String = "", datasetOrigin: String? = nil,
                authority: String = "") -> String {
    try! CredentialBundle(
        session: session, sessionOrigin: origin,
        datasetCredential: dataset,
        datasetOrigin: datasetOrigin ?? origin,
        authority: authority).encoded()
}

/// Credential origin metadata is mandatory: a stored credential is
/// only usable against the exact managed configuration that minted
/// it. Every controller fixture below binds its credentials to the
/// fixture origin (https://fixture.example, device 7).
func fixtureOrigin(deviceID: Int = 7,
                   dataset: URL? = nil) -> String {
    let base = URL(string: "https://fixture.example")!
    return FilterSyncController.bootstrap(
        for: AppConfiguration(controlPlaneBaseURL: base,
                              deviceID: deviceID,
                              datasetBaseURL: dataset ?? base),
        tenantID: nil)!.endpointFingerprint
}

func boundCreds(dataset token: String? = nil,
                deviceID: Int = 7,
                datasetURL: URL? = nil,
                store: FilterRuleStore? = nil) -> FakeCredentials {
    let origin = fixtureOrigin(deviceID: deviceID, dataset: datasetURL)
    return FakeCredentials([CredentialBundle.storageKey:
        makeBundle(origin: origin, dataset: token ?? "",
                   authority: store?.currentEpoch() ?? "")])
}

/// Sign-out/identity teardown must take the app-policy mirror (the
/// remote shield gate) with it, and a late in-flight fetch must never
/// resurrect a stale identity's gate.
final class AppPolicyMirrorTeardownTests: XCTestCase {
    func store() throws -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }
    let endpointFP = String(repeating: "b", count: 64)
    let otherFP = String(repeating: "c", count: 64)
    func boot() -> FilterBootstrap {
        FilterBootstrap(configFingerprint: String(repeating: "a", count: 64),
                        endpointFingerprint: String(repeating: "b", count: 64))
    }

    func testSaveRequiresCurrentIdentity() throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        // No bootstrap yet: nothing to bind to, save refused.
        XCTAssertFalse(try store.saveAppPolicyMirrorIfCurrent(
            Data("x".utf8), endpointFingerprint: endpointFP))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: store.appPolicyMirrorFile.path))
        try store.saveBootstrap(boot())
        // Matching identity saves; foreign identity is dropped.
        XCTAssertTrue(try store.saveAppPolicyMirrorIfCurrent(
            Data("x".utf8), endpointFingerprint: endpointFP))
        XCTAssertFalse(try store.saveAppPolicyMirrorIfCurrent(
            Data("y".utf8), endpointFingerprint: otherFP))
        XCTAssertEqual(try Data(contentsOf: store.appPolicyMirrorFile),
                       Data("x".utf8))
    }

    func testClearRemovesMirrorAndBlocksLateSave() throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(boot())
        XCTAssertTrue(try store.saveAppPolicyMirrorIfCurrent(
            Data("x".utf8), endpointFingerprint: endpointFP))
        // Sign-out path: clear() rotates the epoch and removes the
        // identity files; the mirror must be gone with them.
        try store.clear()
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: store.appPolicyMirrorFile.path))
        // The late in-flight fetch racing the sign-out loses: its
        // save observes the missing identity and is refused.
        XCTAssertFalse(try store.saveAppPolicyMirrorIfCurrent(
            Data("z".utf8), endpointFingerprint: endpointFP))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: store.appPolicyMirrorFile.path))
    }
}

final class RuleStoreTests: XCTestCase {
    func store() throws -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }
    func cleanup(_ dir: URL) { try? FileManager.default.removeItem(at: dir) }
    let fp = String(repeating: "a", count: 64)
    func bound(_ generation: Int, _ policyID: Int,
               _ rules: [String: Bool],
               defaultPolicy: String = "allow",
               fetchedAt: Date = Date()) -> FilterRuleSnapshot {
        FilterRuleSnapshot(generation: generation, policyID: policyID,
                           defaultPolicy: defaultPolicy, rules: rules,
                           tenantID: 11, deviceID: 7,
                           configFingerprint: String(repeating: "a", count: 64),
                           fetchedAt: fetchedAt)
    }
    lazy var snap1 = bound(1, 3, ["bad.example": true, "good.example": false],
        fetchedAt: Date(timeIntervalSince1970:
            (Date().timeIntervalSince1970 * 1000).rounded() / 1000))

    func testRoundtripAndNilWhenAbsent() throws {
        let (s, dir) = try store(); defer { cleanup(dir) }
        XCTAssertNil(try s.load())
        try s.save(snap1)
        XCTAssertEqual(try s.load(), snap1)
        // Status sidecar roundtrip
        s.recordStatus("rules-loaded generation=1")
        XCTAssertEqual(s.readStatus()?["state"], "rules-loaded generation=1")
    }

    func testMonotonicGenerations() throws {
        let (s, dir) = try store(); defer { cleanup(dir) }
        try s.save(bound(2, 3, ["a.example": true]))
        // Older generation rejected
        XCTAssertThrowsError(try s.save(snap1)) { error in
            XCTAssertEqual(error as? FilterRuleStoreError, .staleGeneration) }
        // Same generation, identical content: accepted (freshness
        // refresh - see testSameGenerationRefreshRenewsFreshness)
        try s.save(bound(2, 3, ["a.example": true]))
        // Same generation, different content: rejected by the durable
        // floor's immutable-revision digest (revisionConflict; the
        // in-memory conflictingGeneration check remains as defense in
        // depth but the floor proof fires first).
        XCTAssertThrowsError(try s.save(bound(2, 3, ["b.example": true]))) {
            error in
            XCTAssertEqual(error as? FilterRuleStoreError, .revisionConflict) }
        // A policy switch can NEVER roll the generation back: the
        // tenant's published revision is monotonic across policies.
        XCTAssertThrowsError(try s.save(bound(1, 9, [:],
                                            defaultPolicy: "block"))) {
            error in
            XCTAssertEqual(error as? FilterRuleStoreError,
                           .staleGeneration) }
        // ...but a policy switch at a HIGHER generation is fine.
        try s.save(bound(3, 9, [:], defaultPolicy: "block"))
        XCTAssertEqual(try s.load()?.policyID, 9)
    }

    func testCorruptFileDetectedAndClearable() throws {
        let (s, dir) = try store(); defer { cleanup(dir) }
        try s.save(snap1)
        // Bit-flip the payload: digest must catch it
        var bytes = [UInt8](try Data(contentsOf: s.snapshotFile))
        bytes[bytes.count / 2] ^= 0xFF
        try Data(bytes).write(to: s.snapshotFile)
        XCTAssertThrowsError(try s.load()) { error in
            XCTAssertEqual(error as? FilterRuleStoreError, .corruptSnapshot) }
        try s.clear()
        XCTAssertNil(try s.load())
    }

    func testValidationRejectsBadHostsAndGenerations() throws {
        let (s, dir) = try store(); defer { cleanup(dir) }
        for bad in [bound(0, 1, [:]),
                    bound(1, 1, [:], defaultPolicy: "sideways"),
                    bound(1, 1, ["HTTP://Bad.example": true]),
                    bound(1, 1, ["bad.example/path": true]),
                    // Future fetch time (beyond clock-skew tolerance)
                    bound(1, 1, [:],
                          fetchedAt: Date().addingTimeInterval(3600))] {
            XCTAssertThrowsError(try s.save(bad)) { error in
                XCTAssertEqual(error as? FilterRuleStoreError, .invalidSnapshot) }
        }
    }

    func testNormalizationAndVerdictOrder() {
        XCTAssertEqual(FilterRuleStore.normalizedHost("WWW.Example.COM."), "www.example.com")
        XCTAssertNil(FilterRuleStore.normalizedHost("bad.example/path"))
        XCTAssertNil(FilterRuleStore.normalizedHost("bad.example:443"))
        XCTAssertNil(FilterRuleStore.normalizedHost(""))
        let rules = ["example.com": true, "open.example.com": false]
        // Block matches host and parent suffix
        XCTAssertEqual(FilterRuleStore.verdict(for: "example.com", in: rules), true)
        XCTAssertEqual(FilterRuleStore.verdict(for: "www.example.com", in: rules), true)
        // Explicit allow beats the parent block (engine semantics)
        XCTAssertEqual(FilterRuleStore.verdict(for: "open.example.com", in: rules), false)
        XCTAssertEqual(FilterRuleStore.verdict(for: "api.open.example.com", in: rules), false)
        // Unknown host: no verdict from this layer
        XCTAssertNil(FilterRuleStore.verdict(for: "other.test", in: rules))
    }
}

final class AppConfigurationTests: XCTestCase {
    func defaults(with dict: [String: Any]) -> UserDefaults {
        let name = "kg-test-\(UUID())"
        let defaults = UserDefaults(suiteName: name)!
        defaults.set(dict, forKey: "com.apple.configuration.managed")
        return defaults
    }

    func testFullConfigurationParses() {
        let d = defaults(with: [
            "controlPlaneBaseURL": "https://cp.example.test",
            "datasetBaseURL": "https://data.example.test",
            "dohServerURL": "https://dns.example.test/dns-query",
            "deviceID": 7])
        let c = AppConfiguration.managed(defaults: d)
        XCTAssertEqual(c.deviceID, 7)
        XCTAssertEqual(c.controlPlaneBaseURL?.host, "cp.example.test")
        XCTAssertEqual(c.datasetBaseURL?.host, "data.example.test")
        XCTAssertEqual(c.dohServerURL?.host, "dns.example.test")
        XCTAssertEqual(c.issues, [])
    }

    func testInvalidAndMissingKeysReportedPerKey() {
        let d = defaults(with: [
            "controlPlaneBaseURL": "http://cp.example.test", // plaintext
            "datasetBaseURL": "https://user:pw@data.example.test", // userinfo
            "deviceID": "not-a-number"])
        let c = AppConfiguration.managed(defaults: d)
        XCTAssertNil(c.controlPlaneBaseURL)
        XCTAssertNil(c.datasetBaseURL)
        XCTAssertNil(c.deviceID)
        XCTAssertEqual(c.issues.count, 3) // 3 invalid; dohServerURL is optional
    }

    func testDeviceIDCoercionRules() {
        // digit string accepted (MDM consoles often push strings)
        XCTAssertEqual(AppConfiguration.managed(defaults: defaults(with: [
            "controlPlaneBaseURL": "https://cp.example.test",
            "datasetBaseURL": "https://data.example.test",
            "deviceID": "42"])).deviceID, 42)
        // bool rejected even though it bridges to NSNumber
        XCTAssertNil(AppConfiguration.managed(defaults: defaults(with: [
            "controlPlaneBaseURL": "https://cp.example.test",
            "datasetBaseURL": "https://data.example.test",
            "deviceID": true])).deviceID)
        // fraction rejected
        XCTAssertNil(AppConfiguration.managed(defaults: defaults(with: [
            "controlPlaneBaseURL": "https://cp.example.test",
            "datasetBaseURL": "https://data.example.test",
            "deviceID": 7.5])).deviceID)
        // zero rejected
        XCTAssertNil(AppConfiguration.managed(defaults: defaults(with: [
            "controlPlaneBaseURL": "https://cp.example.test",
            "datasetBaseURL": "https://data.example.test",
            "deviceID": 0])).deviceID)
    }
}

final class FilterSyncControllerTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: config)
    }
    func config() -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: 7,
                         datasetBaseURL: base)
    }
    let manifest = Data(#"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#.utf8)
    let rulesBody = #"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{"bad.example":true,"good.example":false}}"#

    func fullServer() {
        FixtureProtocol.handler = { request in
            if request.url!.path.hasSuffix("filter-rules") {
                XCTAssertEqual(request.value(forHTTPHeaderField:"Cookie"), "kg_session=fixture")
                return (200,[:],Data(self.rulesBody.utf8))
            }
            XCTAssertEqual(request.value(forHTTPHeaderField:"Authorization"), "Bearer fixture-token")
            return (200,[:],request.url!.path.hasSuffix("manifest") ? self.manifest : Data("abc".utf8))
        }
    }

    func testFullSyncWritesRuleStoreAndPrefilter() async throws {
        fullServer()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        let controller = FilterSyncController(
            configuration: config(),
            credentials: boundCreds(dataset: "fixture-token"),
            session: session(), ruleStore: store,
            prefilterFile: dir.appendingPathComponent("prefilter.json"))
        await controller.syncNow()
        guard case .synced(let prefilter, let rules) = controller.state else {
            return XCTFail("unexpected state \(controller.state)")
        }
        XCTAssertEqual(prefilter, 2)
        XCTAssertEqual(rules, 5)
        let snapshot = try store.load()
        XCTAssertEqual(snapshot?.rules, ["bad.example": true, "good.example": false])
        XCTAssertEqual(snapshot?.policyID, 3)
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent("prefilter.json").path))
    }

    func testNotConfiguredIsHonest() async {
        let controller = FilterSyncController(
            configuration: AppConfiguration(controlPlaneBaseURL: nil,
                                            deviceID: nil),
            credentials: FakeCredentials(["session": "fixture"]),
            session: session(), ruleStore: nil, prefilterFile: nil)
        if case .notConfigured(let problem) = controller.state {
            XCTAssertTrue(problem.contains("controlPlaneBaseURL"))
        } else { XCTFail("expected notConfigured") }
        await controller.syncNow()
        if case .notConfigured = controller.state {} else {
            XCTFail("sync proceeded without configuration") }
    }

    func testSignedOutState() async {
        let controller = FilterSyncController(
            configuration: config(), credentials: FakeCredentials([:]),
            session: session(), ruleStore: nil, prefilterFile: nil)
        await controller.syncNow()
        XCTAssertEqual(controller.state, .signedOut)
    }

    func testMissingDatasetCredentialFailsLoudly() async {
        FixtureProtocol.handler = { request in
            (200,[:],Data(self.rulesBody.utf8))
        }
        let controller = FilterSyncController(
            configuration: config(),
            credentials: boundCreds(),
            session: session(), ruleStore: nil, prefilterFile: nil)
        await controller.syncNow()
        guard case .failed(let reason) = controller.state else {
            return XCTFail("expected failed, got \(controller.state)")
        }
        XCTAssertTrue(reason.contains("dataset credential"))
    }

    func testRulesUnauthorizedInvalidatesAndClears() async throws {
        FixtureProtocol.handler = { _ in (401,[:],Data()) }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        let controller = FilterSyncController(
            configuration: config(),
            credentials: boundCreds(dataset: "fixture-token"),
            session: session(), ruleStore: store, prefilterFile: nil)
        await controller.syncNow()
        guard case .invalidated = controller.state else {
            return XCTFail("expected invalidated, got \(controller.state)")
        }
        XCTAssertNil(try store.load())
    }

    func testDeviceInactiveInvalidatesAndClears() async throws {
        FixtureProtocol.handler = { _ in (409,[:],Data()) }
        try await assertAuthoritativeInvalidation(statusExpected: "inactive")
    }

    func testDeviceRemovedInvalidatesAndClears() async throws {
        FixtureProtocol.handler = { _ in (404,[:],Data()) }
        try await assertAuthoritativeInvalidation(statusExpected: "removed")
    }

    private func assertAuthoritativeInvalidation(
        statusExpected: String) async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.save(FilterRuleSnapshot(
            generation: 2, policyID: 3, defaultPolicy: "allow",
            rules: ["keep.example": true], tenantID: 11, deviceID: 7,
            configFingerprint: String(repeating: "a", count: 64),
            fetchedAt: Date()))
        let controller = FilterSyncController(
            configuration: config(),
            credentials: boundCreds(dataset: "fixture-token"),
            session: session(), ruleStore: store, prefilterFile: nil)
        await controller.syncNow()
        guard case .invalidated(let reason) = controller.state else {
            return XCTFail("expected invalidated, got \(controller.state)")
        }
        XCTAssertTrue(reason.contains(statusExpected))
        XCTAssertNil(try store.load())
        XCTAssertNotNil(store.readStatus()?["state"])
    }

    /// Dataset credential rejection (401/403) is an authoritative
    /// invalidation too: prefilter file deleted, rules cleared.
    func testDatasetUnauthorizedInvalidatesAndDeletesPrefilter() async throws {
        FixtureProtocol.handler = { request in
            if request.url!.path.hasSuffix("filter-rules") {
                return (200,[:],Data(self.rulesBody.utf8))
            }
            return (401,[:],Data())
        }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try FileManager.default.createDirectory(atPath: dir.path,
                                                withIntermediateDirectories: true)
        let prefilter = dir.appendingPathComponent("prefilter.json")
        try Data("x".utf8).write(to: prefilter)
        let controller = FilterSyncController(
            configuration: config(),
            credentials: boundCreds(dataset: "fixture-token"),
            session: session(), ruleStore: store, prefilterFile: prefilter)
        await controller.syncNow()
        guard case .invalidated(let reason) = controller.state else {
            return XCTFail("expected invalidated, got \(controller.state)")
        }
        XCTAssertTrue(reason.contains("credential"))
        XCTAssertNil(try store.load())
        XCTAssertFalse(FileManager.default.fileExists(atPath: prefilter.path))
    }

    func testNoEffectivePolicyClearsStaleRules() async throws {
        FixtureProtocol.handler = { request in
            if request.url!.path.hasSuffix("filter-rules") {
                return (200,[:],Data(#"{"device_id":7,"tenant_id":11,"policy_id":null,"generation":0,"default_policy":null,"rules":{},"reason":"no effective policy"}"#.utf8))
            }
            return (200,[:],request.url!.path.hasSuffix("manifest") ? self.manifest : Data("abc".utf8))
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.save(FilterRuleSnapshot(generation: 3, policyID: 3,
            defaultPolicy: "allow", rules: ["bad.example": true],
            tenantID: 11, deviceID: 7,
            configFingerprint: String(repeating: "b", count: 64),
            fetchedAt: Date()))
        let controller = FilterSyncController(
            configuration: config(),
            credentials: boundCreds(dataset: "fixture-token"),
            session: session(), ruleStore: store,
            prefilterFile: dir.appendingPathComponent("prefilter.json"))
        await controller.syncNow()
        // The persisted snapshot's identity (b*64) differs from the
        // response's: the controller must NOT clear-and-rewrite across
        // identities - it refuses with identityConflict and, being
        // the current authority, conditionally invalidates.
        guard case .invalidated = controller.state else {
            XCTFail("unexpected state \(controller.state)")
            return
        }
        XCTAssertNil(try store.load()) // stale rules removed
    }
}

// MARK: - Independent-review regressions and verdict-engine coverage

final class ReviewRegressionTests: XCTestCase {
    /// Reviewer regression: "bad..example" (empty DNS label) must not
    /// normalize to a valid host.
    func testConsecutiveEmptyDNSLabelsAreNotNormalizedHosts() {
        XCTAssertNil(FilterRuleStore.normalizedHost("bad..example"))
        XCTAssertNil(FilterRuleStore.normalizedHost("a.b..c"))
        XCTAssertNil(FilterRuleStore.normalizedHost("."))
        XCTAssertNil(FilterRuleStore.normalizedHost(".."))
    }

    /// Absent and unreadable are distinct states; a read failure must
    /// never collapse into "no snapshot" (which would drop
    /// last-known-good handling and look like a clean slate).
    func testUnreadableSnapshotDistinctFromAbsent() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        XCTAssertNil(try store.load()) // absent
        // A directory at the snapshot path: exists, but cannot be read
        // as file contents - deterministic unreadable state.
        try FileManager.default.createDirectory(at: store.snapshotFile,
                                                withIntermediateDirectories: true)
        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? FilterRuleStoreError, .unreadableSnapshot)
        }
    }

    /// Cross-process compare-and-replace: concurrent writers
    /// serialize on the store lock; an older generation can never
    /// overwrite a newer one.
    func testConcurrentWritesKeepHighestGeneration() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        let group = DispatchGroup()
        for _ in 0..<40 {
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                try? store.save(FilterRuleSnapshot(
                    generation: 10, policyID: 3, defaultPolicy: "allow",
                    rules: ["new.example": true], tenantID: 11, deviceID: 7,
                    configFingerprint: String(repeating: "a", count: 64),
                    fetchedAt: Date()))
            }
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                try? store.save(FilterRuleSnapshot(
                    generation: 5, policyID: 3, defaultPolicy: "allow",
                    rules: ["old.example": true], tenantID: 11, deviceID: 7,
                    configFingerprint: String(repeating: "a", count: 64),
                    fetchedAt: Date()))
            }
        }
        group.wait()
        let persisted = try store.load()
        XCTAssertEqual(persisted?.generation, 10)
        XCTAssertEqual(persisted?.rules, ["new.example": true])
    }

    /// Reviewer regression (stricter variant): a response mixing a
    /// non-nil policy id with generation 0 is a contract violation -
    /// the client throws invalidPayload and the sync controller FAILS
    /// WITHOUT clearing or persisting anything. (The reviewer's
    /// attached probe asserted response.snapshot non-nil; rejecting
    /// the malformed body at decode is the stronger guard: it can
    /// never become either a persist or a clear instruction.)
    func testInconsistentPolicyResponseRejectedAndStoreUntouched() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.save(FilterRuleSnapshot(
            generation: 4, policyID: 3, defaultPolicy: "allow",
            rules: ["keep.example": true], tenantID: 11, deviceID: 7,
            configFingerprint: String(repeating: "a", count: 64),
            fetchedAt: Date()))
        FixtureProtocol.handler = { _ in
            (200, [:], Data(#"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":0,"default_policy":"block","rules":{"bad.example":true}}"#.utf8))
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        let session = URLSession(configuration: config)
        await XCTAssertThrowsErrorAsync(
            try await FilterRulesClient(
                baseURL: URL(string: "https://fixture.example")!,
                session: session).fetch(deviceID: 7, sessionCookie: "f")
        ) { error in
            XCTAssertEqual(error as? FilterRulesClient.RulesError,
                           .invalidPayload)
        }
        let controller = FilterSyncController(
            configuration: AppConfiguration(
                controlPlaneBaseURL: URL(string: "https://fixture.example")!,
                deviceID: 7,
                datasetBaseURL: URL(string: "https://fixture.example")!),
            credentials: boundCreds(dataset: "tok"),
            session: session, ruleStore: store, prefilterFile: nil)
        await controller.syncNow()
        guard case .failed = controller.state else {
            return XCTFail("expected failed, got \(controller.state)")
        }
        // The pre-existing rules were NOT cleared by a malformed feed.
        XCTAssertEqual(try store.load()?.rules, ["keep.example": true])
    }

    /// Reviewer regression: with NO persistence destination the sync
    /// must never report .synced.
    func testUnavailablePersistenceIsNotReportedSynced() async {
        let base = URL(string: "https://fixture.example")!
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [FixtureProtocol.self]
        FixtureProtocol.handler = { req in
            let path = req.url!.path
            let rules = #"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{"bad.example":true}}"#
            let manifest = #"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#
            return (200, [:], Data((path.hasSuffix("filter-rules") ? rules : path.hasSuffix("manifest") ? manifest : "abc").utf8))
        }
        let sut = FilterSyncController(
            configuration: AppConfiguration(controlPlaneBaseURL: base,
                                            deviceID: 7, datasetBaseURL: base),
            credentials: boundCreds(dataset: "fixture-token"),
            session: URLSession(configuration: cfg),
            ruleStore: nil, prefilterFile: nil)
        await sut.syncNow()
        if case .synced = sut.state {
            XCTFail("reports synced with no persistence destination")
        }
        guard case .persistenceUnavailable = sut.state else {
            return XCTFail("expected persistenceUnavailable, got \(sut.state)")
        }
    }
}

/// Async throwing assertion helper (XCTest has no async variant).
func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: String = "",
    file: StaticString = #filePath, line: UInt = #line,
    _ errorHandler: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error: \(message)", file: file, line: line)
    } catch { errorHandler(error) }
}

final class FilterVerdictEngineTests: XCTestCase {
    let cp = URL(string: "https://cp.example.test")!
    let ds = URL(string: "https://ds.example.test")!

    func makeStore() throws -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }

    func fingerprint(tenant: Int = 11, device: Int = 7) -> String {
        FilterRuleStore.configFingerprint(controlPlane: cp, dataset: ds,
                                          doh: nil, tenantID: tenant,
                                          deviceID: device)
    }

    func bootstrap(tenant: Int = 11) -> FilterBootstrap {
        FilterBootstrap(configFingerprint: fingerprint(tenant: tenant),
                        endpointFingerprint: fingerprint(tenant: 0))
    }

    func snapshot(defaultPolicy: String = "allow",
                  rules: [String: Bool] = ["bad.example": true,
                                           "good.example": false],
                  fetchedAt: Date = Date(),
                  tenant: Int = 11) -> FilterRuleSnapshot {
        FilterRuleSnapshot(generation: 1, policyID: 3,
                           defaultPolicy: defaultPolicy, rules: rules,
                           tenantID: tenant, deviceID: 7,
                           configFingerprint: fingerprint(tenant: tenant),
                           fetchedAt: fetchedAt)
    }

    /// Fail closed: no snapshot, no bootstrap -> every identified host
    /// blocked; hostless flows have no verdict from this layer.
    func testNotReadyBlocksEverythingWithoutBootstrap() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "anything.example"), .block)
        XCTAssertEqual(engine.verdict(forHost: nil), .askControl)
        XCTAssertFalse(engine.isReady)
    }

    /// NO infrastructure exception (review round 4): while notReady,
    /// even the device's own service hosts are blocked on the data
    /// path. Rule sync runs on the control provider's supported
    /// maintenance channel instead.
    func testNotReadyBlocksEvenServiceHosts() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(bootstrap())
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "cp.example.test"), .block)
        XCTAssertEqual(engine.verdict(forHost: "ds.example.test"), .block)
        XCTAssertEqual(engine.verdict(forHost: "anything.example"), .block)
    }

    /// Missing identity record: a snapshot without its bootstrap is
    /// rejected outright (no binding, no LKG, fail closed).
    func testMissingIdentityRecordRejectsSnapshot() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.save(snapshot())
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        guard case .notReady(let reason) = engine.currentReadiness() else {
            return XCTFail("expected notReady, got \(engine.currentReadiness())")
        }
        XCTAssertTrue(reason.contains("identity"))
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .block)
    }

    /// defaultPolicy "block" must be enforced for unmatched hosts
    /// (reviewer: the persisted default was previously ignored).
    func testDefaultPolicyBlockEnforced() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(bootstrap())
        try store.save(snapshot(defaultPolicy: "block",
                                rules: ["good.example": false]))
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .allow)
        XCTAssertEqual(engine.verdict(forHost: "random.example"), .block)
    }

    func testDefaultPolicyAllowLeavesUnknownToOtherLayers() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(bootstrap())
        try store.save(snapshot())
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "bad.example"), .block)
        XCTAssertEqual(engine.verdict(forHost: "www.bad.example"), .block)
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .allow)
        XCTAssertEqual(engine.verdict(forHost: "unknown.example"), .allow)
    }

    /// Per-flow expiry: an aging snapshot flips to fail-closed even
    /// with zero disk events.
    func testExpiredSnapshotFailsClosedPerFlow() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(bootstrap())
        try store.save(snapshot())
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        let future = Date().addingTimeInterval(
            FilterVerdictEngine.maxSnapshotAge + 3600)
        XCTAssertEqual(engine.verdict(forHost: "good.example", now: future),
                       .block)
        XCTAssertFalse(engine.isReady)
    }

    /// Corruption keeps last-known-good only inside its own expiry
    /// window.
    func testCorruptKeepsLastKnownGoodWithinExpiry() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(bootstrap())
        try store.save(snapshot())
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        var bytes = [UInt8](try Data(contentsOf: store.snapshotFile))
        bytes[bytes.count / 2] ^= 0xFF
        try Data(bytes).write(to: store.snapshotFile)
        XCTAssertTrue(engine.reloadIfChanged())
        guard case .degraded = engine.currentReadiness() else {
            return XCTFail("expected degraded, got \(engine.currentReadiness())")
        }
        XCTAssertEqual(engine.verdict(forHost: "bad.example"), .block)
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .allow)
        // The LKG window closes at the snapshot's own expiry.
        let future = Date().addingTimeInterval(
            FilterVerdictEngine.maxSnapshotAge + 3600)
        XCTAssertEqual(engine.verdict(forHost: "good.example", now: future),
                       .block)
    }

    /// Identity boundary: a snapshot whose fingerprint does not match
    /// the app's current bootstrap is never applied.
    func testIdentityMismatchFailsClosed() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // Snapshot bound to tenant 11; bootstrap for tenant 22.
        try store.save(snapshot(tenant: 11))
        try store.saveBootstrap(bootstrap(tenant: 22))
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertFalse(engine.isReady)
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .block)
    }

    /// Change detection: a new generation on disk is picked up via
    /// reloadIfChanged (the control provider's notifyRulesChanged
    /// path), with no reload work when the stamp is unchanged.
    func testStampChangeDetection() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(bootstrap())
        try store.save(snapshot(rules: ["a.example": true]))
        let engine = FilterVerdictEngine(store: store)
        XCTAssertTrue(engine.reloadIfChanged())
        XCTAssertFalse(engine.reloadIfChanged()) // unchanged stamp
        try store.save(FilterRuleSnapshot(
            generation: 2, policyID: 3, defaultPolicy: "allow",
            rules: ["b.example": true], tenantID: 11, deviceID: 7,
            configFingerprint: fingerprint(), fetchedAt: Date()))
        XCTAssertTrue(engine.reloadIfChanged())
        XCTAssertEqual(engine.verdict(forHost: "b.example"), .block)
        XCTAssertEqual(engine.verdict(forHost: "a.example"), .allow)
    }

    /// A cleared store is an explicit boundary: last-known-good is
    /// dropped, fail closed.
    func testClearedStoreDropsLastKnownGood() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(bootstrap())
        try store.save(snapshot())
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        try store.clear()
        XCTAssertTrue(engine.reloadIfChanged())
        XCTAssertFalse(engine.isReady)
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .block)
    }
}

// MARK: - Review round 3 regressions

final class StoreBindingAndStampTests: XCTestCase {
    func makeStore() -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }
    let fp = String(repeating: "a", count: 64)
    func bound(_ generation: Int, _ rules: [String: Bool],
               fetchedAt: Date = Date()) -> FilterRuleSnapshot {
        FilterRuleSnapshot(generation: generation, policyID: 3,
                           defaultPolicy: "allow", rules: rules,
                           tenantID: 11, deviceID: 7,
                           configFingerprint: String(repeating: "a", count: 64),
                           fetchedAt: fetchedAt)
    }

    /// Reviewer finding 1: a repeated sync of the SAME published
    /// generation must renew freshness, not conflict.
    func testSameGenerationRefreshRenewsFreshness() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let t1 = Date().addingTimeInterval(-3600)
        try store.save(bound(5, ["a.example": true], fetchedAt: t1))
        // Same generation, same immutable content, newer fetch time.
        try store.save(bound(5, ["a.example": true]))
        let persisted = try store.load()
        XCTAssertEqual(persisted?.generation, 5)
        XCTAssertGreaterThan(persisted?.fetchedAt ?? .distantPast, t1)
        // Same generation, MUTATED content: still rejected - now by
        // the durable floor's immutable-revision digest.
        XCTAssertThrowsError(try store.save(bound(5, ["b.example": true]))) {
            XCTAssertEqual($0 as? FilterRuleStoreError, .revisionConflict)
        }
    }

    /// Reviewer finding 3: unbound/legacy snapshots are rejected
    /// fail-safe - at save AND when a legacy file is read from disk.
    func testUnboundSnapshotsRejectedAtSaveAndLoad() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let legacy = FilterRuleSnapshot(generation: 1, policyID: 3,
                                        defaultPolicy: "allow",
                                        rules: ["a.example": true])
        XCTAssertThrowsError(try store.save(legacy)) {
            XCTAssertEqual($0 as? FilterRuleStoreError, .invalidSnapshot)
        }
        // A legacy on-disk envelope (no binding fields, no digest
        // contract) must never load as ready either.
        let legacyJSON = #"{"generation":1,"policy_id":3,"default_policy":"allow","rules":{"a.example":true}}"#
        try FileManager.default.createDirectory(at: store.directory,
                                                withIntermediateDirectories: true)
        try Data(legacyJSON.utf8).write(to: store.snapshotFile)
        XCTAssertThrowsError(try store.load())
        XCTAssertNil(try? store.load())
    }

    /// Reviewer finding 2: stamp identity uses the real inode
    /// (systemFileNumber), so an atomic replacement with identical
    /// size AND mtime is still detected.
    func testStampDetectsSameSizeSameMtimeReplacement() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: store.directory,
                                                withIntermediateDirectories: true)
        let file = store.directory.appendingPathComponent("probe.json")
        let fixed = Date(timeIntervalSince1970: 1_700_000_000)
        try Data(repeating: 65, count: 128).write(to: file)
        try FileManager.default.setAttributes(
            [.modificationDate: fixed], ofItemAtPath: file.path)
        let stamp1 = store.stamp(of: file)
        // Atomic replacement: same bytes, same size, same mtime.
        let tmp = store.directory.appendingPathComponent("probe.tmp")
        try Data(repeating: 65, count: 128).write(to: tmp)
        try FileManager.default.setAttributes(
            [.modificationDate: fixed], ofItemAtPath: tmp.path)
        try FileManager.default.removeItem(at: file)
        try FileManager.default.moveItem(at: tmp, to: file)
        let stamp2 = store.stamp(of: file)
        XCTAssertNotNil(stamp1); XCTAssertNotNil(stamp2)
        XCTAssertNotEqual(stamp1, stamp2,
                          "inode change must differentiate the stamps")
        XCTAssertEqual(stamp1?.mtime, stamp2?.mtime)
        XCTAssertEqual(stamp1?.size, stamp2?.size)
    }
}

final class EngineIdentityRefreshTests: XCTestCase {
    let cp = URL(string: "https://cp.example.test")!
    let ds = URL(string: "https://ds.example.test")!
    func fp(_ tenant: Int) -> String {
        FilterRuleStore.configFingerprint(controlPlane: cp, dataset: ds,
                                          doh: nil, tenantID: tenant,
                                          deviceID: 7)
    }
    func boot(_ tenant: Int) -> FilterBootstrap {
        FilterBootstrap(configFingerprint: fp(tenant),
                        endpointFingerprint: fp(0))
    }
    func snap(_ tenant: Int) -> FilterRuleSnapshot {
        FilterRuleSnapshot(generation: 1, policyID: 3,
                           defaultPolicy: "allow",
                           rules: ["good.example": false],
                           tenantID: tenant, deviceID: 7,
                           configFingerprint: fp(tenant), fetchedAt: Date())
    }
    func makeStore() throws -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }

    /// Reviewer finding 4a: a bootstrap/config change with an
    /// UNCHANGED snapshot file must still invalidate the engine.
    func testBootstrapChangeDetectedWithUnchangedSnapshot() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(boot(11))
        try store.save(snap(11))
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .allow)
        // Only the bootstrap changes (config switch to tenant 22).
        try store.saveBootstrap(boot(22))
        XCTAssertTrue(engine.reloadIfChanged(),
                      "bootstrap stamp change must trigger reload")
        XCTAssertFalse(engine.isReady)
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .block)
    }

    /// Reviewer finding 4b: after a config switch, last-known-good is
    /// NOT reused even when the new snapshot is corrupt.
    func testLKGDroppedAfterConfigSwitchEvenWhenCorrupt() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(boot(11))
        try store.save(snap(11))
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertTrue(engine.isReady)
        // Config switch + corrupted snapshot in the same window.
        try store.saveBootstrap(boot(22))
        var bytes = [UInt8](try Data(contentsOf: store.snapshotFile))
        bytes[bytes.count / 2] ^= 0xFF
        try Data(bytes).write(to: store.snapshotFile)
        engine.reloadIfChanged()
        guard case .notReady = engine.currentReadiness() else {
            return XCTFail("old LKG reused after config switch: "
                + "\(engine.currentReadiness())")
        }
        XCTAssertEqual(engine.verdict(forHost: "good.example"), .block)
    }
}

final class SyncControllerIdentityTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    let rulesBody = #"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{"bad.example":true}}"#
    let manifest = Data(#"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#.utf8)
    func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: cfg)
    }
    func fullServer() {
        FixtureProtocol.handler = { req in
            (200, [:], Data((req.url!.path.hasSuffix("filter-rules")
                ? self.rulesBody
                : req.url!.path.hasSuffix("manifest")
                    ? String(data: self.manifest, encoding: .utf8)!
                    : "abc").utf8))
        }
    }
    func makeController(dir: URL, dataset: URL? = nil)
        -> (FilterSyncController, FilterRuleStore) {
        let store = FilterRuleStore(directory: dir)
        let controller = FilterSyncController(
            configuration: AppConfiguration(
                controlPlaneBaseURL: base, deviceID: 7,
                datasetBaseURL: dataset ?? base),
            credentials: boundCreds(dataset: "tok", datasetURL: dataset),
            session: session(), ruleStore: store,
            prefilterFile: dir.appendingPathComponent("prefilter.json"))
        return (controller, store)
    }

    /// Reviewer finding 5: reopening the app (new controller, same
    /// config and store) must NOT overwrite the tenant-pinned
    /// bootstrap with a tenant-0 placeholder.
    func testReopenKeepsPinnedIdentity() async throws {
        fullServer()
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (first, store) = makeController(dir: dir)
        await first.syncNow()
        guard case .synced = first.state else {
            return XCTFail("unexpected \(first.state)")
        }
        let pinned = store.readBootstrap()?.configFingerprint
        XCTAssertNotNil(pinned)
        let tenantFP = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 11, deviceID: 7)
        XCTAssertEqual(pinned, tenantFP)
        // "Reopen": a new controller over the same store/config.
        let _ = makeController(dir: dir)
        XCTAssertEqual(store.readBootstrap()?.configFingerprint, tenantFP,
                       "reopen replaced the pinned identity")
        // And the engine still loads ready.
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertTrue(engine.isReady)
    }

    /// A managed-configuration change clears rules and re-bootstraps
    /// with a placeholder (fail closed until the next sync).
    func testConfigChangeClearsAndRebootstraps() async throws {
        fullServer()
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (first, store) = makeController(dir: dir)
        await first.syncNow()
        XCTAssertNotNil(try store.load())
        // Same tenant, DIFFERENT dataset endpoint. The supported
        // switch is the app's atomic adoption path (epoch advance +
        // identity clear + mirror, under one lock).
        let newConfig = AppConfiguration(
            controlPlaneBaseURL: base, deviceID: 7,
            datasetBaseURL: URL(string: "https://other.example")!)
        try store.adoptConfiguration(newConfig)
        XCTAssertNil(try store.load(), "old rules survived config change")
        XCTAssertTrue(FilterRuleStore.sameIdentity(
            store.mirroredConfiguration()!, newConfig))
        // A NEW controller for the adopted configuration re-pins the
        // bootstrap and is accepted (not treated as stale).
        let next = FilterSyncController(
            configuration: newConfig,
            credentials: boundCreds(dataset: "tok",
                datasetURL: URL(string: "https://other.example")!),
            session: session(), ruleStore: store, prefilterFile: nil)
        if case .notConfigured = next.state {
            XCTFail("new-configuration controller refused its own config")
        }
        let boot = store.readBootstrap()
        let endpointFP = FilterRuleStore.configFingerprint(
            controlPlane: base,
            dataset: URL(string: "https://other.example")!,
            doh: nil, tenantID: 0, deviceID: 7)
        XCTAssertEqual(boot?.configFingerprint, endpointFP)
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertFalse(engine.isReady)
    }
}

// MARK: - Corruption recovery (review: dead-end finding)

final class CorruptionRecoveryTests: XCTestCase {
    let cp = URL(string: "https://cp.example.test")!
    let ds = URL(string: "https://ds.example.test")!
    func fp(_ tenant: Int) -> String {
        FilterRuleStore.configFingerprint(controlPlane: cp, dataset: ds,
                                          doh: nil, tenantID: tenant,
                                          deviceID: 7)
    }
    func snap(_ generation: Int, _ tenant: Int = 11) -> FilterRuleSnapshot {
        FilterRuleSnapshot(generation: generation, policyID: 3,
                           defaultPolicy: "allow",
                           rules: ["bad.example": true],
                           tenantID: tenant, deviceID: 7,
                           configFingerprint: fp(tenant), fetchedAt: Date())
    }
    func makeStore() throws -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }
    func corrupt(_ store: FilterRuleStore) throws {
        var bytes = [UInt8](try Data(contentsOf: store.snapshotFile))
        bytes[bytes.count / 2] ^= 0xFF
        try Data(bytes).write(to: store.snapshotFile)
    }

    /// Seeded corrupt store + fresh same-identity published snapshot
    /// -> safe replace and ready (availability without fail-open).
    func testCorruptStoreRecoversWithSameIdentityFreshSnapshot() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(FilterBootstrap(
            configFingerprint: fp(11), endpointFingerprint: fp(0)))
        try store.save(snap(5))
        try corrupt(store)
        // The replacement must verify against the CURRENT identity.
        try store.save(snap(6))
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertTrue(engine.isReady)
        XCTAssertEqual(engine.verdict(forHost: "bad.example"), .block)
    }

    /// A replayed OLDER generation must not recover a corrupt store:
    /// the independent floor survives the corruption.
    func testCorruptStoreRejectsReplayedOlderGeneration() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(FilterBootstrap(
            configFingerprint: fp(11), endpointFingerprint: fp(0)))
        try store.save(snap(5))
        try corrupt(store)
        XCTAssertThrowsError(try store.save(snap(4))) {
            XCTAssertEqual($0 as? FilterRuleStoreError, .staleGeneration)
        }
    }

    /// A corrupt store must never be replaced by a DIFFERENT identity
    /// (the corrupt file cannot vouch for a switch).
    func testCorruptStoreRejectsIdentitySwitch() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(FilterBootstrap(
            configFingerprint: fp(11), endpointFingerprint: fp(0)))
        try store.save(snap(5))
        try corrupt(store)
        XCTAssertThrowsError(try store.save(snap(6, 22))) {
            XCTAssertEqual($0 as? FilterRuleStoreError, .invalidSnapshot)
        }
    }

    /// No identity record at all: no recovery path.
    func testCorruptStoreWithoutBootstrapCannotRecover() throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(FilterBootstrap(
            configFingerprint: fp(11), endpointFingerprint: fp(0)))
        try store.save(snap(5))
        try corrupt(store)
        try FileManager.default.removeItem(at: store.bootstrapFile)
        XCTAssertThrowsError(try store.save(snap(6))) {
            XCTAssertEqual($0 as? FilterRuleStoreError, .invalidSnapshot)
        }
    }

    /// End to end: controller sync recovers a corrupt store (fresh
    /// published response), state is synced and the engine is ready.
    func testSyncRecoversCorruptStore() async throws {
        let base = URL(string: "https://fixture.example")!
        let fixtureFP = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 11, deviceID: 7)
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.saveBootstrap(FilterBootstrap(
            configFingerprint: fixtureFP,
            endpointFingerprint: FilterRuleStore.configFingerprint(
                controlPlane: base, dataset: base, doh: nil,
                tenantID: 0, deviceID: 7)))
        try store.save(FilterRuleSnapshot(
            generation: 1, policyID: 3, defaultPolicy: "allow",
            rules: ["old.example": true], tenantID: 11, deviceID: 7,
            configFingerprint: fixtureFP, fetchedAt: Date()))
        try corrupt(store)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [FixtureProtocol.self]
        FixtureProtocol.handler = { req in
            let path = req.url!.path
            let rules = #"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{"bad.example":true}}"#
            let manifest = #"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#
            return (200, [:], Data((path.hasSuffix("filter-rules") ? rules : path.hasSuffix("manifest") ? manifest : "abc").utf8))
        }
        let controller = FilterSyncController(
            configuration: AppConfiguration(controlPlaneBaseURL: base,
                                            deviceID: 7,
                                            datasetBaseURL: base),
            credentials: boundCreds(dataset: "tok"),
            session: URLSession(configuration: cfg), ruleStore: store,
            prefilterFile: dir.appendingPathComponent("prefilter.json"))
        await controller.syncNow()
        guard case .synced = controller.state else {
            return XCTFail("expected synced, got \(controller.state)")
        }
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertTrue(engine.isReady)
        XCTAssertEqual(engine.verdict(forHost: "bad.example"), .block)
    }
}

// MARK: - Round 5: durable session epoch, credential origin, floor
// integrity, maintenance policy, static build-config guards

final class SessionEpochTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ deviceID: Int = 7) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: deviceID,
                         datasetBaseURL: base)
    }
    func session() -> URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: c)
    }
    func makeStore() -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }
    let rulesBody = #"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{"bad.example":true}}"#
    let manifestBody = #"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#

    /// Reviewer regression: a slow HTTP response from the OLD managed
    /// configuration must not reinstall the old identity after the
    /// configuration changed mid-flight. The app's adoption path
    /// (adoptConfiguration) advances the durable epoch; the in-flight
    /// sync's commit then fails under the same lock.
    func testOldHTTPResponseCannotUndoConfigurationChange() async throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sut = FilterSyncController(
            configuration: cfg(7), credentials: boundCreds(dataset: "tok"),
            session: session(), ruleStore: store,
            prefilterFile: dir.appendingPathComponent("pre.json"))
        FixtureProtocol.handler = { req in
            if req.url!.path.hasSuffix("filter-rules") {
                // The app adopts the pushed configuration (device 8)
                // while the old sync's request is in flight.
                try? store.adoptConfiguration(self.cfg(8))
                return (200, [:], Data(self.rulesBody.utf8))
            }
            return (200, [:], Data((req.url!.path.hasSuffix("manifest")
                ? self.manifestBody : "abc").utf8))
        }
        await sut.syncNow()
        guard case .invalidated = sut.state else {
            return XCTFail("expected invalidated, got \(sut.state)")
        }
        XCTAssertNil(try store.load(),
                     "old response reinstalled old device policy")
        XCTAssertTrue(FilterRuleStore.sameIdentity(
            store.mirroredConfiguration()!, cfg(8)))
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "unknown.example"),
                       .block)
    }

    /// Sign-out while the rules request is in flight: the awaited
    /// response must be discarded, never committed.
    func testSignOutDuringFlightDiscardsResponse() async throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sut = FilterSyncController(
            configuration: cfg(), credentials: boundCreds(dataset: "tok"),
            session: session(), ruleStore: store,
            prefilterFile: dir.appendingPathComponent("pre.json"))
        FixtureProtocol.handler = { req in
            if req.url!.path.hasSuffix("filter-rules") {
                try? store.clear() // sign-out's authoritative clear
                return (200, [:], Data(self.rulesBody.utf8))
            }
            return (200, [:], Data((req.url!.path.hasSuffix("manifest")
                ? self.manifestBody : "abc").utf8))
        }
        await sut.syncNow()
        guard case .invalidated = sut.state else {
            return XCTFail("expected invalidated, got \(sut.state)")
        }
        XCTAssertNil(try store.load(),
                     "response committed after sign-out")
    }

    /// Two instances: a process still holding the OLD configuration
    /// (e.g. a control provider started before the adoption) must not
    /// clear, re-bootstrap or re-mirror the store.
    func testStaleInstanceCannotResurrectOldIdentity() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = FilterSyncController(
            configuration: cfg(7), credentials: boundCreds(),
            session: session(), ruleStore: store, prefilterFile: nil)
        try store.adoptConfiguration(cfg(8))
        let stale = FilterSyncController(
            configuration: cfg(7), credentials: boundCreds(),
            session: session(), ruleStore: store, prefilterFile: nil)
        guard case .notConfigured = stale.state else {
            return XCTFail("stale instance not refused: \(stale.state)")
        }
        XCTAssertTrue(FilterRuleStore.sameIdentity(
            store.mirroredConfiguration()!, cfg(8)),
            "stale instance overwrote the mirror")
        XCTAssertNil(store.readBootstrap(),
                     "stale instance re-pinned the old identity")
    }

    /// Store-level: a commit captured before an invalidation cannot
    /// land afterwards.
    func testCommitRejectsStaleEpoch() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.mirrorConfiguration(cfg())
        let epoch = store.currentEpoch()!
        try store.clear()
        let fp = String(repeating: "a", count: 64)
        XCTAssertThrowsError(try store.commit(
            snapshot: nil,
            bootstrap: FilterBootstrap(configFingerprint: fp,
                                       endpointFingerprint: fp),
            expectedEpoch: epoch)) {
            XCTAssertEqual($0 as? FilterRuleStoreError,
                           .staleSessionEpoch)
        }
        XCTAssertNil(store.readBootstrap())
    }

    /// Credential origin binding: mismatched or absent metadata means
    /// the credential's origin cannot be proven - fail closed, never
    /// send the old bearer token to the configured origin.
    func testMismatchedCredentialOriginIsSignedOut() async throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let wrongOrigin = String(repeating: "f", count: 64)
        let wrong = FakeCredentials([CredentialBundle.storageKey:
            makeBundle(origin: wrongOrigin, dataset: "tok")])
        let sut = FilterSyncController(
            configuration: cfg(), credentials: wrong,
            session: session(), ruleStore: store, prefilterFile: nil)
        await sut.syncNow()
        XCTAssertEqual(sut.state, .signedOut)
    }

    func testUnboundCredentialIsSignedOut() async throws {
        let sut = FilterSyncController(
            configuration: cfg(),
            credentials: FakeCredentials(["session": "fixture",
                                          "credential.dataset": "tok"]),
            session: session(), ruleStore: nil, prefilterFile: nil)
        await sut.syncNow()
        XCTAssertEqual(sut.state, .signedOut)
    }
}

final class FloorIntegrityTests: XCTestCase {
    func makeStore() -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (FilterRuleStore(directory: dir), dir)
    }

    /// Reviewer regression: published generations are monotonic per
    /// identity ACROSS policies (the tenant's published revision does
    /// not reset on a policy switch).
    func testPolicySwitchCannotRollBackTenantGeneration() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fp = String(repeating: "a", count: 64)
        try store.saveBootstrap(FilterBootstrap(configFingerprint: fp,
                                                endpointFingerprint: fp))
        try store.save(FilterRuleSnapshot(
            generation: 10, policyID: 3, defaultPolicy: "block",
            rules: [:], tenantID: 11, deviceID: 7,
            configFingerprint: fp, fetchedAt: Date()))
        XCTAssertThrowsError(try store.save(FilterRuleSnapshot(
            generation: 2, policyID: 2, defaultPolicy: "allow",
            rules: [:], tenantID: 11, deviceID: 7,
            configFingerprint: fp, fetchedAt: Date()))) {
            XCTAssertEqual($0 as? FilterRuleStoreError, .staleGeneration)
        }
    }

    /// A corrupt floor file is NOT "no floor": writes fail closed.
    func testCorruptFloorFailsClosed() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fp = String(repeating: "a", count: 64)
        try store.saveBootstrap(FilterBootstrap(configFingerprint: fp,
                                                endpointFingerprint: fp))
        try store.save(FilterRuleSnapshot(
            generation: 5, policyID: 3, defaultPolicy: "allow",
            rules: [:], tenantID: 11, deviceID: 7,
            configFingerprint: fp, fetchedAt: Date()))
        try Data("not json".utf8).write(to: store.floorFile)
        XCTAssertThrowsError(try store.save(FilterRuleSnapshot(
            generation: 6, policyID: 3, defaultPolicy: "allow",
            rules: [:], tenantID: 11, deviceID: 7,
            configFingerprint: fp, fetchedAt: Date()))) {
            XCTAssertEqual($0 as? FilterRuleStoreError, .unreadableFloor)
        }
    }
}

final class MaintenancePolicyTests: XCTestCase {
    func testRoutineIntervalAfterSuccess() {
        XCTAssertEqual(MaintenancePolicy.nextInterval(failures: 0), 3600)
    }
    func testExponentialBackoffBounded() {
        XCTAssertEqual(MaintenancePolicy.nextInterval(failures: 1), 300)
        XCTAssertEqual(MaintenancePolicy.nextInterval(failures: 2), 600)
        XCTAssertEqual(MaintenancePolicy.nextInterval(failures: 3), 1200)
        XCTAssertEqual(MaintenancePolicy.nextInterval(failures: 4), 2400)
        XCTAssertEqual(MaintenancePolicy.nextInterval(failures: 5), 3600)
        XCTAssertEqual(MaintenancePolicy.nextInterval(failures: 50), 3600,
                       "backoff never exceeds the routine interval")
    }
}

/// Background policy-refresh scheduling: plist/code parity and the
/// refresh cadence. The OS-discretion safety story (fail-closed
/// use-time expiry when no refresh ever runs) is proven by
/// FilterVerdictEngineTests.testExpiredSnapshotFailsClosedPerFlow
/// and URLFilterPrefilterSourceTests.testExpiredArtifactIsInvalidAtUseTime.
final class BackgroundRefreshPolicyTests: XCTestCase {
    func repoRoot() throws -> URL {
        guard let root = ProcessInfo.processInfo
            .environment["KG_REPO_ROOT"]
        else { throw XCTSkip("KG_REPO_ROOT not set") }
        return URL(fileURLWithPath: root)
    }

    /// The registered task identifier MUST be declared in the app's
    /// Info.plist (BGTaskSchedulerPermittedIdentifiers) with the
    /// fetch background mode, or registration traps at runtime on
    /// device. Code and plist can drift silently; this is the parity
    /// check between them.
    func testPlistDeclaresBackgroundRefreshTask() throws {
        let root = try repoRoot()
        let data = try Data(contentsOf: root.appendingPathComponent(
            "ios/Configuration/App-Info.plist"))
        let plist = try PropertyListSerialization.propertyList(
            from: data, format: nil) as? [String: Any]
        let identifiers = plist?["BGTaskSchedulerPermittedIdentifiers"]
            as? [String] ?? []
        XCTAssertTrue(
            identifiers.contains(BackgroundRefreshPolicy.taskIdentifier),
            "App-Info.plist must permit "
                + BackgroundRefreshPolicy.taskIdentifier)
        let modes = plist?["UIBackgroundModes"] as? [String] ?? []
        XCTAssertTrue(modes.contains("fetch"),
                      "App-Info.plist must declare the fetch mode")
    }

    /// The identifier is pinned: a silent rename would break both the
    /// plist parity and the on-device registration.
    func testTaskIdentifierPinned() {
        XCTAssertEqual(BackgroundRefreshPolicy.taskIdentifier,
                       "com.kosherguard.app.policy-refresh")
    }

    /// Cadence: the routine interval after success, bounded backoff
    /// after failures (the tested MaintenancePolicy values).
    func testEarliestBeginDateFollowsMaintenancePolicy() {
        let now = Date()
        XCTAssertEqual(
            BackgroundRefreshPolicy.earliestBeginDate(
                now: now, consecutiveFailures: 0),
            now.addingTimeInterval(MaintenancePolicy.routineInterval))
        XCTAssertEqual(
            BackgroundRefreshPolicy.earliestBeginDate(
                now: now, consecutiveFailures: 1),
            now.addingTimeInterval(MaintenancePolicy.minBackoff))
        XCTAssertEqual(
            BackgroundRefreshPolicy.earliestBeginDate(
                now: now, consecutiveFailures: 12),
            now.addingTimeInterval(MaintenancePolicy.routineInterval),
            "backoff is capped at the routine interval")
    }
}

/// Static build-configuration guards: the portable suite compiles a
/// copied-source harness, NOT the Xcode target graph - these tests
/// statically verify the hand-authored project stays consistent.
final class BuildConfigGuardTests: XCTestCase {
    func repoRoot() throws -> URL {
        guard let root = ProcessInfo.processInfo
            .environment["KG_REPO_ROOT"]
        else { throw XCTSkip("KG_REPO_ROOT not set") }
        return URL(fileURLWithPath: root)
    }

    /// Every type referenced by a target's member sources must be
    /// defined by a member of the SAME target (the extensions do not
    /// link a URLFilter module; sources are compiled per-target).
    func testXcodeTargetSourceMembershipClosure() throws {
        let root = try repoRoot()
        let sourcesDir = root.appendingPathComponent("ios/Sources")
        var typeToFile: [String: String] = [:]
        var fileText: [String: String] = [:]
        let enumerator = FileManager.default.enumerator(
            at: sourcesDir, includingPropertiesForKeys: nil)!
        for case let file as URL in enumerator
        where file.pathExtension == "swift" {
            let text = try String(contentsOf: file, encoding: .utf8)
            fileText[file.lastPathComponent] = text
            // Private declarations are file-scoped: invisible to
            // other files, so they can neither satisfy nor break the
            // per-target closure and are excluded from the registry.
            for match in text.matches(of:
                #/(?:(private)\s+)?(?:final class|class|struct|enum|protocol)\s+([A-Z][A-Za-z0-9_]*)/#) {
                guard match.1 == nil else { continue }
                typeToFile[String(match.2)] = file.lastPathComponent
            }
        }
        let pbx = try String(contentsOf: root.appendingPathComponent(
            "ios/KosherGuard.xcodeproj/project.pbxproj"),
            encoding: .utf8)
        let lines = pbx.components(separatedBy: .newlines)
        // target name -> its Sources build phase ids
        var targetPhases: [String: [String]] = [:]
        for line in lines where line.contains("isa = PBXNativeTarget") {
            guard let marker = line.range(of: " = {isa = PBXNativeTarget"),
                  let open = line.range(of: "/* ")
            else { continue }
            let name = String(line[open.upperBound..<marker.lowerBound]
                .dropLast(2)) // strip trailing " */"
            var phases: [String] = []
            for m in line.matches(of:
                #/(KG[0-9a-f]{22}) \/\* Sources \*\//#) {
                phases.append(String(m.1))
            }
            targetPhases[name] = phases
        }
        // phase id -> member swift files
        var phaseFiles: [String: [String]] = [:]
        for line in lines where line.contains(
            "isa = PBXSourcesBuildPhase") {
            let trimmed = line.drop(while: { $0 == " " || $0 == "\t" })
            guard trimmed.hasPrefix("KG"), trimmed.count >= 24
            else { continue }
            let id = String(trimmed.prefix(24))
            phaseFiles[id] = line.matches(of:
                #/\/\* ([A-Za-z]+\.swift) in Sources \*\//#)
                .map { String($0.1) }
        }
        var failures: [String] = []
        for (target, phases) in targetPhases {
            let members = Set(phases.flatMap { phaseFiles[$0] ?? [] })
            XCTAssertFalse(members.isEmpty,
                           "\(target): no member sources parsed")
            for file in members {
                guard let text = fileText[file] else {
                    failures.append("\(target): \(file) not on disk")
                    continue
                }
                // Strip line comments so prose mentioning a type does
                // not count as a reference.
                let code = text.components(separatedBy: .newlines)
                    .map { String($0.components(separatedBy: "//")
                        .first ?? "") }
                    .joined(separator: "\n")
                let tokens = Set(code.components(
                    separatedBy: CharacterSet.alphanumerics.inverted))
                for token in tokens {
                    guard let defining = typeToFile[token],
                          defining != file,
                          !members.contains(defining)
                    else { continue }
                    failures.append("\(target): \(file) references "
                        + "\(token) (defined in \(defining), "
                        + "not a member of the target)")
                }
            }
        }
        XCTAssertTrue(failures.isEmpty,
                      failures.joined(separator: "\n"))
    }

    /// Every object ID in the project must be unique (a duplicate ID
    /// silently rebinds an unrelated object), every build file's
    /// fileRef must resolve, and the embed phase may only copy
    /// extension PRODUCTS, never source build files.
    func testXcodeProjectStructuralIntegrity() throws {
        let root = try repoRoot()
        let pbx = try String(contentsOf: root.appendingPathComponent(
            "ios/KosherGuard.xcodeproj/project.pbxproj"),
            encoding: .utf8)
        // Definitions: lines that start (after whitespace) with the
        // ID followed by " = {isa =".
        var definitions: [String: Int] = [:]
        var duplicates: [String] = []
        for line in pbx.components(separatedBy: .newlines) {
            guard line.contains(" = {isa = "),
                  let match = line.firstMatch(of:
                    #/^\s*(KG[0-9a-fA-F]{22})[ \t]/#)
            else { continue }
            let id = String(match.1)
            definitions[id, default: 0] += 1
            if definitions[id] == 2 { duplicates.append(id) }
        }
        XCTAssertTrue(duplicates.isEmpty,
                      "duplicate object IDs: \(duplicates)")
        // Every fileRef / target / targetProxy reference resolves to
        // a definition.
        var unresolved: [String] = []
        for line in pbx.components(separatedBy: .newlines) {
            for match in line.matches(of:
                #/(?:fileRef|target|targetProxy|productReference|containerPortal) = (KG[0-9a-fA-F]{22})/#) {
                let ref = String(match.1)
                if definitions[ref] == nil { unresolved.append(ref) }
            }
        }
        XCTAssertTrue(unresolved.isEmpty,
                      "unresolved references: \(unresolved)")
        // The embed phase copies only wrapper.app-extension products.
        for line in pbx.components(separatedBy: .newlines)
        where line.contains("PBXCopyFilesBuildPhase") {
            for match in line.matches(of:
                #/(KG[0-9a-fA-F]{22}) \/\* [^*]*\.appex in Embed [^*]*\*\//#) {
                let buildFile = String(match.1)
                // Find the build file's fileRef and that product's type.
                guard let bfLine = pbx.components(separatedBy: .newlines)
                    .first(where: {
                        $0.hasPrefix("\t\t" + buildFile + " ") }),
                      let refMatch = bfLine.firstMatch(of:
                        #/fileRef = (KG[0-9a-fA-F]{22})/#),
                      let productLine = pbx.components(
                        separatedBy: .newlines).first(where: {
                        $0.hasPrefix("\t\t" + String(refMatch.1) + " ") })
                else {
                    XCTFail("embed entry \(buildFile) does not resolve")
                    continue
                }
                XCTAssertTrue(
                    productLine.contains("wrapper.app-extension"),
                    "embed entry \(buildFile) is not an app-extension "
                    + "product: \(productLine)")
            }
        }
    }

    /// The shared keychain access group literal in code must match
    /// the keychain-access-groups entitlement of every target, and
    /// the app group entitlement must match the store's app-group id.
    func testEntitlementConsistency() throws {
        let root = try repoRoot()
        let keychainSrc = try String(contentsOf:
            root.appendingPathComponent(
                "ios/Sources/URLFilter/KeychainCredentialStore.swift"),
            encoding: .utf8)
        guard let groupMatch = keychainSrc.firstMatch(of:
            #/sharedAccessGroup =\s*"([^"]+)"/#)
        else { return XCTFail("sharedAccessGroup literal not found") }
        let sharedGroup = String(groupMatch.1)
        let storeSrc = try String(contentsOf: root.appendingPathComponent(
            "ios/Sources/URLFilter/FilterRuleStore.swift"),
            encoding: .utf8)
        guard let appGroupMatch = storeSrc.firstMatch(of:
            #/appGroupIdentifier =\s*"([^"]+)"/#)
        else { return XCTFail("appGroupIdentifier literal not found") }
        let appGroup = String(appGroupMatch.1)
        for name in ["App.entitlements", "FilterExtension.entitlements",
                     "FilterControlExtension.entitlements"] {
            let plist = try String(contentsOf: root.appendingPathComponent(
                "ios/Configuration/" + name), encoding: .utf8)
            XCTAssertTrue(plist.contains("<string>" + sharedGroup
                + "</string>"),
                "\(name): keychain-access-groups != code placeholder")
            XCTAssertTrue(plist.contains("<string>" + appGroup
                + "</string>"),
                "\(name): app group != FilterRuleStore identifier")
        }
    }
}


// MARK: - Round 6: reviewer race regressions (new identity already
// installed before the old response arrives)

final class LateResponseRaceTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ id: Int) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: id,
                         datasetBaseURL: base)
    }
    func session() -> URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: c)
    }
    /// A NEW device identity (device 8) fully adopted AND synced while
    /// the old device-7 sync is still awaiting its response.
    func seedNew(_ store: FilterRuleStore) throws {
        try store.adoptConfiguration(cfg(8))
        let fp = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 11, deviceID: 8)
        let ep = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: 8)
        try store.commit(
            snapshot: FilterRuleSnapshot(
                generation: 10, policyID: 3, defaultPolicy: "block",
                rules: [:], tenantID: 11, deviceID: 8,
                configFingerprint: fp, fetchedAt: Date()),
            bootstrap: FilterBootstrap(configFingerprint: fp,
                                       endpointFingerprint: ep),
            expectedEpoch: store.currentEpoch()!)
    }
    func runRace(status: Int) async throws
        -> (FilterRuleSnapshot?, FilterSyncController.State) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        let ep = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: 7)
        let sut = FilterSyncController(
            configuration: cfg(7),
            credentials: FakeCredentials([CredentialBundle.storageKey:
                makeBundle(origin: ep, dataset: "tok")]),
            session: session(), ruleStore: store,
            prefilterFile: dir.appendingPathComponent("pre.json"))
        FixtureProtocol.handler = { req in
            if req.url!.path.hasSuffix("filter-rules") {
                try? self.seedNew(store)
                return (status, [:], Data(#"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{}}"#.utf8))
            }
            let manifest = #"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#
            return (200, [:], Data((req.url!.path.hasSuffix("manifest")
                ? manifest : "abc").utf8))
        }
        await sut.syncNow()
        return (try store.load(), sut.state)
    }

    /// Reviewer regression: a late SUCCESS from the old identity must
    /// not clear or displace the fully-synced new identity.
    func testLateOldSuccessCannotClearNewSyncedIdentity() async throws {
        let (result, state) = try await runRace(status: 200)
        XCTAssertEqual(result?.deviceID, 8)
        XCTAssertEqual(result?.generation, 10)
        guard case .invalidated = state else {
            XCTFail("old session ended as \(state)"); return
        }
    }

    /// Reviewer regression: a late REJECTION from the old identity
    /// must not invalidate the fully-synced new identity.
    func testLateOldRejectionCannotClearNewSyncedIdentity() async throws {
        let (result, state) = try await runRace(status: 401)
        XCTAssertEqual(result?.deviceID, 8)
        XCTAssertEqual(result?.generation, 10)
        guard case .invalidated = state else {
            XCTFail("old session ended as \(state)"); return
        }
    }

    /// Sign-out during the DATASET phase: the staged prefilter must
    /// never become durable; the destination must stay absent.
    func testStaleFetchCannotRecreatePrefilterArtifact() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        let destination = dir.appendingPathComponent("pre.json")
        let sut = FilterSyncController(
            configuration: cfg(7),
            credentials: boundCreds(dataset: "tok"),
            session: session(), ruleStore: store,
            prefilterFile: destination)
        FixtureProtocol.handler = { req in
            if req.url!.path.hasSuffix("manifest") {
                try? store.clear() // sign-out mid-fetch
                return (200, [:], Data(self.manifestForRace.utf8))
            }
            if req.url!.path.hasSuffix("filter-rules") {
                return (200, [:], Data(#"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{}}"#.utf8))
            }
            return (200, [:], Data("abc".utf8))
        }
        await sut.syncNow()
        guard case .invalidated = sut.state else {
            XCTFail("expected invalidated, got \(sut.state)"); return
        }
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: destination.path),
            "stale fetch recreated the prefilter after sign-out")
    }
    let manifestForRace = #"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#

    /// Store level: a staged artifact cannot be committed under an
    /// epoch advanced by an intervening invalidation.
    func testCommitArtifactRejectsStaleEpoch() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(atPath: dir.path,
                                                withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        let epoch = store.currentEpoch()!
        let staged = dir.appendingPathComponent("staged.json")
        try Data("x".utf8).write(to: staged)
        try store.clear() // invalidation advances the epoch
        XCTAssertThrowsError(try store.commitArtifact(
            from: staged, to: dir.appendingPathComponent("pre.json"),
            expectedEpoch: epoch)) {
            XCTAssertEqual($0 as? FilterRuleStoreError,
                           .staleSessionEpoch)
        }
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dir.appendingPathComponent("pre.json").path))
    }
}

// MARK: - Round 6b: admission is enforced in syncNow, not only at init

final class AdmissionTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ id: Int) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: id,
                         datasetBaseURL: base)
    }

    /// A controller holding the OLD configuration must be refused by
    /// syncNow itself (admission), never reaching the network - even
    /// though its captured credentials are well-formed.
    func testStaleControllerSyncNowRefusedBeforeNetwork() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        _ = FilterSyncController(configuration: cfg(7),
                                 credentials: boundCreds(),
                                 session: .shared, ruleStore: store,
                                 prefilterFile: nil)
        try store.adoptConfiguration(cfg(8))
        var requests = 0
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [FixtureProtocol.self]
        FixtureProtocol.handler = { _ in
            requests += 1
            return (200, [:], Data())
        }
        let stale = FilterSyncController(configuration: cfg(7),
                                         credentials: boundCreds(),
                                         session: URLSession(configuration: c),
                                         ruleStore: store,
                                         prefilterFile: nil)
        await stale.syncNow()
        guard case .notConfigured = stale.state else {
            XCTFail("stale sync not refused: \(stale.state)"); return
        }
        XCTAssertEqual(requests, 0, "stale controller reached network")
        XCTAssertTrue(FilterRuleStore.sameIdentity(
            store.mirroredConfiguration()!, cfg(8)))
    }

    /// A corrupt epoch record denies admission entirely (fail closed):
    /// no nonce can be captured, so no request is made.
    func testCorruptEpochDeniesAdmission() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        _ = FilterSyncController(configuration: cfg(7),
                                 credentials: boundCreds(),
                                 session: .shared, ruleStore: store,
                                 prefilterFile: nil)
        try Data("garbage".utf8).write(to: store.epochFile)
        var requests = 0
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [FixtureProtocol.self]
        FixtureProtocol.handler = { _ in
            requests += 1
            return (200, [:], Data())
        }
        let sut = FilterSyncController(configuration: cfg(7),
                                       credentials: boundCreds(),
                                       session: URLSession(configuration: c),
                                       ruleStore: store,
                                       prefilterFile: nil)
        await sut.syncNow()
        guard case .notConfigured = sut.state else {
            XCTFail("corrupt-epoch sync not refused: \(sut.state)")
            return
        }
        XCTAssertEqual(requests, 0)
    }
}

// MARK: - Round 7: tombstone admission + reader binding + revision immutability

final class SixthReviewRegressionTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg() -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: 7,
                         datasetBaseURL: base)
    }
    // Adapted from the independent reviewer's proof (SixthReviewRegressions):
    // an invalidated configuration must not be re-admitted or re-mirrored.
    func testInvalidatedConfigurationCannotBeReadmittedByStaleInstance() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let old = try XCTUnwrap(store.admit(configuration: cfg()))
        try store.invalidateConfiguration()
        XCTAssertNotEqual(old, store.currentEpoch())
        XCTAssertNil(store.admit(configuration: cfg()),
                     "missing mirror after invalidation must not authorize")
        _ = FilterSyncController(configuration: cfg(),
                                 credentials: FakeCredentials([:]),
                                 ruleStore: store, prefilterFile: nil)
        XCTAssertNil(store.mirroredConfiguration(),
                     "stale constructor must not recreate tombstoned mirror")
    }
    // Adapted reviewer proof: a rotated authority marker must revoke the
    // reader even when the identity-file deletions never ran.
    func testLifecycleMarkerRotationMustInvalidateReaderEvenIfDeletionFails() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let nonce = try XCTUnwrap(store.admit(configuration: cfg()))
        let fp = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 11, deviceID: 7)
        let ep = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: 7)
        try store.commit(
            snapshot: FilterRuleSnapshot(
                generation: 10, policyID: 3, defaultPolicy: "allow",
                rules: [:], tenantID: 11, deviceID: 7,
                configFingerprint: fp, fetchedAt: Date()),
            bootstrap: FilterBootstrap(configFingerprint: fp,
                                       endpointFingerprint: ep),
            expectedEpoch: nonce)
        let engine = FilterVerdictEngine(store: store)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "unknown.example"), .allow)
        // Invalidation marker written; interruption before removals.
        let bytes = try JSONEncoder().encode(
            FilterRuleStore.EpochRecord(nonce: UUID().uuidString))
        try bytes.write(to: store.epochFile, options: .atomic)
        engine.reloadIfChanged()
        XCTAssertEqual(engine.verdict(forHost: "unknown.example"), .block,
                       "reader ignored the lifecycle invalidation marker")
    }
    // A fresh install (no tombstone) still admits after the init mirror.
    func testFreshInstallStillAdmitsAfterInitMirror() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        _ = FilterSyncController(configuration: cfg(),
                                 credentials: FakeCredentials([:]),
                                 ruleStore: store, prefilterFile: nil)
        XCTAssertNotNil(store.admit(configuration: cfg()))
    }
    // Adoption is the ONLY path that lifts a tombstone.
    func testAdoptionLiftsTombstoneAndReadmits() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        _ = store.admit(configuration: cfg())
        try store.invalidateConfiguration()
        XCTAssertTrue(store.isTombstoned())
        try store.adoptConfiguration(cfg())
        XCTAssertFalse(store.isTombstoned())
        XCTAssertNotNil(store.admit(configuration: cfg()))
    }
    // Sign-in session rotation is conditional on the attempt token.
    func testRotateAuthorityIsConditional() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let nonce = try XCTUnwrap(store.admit(configuration: cfg()))
        XCTAssertNil(store.rotateAuthority(expectedEpoch: "wrong"))
        XCTAssertEqual(store.currentEpoch(), nonce)
        let rotated = try XCTUnwrap(
            store.rotateAuthority(expectedEpoch: nonce))
        XCTAssertNotEqual(rotated, nonce)
        XCTAssertEqual(store.currentEpoch(), rotated)
        // The OLD attempt token is dead now.
        XCTAssertNil(store.rotateAuthority(expectedEpoch: nonce))
    }
}

final class RevisionImmutabilityTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg() -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: 7,
                         datasetBaseURL: base)
    }
    private func makeStore() throws -> (FilterRuleStore, URL, String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let nonce = try XCTUnwrap(store.admit(configuration: cfg()))
        return (store, dir, nonce)
    }
    private func snap(gen: Int, policy: Int, fp: String) -> FilterRuleSnapshot {
        FilterRuleSnapshot(generation: gen, policyID: policy,
                           defaultPolicy: "allow", rules: [:],
                           tenantID: 11, deviceID: 7,
                           configFingerprint: fp, fetchedAt: Date())
    }
    private func boot(fp: String) -> FilterBootstrap {
        let ep = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: 7)
        return FilterBootstrap(configFingerprint: fp,
                               endpointFingerprint: ep)
    }
    // Same identity, same generation, DIFFERENT policy content:
    // an immutable published revision rejects the conflict.
    func testSameGenerationDifferentPolicyIsRejected() throws {
        let (store, dir, nonce) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fp = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 11, deviceID: 7)
        try store.commit(snapshot: snap(gen: 5, policy: 1, fp: fp),
                         bootstrap: boot(fp: fp), expectedEpoch: nonce)
        XCTAssertThrowsError(try store.commit(
            snapshot: snap(gen: 5, policy: 2, fp: fp),
            bootstrap: boot(fp: fp), expectedEpoch: nonce)) { error in
            XCTAssertEqual(error as? FilterRuleStoreError,
                           .revisionConflict)
        }
        // The ORIGINAL revision survives the rejected write.
        XCTAssertEqual(try XCTUnwrap(store.load()).policyID, 1)
    }
    // Same identity, same generation, IDENTICAL content: allowed
    // (freshness-only re-delivery).
    func testSameGenerationIdenticalContentIsAllowed() throws {
        let (store, dir, nonce) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fp = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 11, deviceID: 7)
        try store.commit(snapshot: snap(gen: 5, policy: 1, fp: fp),
                         bootstrap: boot(fp: fp), expectedEpoch: nonce)
        XCTAssertNoThrow(try store.commit(
            snapshot: snap(gen: 5, policy: 1, fp: fp),
            bootstrap: boot(fp: fp), expectedEpoch: nonce))
    }
    // A corrupt SNAPSHOT file cannot destroy the immutable proof:
    // the floor's digest still rejects a conflicting same-generation
    // "recovery" write.
    func testCorruptSnapshotRecoveryRetainsFloorProof() throws {
        let (store, dir, nonce) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fp = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 11, deviceID: 7)
        try store.commit(snapshot: snap(gen: 5, policy: 1, fp: fp),
                         bootstrap: boot(fp: fp), expectedEpoch: nonce)
        try Data("corrupt".utf8).write(
            to: dir.appendingPathComponent("filter-rules.json"))
        XCTAssertThrowsError(try store.commit(
            snapshot: snap(gen: 5, policy: 2, fp: fp),
            bootstrap: boot(fp: fp), expectedEpoch: nonce)) { error in
            XCTAssertEqual(error as? FilterRuleStoreError,
                           .revisionConflict)
        }
        // Identical-content recovery at/above the floor still works.
        XCTAssertNoThrow(try store.commit(
            snapshot: snap(gen: 5, policy: 1, fp: fp),
            bootstrap: boot(fp: fp), expectedEpoch: nonce))
    }
}

final class AtomicArtifactTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg() -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: 7,
                         datasetBaseURL: base)
    }
    // commitArtifact replaces the destination atomically; a stale
    // epoch preserves the previous destination entirely.
    func testAtomicReplaceAndStaleEpochPreservation() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let nonce = try XCTUnwrap(store.admit(configuration: cfg()))
        let dest = dir.appendingPathComponent("prefilter-snapshot.json")
        let staged1 = dir.appendingPathComponent("stage1")
        try Data("version-1".utf8).write(to: staged1)
        try store.commitArtifact(from: staged1, to: dest,
                                 expectedEpoch: nonce)
        XCTAssertEqual(String(data: try Data(contentsOf: dest),
                              encoding: .utf8), "version-1")
        let staged2 = dir.appendingPathComponent("stage2")
        try Data("version-2".utf8).write(to: staged2)
        // Stale authority: destination keeps the OLD bytes, staged
        // file is NOT consumed into place.
        XCTAssertThrowsError(try store.commitArtifact(
            from: staged2, to: dest, expectedEpoch: "stale"))
        XCTAssertEqual(String(data: try Data(contentsOf: dest),
                              encoding: .utf8), "version-1")
        // Current authority: atomic replace installs the new bytes.
        try store.commitArtifact(from: staged2, to: dest,
                                 expectedEpoch: nonce)
        XCTAssertEqual(String(data: try Data(contentsOf: dest),
                              encoding: .utf8), "version-2")
    }
}

// MARK: - Round 8: sign-in orchestration, config recovery, prefilter binding

private final class DelayedAuth: SessionSigningIn {
    let cookie: String
    let delayNanos: UInt64
    init(_ cookie: String, delayNanos: UInt64 = 0) {
        self.cookie = cookie; self.delayNanos = delayNanos
    }
    func signIn(email: String, password: String,
                totpCode: String?) async throws -> String {
        if delayNanos > 0 {
            try await Task.sleep(nanoseconds: delayNanos)
        }
        return cookie
    }
}
private final class DelayedIssuance: DatasetCredentialIssuing {
    let token: String
    let delayNanos: UInt64
    let error: Error?
    init(_ token: String, delayNanos: UInt64 = 0, error: Error? = nil) {
        self.token = token; self.delayNanos = delayNanos
        self.error = error
    }
    func mintDatasetCredential(deviceID: Int,
                               sessionCookie: String) async throws -> String {
        if delayNanos > 0 {
            try await Task.sleep(nanoseconds: delayNanos)
        }
        if let error { throw error }
        return token
    }
}

final class SignInCoordinatorTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ device: Int = 7) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: device,
                         datasetBaseURL: base)
    }
    func origin(_ device: Int = 7) -> String {
        FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: device)
    }
    func makeStore() throws -> (FilterRuleStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        _ = store.admit(configuration: cfg())
        return (store, dir)
    }
    // A/B race: the second concurrent attempt is REFUSED, and the
    // surviving attempt stores a complete, consistent bundle.
    func testConcurrentAttemptsAreExclusive() async throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = FakeCredentials([:])
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        let attemptA = Task {
            try await coordinator.signInAndIssue(
                configuration: cfg(),
                email: "a@x", password: "p", totpCode: nil,
                deviceID: 7, origin: origin(),
                auth: DelayedAuth("cookie-A", delayNanos: 300_000_000),
                issuance: DelayedIssuance("dataset-A"),
                currentOrigin: { self.origin() })
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        do {
            try await coordinator.signInAndIssue(
                configuration: cfg(),
                email: "b@x", password: "p", totpCode: nil,
                deviceID: 7, origin: origin(),
                auth: DelayedAuth("cookie-B"),
                issuance: DelayedIssuance("dataset-B"),
                currentOrigin: { self.origin() })
            XCTFail("concurrent attempt admitted")
        } catch SignInCoordinator.SignInError.alreadyInProgress {}
        try await attemptA.value
        let bundle = try XCTUnwrap(CredentialBundle.load(from: vault))
        XCTAssertEqual(bundle.session, "cookie-A")
        XCTAssertEqual(bundle.datasetCredential, "dataset-A")
        XCTAssertEqual(bundle.sessionOrigin, bundle.datasetOrigin)
    }
    // Sign-out mid-flight: the attempt discards everything; NO global
    // credential is ever written.
    func testSignOutMidFlightDiscardsAttempt() async throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = FakeCredentials([:])
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        let attempt = Task {
            try await coordinator.signInAndIssue(
                configuration: cfg(),
                email: "a@x", password: "p", totpCode: nil,
                deviceID: 7, origin: origin(),
                auth: DelayedAuth("cookie-A", delayNanos: 300_000_000),
                issuance: DelayedIssuance("dataset-A"),
                currentOrigin: { self.origin() })
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        try store.clear() // sign-out: authority rotated, identity gone
        do {
            try await attempt.value
            XCTFail("stale attempt succeeded")
        } catch SignInCoordinator.SignInError.staleAttempt {}
        XCTAssertNil(CredentialBundle.load(from: vault),
                     "stale attempt wrote global credentials")
    }
    // Managed-config change mid-flight (adoption rotates authority).
    func testConfigChangeMidFlightDiscardsAttempt() async throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = FakeCredentials([:])
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        let attempt = Task {
            try await coordinator.signInAndIssue(
                configuration: cfg(),
                email: "a@x", password: "p", totpCode: nil,
                deviceID: 7, origin: origin(),
                auth: DelayedAuth("cookie-A", delayNanos: 300_000_000),
                issuance: DelayedIssuance("dataset-A"),
                currentOrigin: { self.origin() })
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        try store.adoptConfiguration(cfg(9)) // MDM pushed new device
        do {
            try await attempt.value
            XCTFail("stale attempt succeeded")
        } catch SignInCoordinator.SignInError.staleAttempt {}
        XCTAssertNil(CredentialBundle.load(from: vault))
    }
    // A rejected mint writes nothing global and rotates nothing.
    func testRejectedMintLeavesNothingGlobal() async throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = FakeCredentials([:])
        let epochBefore = store.currentEpoch()
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        do {
            try await coordinator.signInAndIssue(
                configuration: cfg(),
                email: "a@x", password: "p", totpCode: nil,
                deviceID: 7, origin: origin(),
                auth: DelayedAuth("cookie-A"),
                issuance: DelayedIssuance(
                    "", error: SignInCoordinator.SignInError
                        .sessionRejected),
                currentOrigin: { self.origin() })
            XCTFail("rejected mint succeeded")
        } catch SignInCoordinator.SignInError.sessionRejected {}
        XCTAssertNil(CredentialBundle.load(from: vault))
        XCTAssertEqual(store.currentEpoch(), epochBefore,
                       "a failed attempt must not rotate the authority")
    }
    // Success: authority rotates conditionally, the OLD token is dead,
    // and the bundle is complete and origin-bound.
    func testSuccessRotatesAndStoresAtomicBundle() async throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = FakeCredentials([:])
        let oldToken = try XCTUnwrap(store.currentEpoch())
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        try await coordinator.signInAndIssue(
            configuration: cfg(),
            email: "a@x", password: "p", totpCode: nil,
            deviceID: 7, origin: origin(),
            auth: DelayedAuth("cookie-A"),
            issuance: DelayedIssuance("dataset-A"),
            currentOrigin: { self.origin() })
        let bundle = try XCTUnwrap(CredentialBundle.load(from: vault))
        XCTAssertEqual(bundle.session, "cookie-A")
        XCTAssertEqual(bundle.datasetCredential, "dataset-A")
        XCTAssertEqual(bundle.sessionOrigin, origin())
        XCTAssertNotEqual(store.currentEpoch(), oldToken)
        XCTAssertNil(store.rotateAuthority(expectedEpoch: oldToken),
                     "the old attempt token must be dead")
    }
    // A tombstoned (invalidated) store can never vouch for an attempt.
    func testTombstonedStoreRefusesSignIn() async throws {
        let (store, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.invalidateConfiguration()
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: FakeCredentials([:]))
        do {
            try await coordinator.signInAndIssue(
                configuration: cfg(),
                email: "a@x", password: "p", totpCode: nil,
                deviceID: 7, origin: origin(),
                auth: DelayedAuth("cookie-A"),
                issuance: DelayedIssuance("dataset-A"),
                currentOrigin: { self.origin() })
            XCTFail("tombstoned store admitted sign-in")
        } catch SignInCoordinator.SignInError.storeNotReady {}
    }
}

final class ConfigRecoveryOrchestrationTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ device: Int = 7) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: device,
                         datasetBaseURL: base)
    }
    // THE app-orchestration proof: invalid push -> tombstone ->
    // controller refuses -> VALID config returns -> app adopts ->
    // controller syncs. Not a direct store test: the whole
    // invalid -> valid -> adopt -> sync-ready path.
    func testInvalidThenValidIsAdoptedAndSyncs() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        // First valid configuration: adopted from the app side.
        XCTAssertEqual(
            try ConfigurationApplier.apply(configuration: cfg(),
                                           to: store), .adopted)
        // An invalid push arrives (MDM removal/corruption).
        let invalid = AppConfiguration(controlPlaneBaseURL: nil,
                                       deviceID: nil)
        XCTAssertEqual(
            try ConfigurationApplier.apply(configuration: invalid,
                                           to: store), .invalidated)
        XCTAssertTrue(store.isTombstoned())
        // The controller refuses while tombstoned (fail closed).
        let refused = FilterSyncController(
            configuration: cfg(), credentials: FakeCredentials([:]),
            ruleStore: store, prefilterFile: nil)
        if case .notConfigured = refused.state {} else {
            XCTFail("tombstoned store must refuse the controller")
        }
        // A VALID configuration returns: the app MUST adopt it -
        /// mirror missing AND tombstone present is the recovery case.
        XCTAssertEqual(
            try ConfigurationApplier.apply(configuration: cfg(),
                                           to: store), .adopted)
        XCTAssertFalse(store.isTombstoned())
        XCTAssertNotNil(store.mirroredConfiguration())
        // The sync path works again end to end (admission passes; no
        // credentials yet, so the honest state is signedOut).
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [FixtureProtocol.self]
        let recovered = FilterSyncController(
            configuration: cfg(), credentials: FakeCredentials([:]),
            session: URLSession(configuration: sessionConfig),
            ruleStore: store, prefilterFile: nil)
        XCTAssertEqual(recovered.state, .ready)
        await recovered.syncNow()
        XCTAssertEqual(recovered.state, .signedOut)
    }
    // Same valid configuration twice: the second is a no-op.
    func testSameConfigurationIsAlreadyCurrent() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        XCTAssertEqual(
            try ConfigurationApplier.apply(configuration: cfg(),
                                           to: store), .adopted)
        XCTAssertEqual(
            try ConfigurationApplier.apply(configuration: cfg(),
                                           to: store), .alreadyCurrent)
    }
}

final class PrefilterCacheBindingTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: config)
    }
    // The cached prefilter version is IDENTITY-BOUND: a snapshot from
    // a different server/identity never suppresses the first download
    // from the current one.
    func testRestoreRejectsForeignIdentityCache() async throws {
        FixtureProtocol.handler = { request in
            if request.url!.path.hasSuffix("manifest") {
                return (200, [:], Data(#"{"version":4,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"format":"apple-fnv1a-murmur3-doublehash-v1","bit_count":24,"hash_count":3,"murmur_seed":1262944257,"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#.utf8))
            }
            return (200, [:], Data("abc".utf8))
        }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("prefilter.json")
        let fpA = String(repeating: "a", count: 64)
        let fpB = String(repeating: "b", count: 64)
        var writer = PrefilterUpdater(serverBaseURL: base,
                                      endpointFingerprint: fpA,
                                      session: session())
        _ = try await writer.refresh(credential: "tok",
                                     persistTo: file)
        // Same identity: the cache restores and suppresses duplicates.
        var same = PrefilterUpdater(serverBaseURL: base,
                                    endpointFingerprint: fpA,
                                    session: session())
        XCTAssertNoThrow(try same.restore(from: file))
        XCTAssertEqual(same.currentVersion, 4)
        // DIFFERENT identity (server switch): the cached version must
        // NOT carry over - restore rejects, version stays 0, and the
        // next refresh downloads instead of reporting staleVersion.
        var foreign = PrefilterUpdater(serverBaseURL: base,
                                       endpointFingerprint: fpB,
                                       session: session())
        XCTAssertThrowsError(try foreign.restore(from: file))
        XCTAssertEqual(foreign.currentVersion, 0)
        _ = try await foreign.refresh(credential: "tok")
        XCTAssertEqual(foreign.currentVersion, 4)
    }
}

final class SyncCancellationTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    /// A cross-thread flag for the deterministic gate below.
    private final class Gate {
        private var isOpen = false
        private let lock = NSLock()
        var open: Bool {
            get { lock.lock(); defer { lock.unlock() }; return isOpen }
            set { lock.lock(); isOpen = newValue; lock.unlock() }
        }
    }
    // A cancelled sync must NEVER fetch or commit. The task is
    // cancelled BEFORE syncNow runs (gate), so the top-of-sync
    // cancellation check deterministically stops all work. NOTE:
    // cancelling a task DURING a corelibs URLSession await hangs the
    // await on Linux (platform limitation, proven during this test's
    // development), so the mid-flight checks in syncNow are exercised
    // only on Apple platforms; this test covers the portable boundary.
    func testCancelledSyncNeverFetchesOrCommits() async throws {
        var fetched = false
        FixtureProtocol.handler = { request in
            if request.url!.path.hasSuffix("filter-rules") {
                fetched = true
                return (200, [:], Data(#"{"device_id":7,"tenant_id":11,"policy_id":3,"generation":5,"default_policy":"allow","rules":{}}"#.utf8))
            }
            return (200, [:], Data("abc".utf8))
        }
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(AppConfiguration(
            controlPlaneBaseURL: base, deviceID: 7, datasetBaseURL: base))
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [FixtureProtocol.self]
        let controller = FilterSyncController(
            configuration: AppConfiguration(
                controlPlaneBaseURL: base, deviceID: 7,
                datasetBaseURL: base),
            credentials: boundCreds(dataset: "tok"),
            session: URLSession(configuration: sessionConfig),
            ruleStore: store,
            prefilterFile: dir.appendingPathComponent("pre.json"))
        let gate = Gate()
        let task = Task {
            while !gate.open {
                try? await Task.sleep(nanoseconds: 1_000_000)
            }
            await controller.syncNow()
        }
        task.cancel() // before syncNow starts
        gate.open = true
        await task.value
        XCTAssertTrue(task.isCancelled)
        XCTAssertFalse(fetched, "a cancelled sync must not fetch")
        XCTAssertNil(try store.load(),
                     "a cancelled sync must not commit rules")
        guard case .failed = controller.state else {
            return XCTFail("cancelled sync reported \(controller.state)")
        }
    }
}

// MARK: - Round 9: gated credential commit + admission before network

final class EighthReviewRegressionTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ device: Int = 7) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: device,
                         datasetBaseURL: base)
    }
    func origin(_ device: Int = 7) -> String {
        FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: device)
    }
    struct InstantAuth: SessionSigningIn {
        func signIn(email: String, password: String,
                    totpCode: String?) async throws -> String {
            "old-cookie"
        }
    }
    struct InstantIssuer: DatasetCredentialIssuing {
        func mintDatasetCredential(deviceID: Int,
                                   sessionCookie: String)
            async throws -> String { "old-dataset" }
    }
    final class HookVault: CredentialVault {
        var values: [String: String] = [:]
        var beforeSave: (() -> Void)?
        func read(key: String) throws -> String? { values[key] }
        func save(key: String, value: String) throws {
            beforeSave?()
            values[key] = value
        }
        func delete(key: String) throws {
            values.removeValue(forKey: key)
        }
    }
    // Adapted from EighthReviewRegressions proof 1: a sign-out that
    // lands between the rotation and the bundle write must not let
    /// the stale bundle resurrect a session. The sync must make ZERO
    /// HTTP requests.
    func testSignoutBetweenRotationAndBundleSaveCannotResurrect() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let vault = HookVault()
        vault.beforeSave = {
            try? store.clear()
            try? SignInCoordinator.clearCredentials(vault)
            vault.beforeSave = nil
        }
        let signIn = SignInCoordinator(ruleStore: store, vault: vault)
        do {
            try await signIn.signInAndIssue(
                configuration: cfg(),
                email: "test@example.test", password: "fixture",
                totpCode: nil, deviceID: 7, origin: origin(),
                auth: InstantAuth(), issuance: InstantIssuer(),
                currentOrigin: { self.origin() })
        } catch SignInCoordinator.SignInError.staleAttempt {
            // Honest outcome: the interleaving sign-out was detected.
        }
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [FixtureProtocol.self]
        var requests = 0
        FixtureProtocol.handler = { _ in
            requests += 1
            return (503, [:], Data())
        }
        let sync = FilterSyncController(
            configuration: cfg(), credentials: vault,
            session: URLSession(configuration: sessionConfig),
            ruleStore: store,
            prefilterFile: dir.appendingPathComponent("pre.json"))
        await sync.syncNow()
        XCTAssertEqual(requests, 0,
            "stale post-sign-out bundle was accepted and sent")
    }
    // Adapted proof 2: an already-stale origin must be refused BEFORE
    // the password/TOTP reach the network.
    func testOriginMismatchBeforeAttemptSendsNothing() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let vault = HookVault()
        final class CountAuth: SessionSigningIn {
            var calls = 0
            func signIn(email: String, password: String,
                        totpCode: String?) async throws -> String {
                calls += 1
                return "cookie"
            }
        }
        let auth = CountAuth()
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        do {
            try await coordinator.signInAndIssue(
                configuration: cfg(),
                email: "test@example.test", password: "fixture",
                totpCode: nil, deviceID: 7, origin: "old",
                auth: auth, issuance: InstantIssuer(),
                currentOrigin: { "new" })
            XCTFail("stale origin admitted")
        } catch {}
        XCTAssertEqual(auth.calls, 0,
            "already-stale origin sent credentials to the network")
    }
    // A queued sign-in for a SUPERSEDED configuration (mirror moved
    // on) is refused before any network call.
    func testSupersededConfigurationRefusedBeforeNetwork() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg(7))
        let vault = HookVault()
        final class CountAuth: SessionSigningIn {
            var calls = 0
            func signIn(email: String, password: String,
                        totpCode: String?) async throws -> String {
                calls += 1
                return "cookie"
            }
        }
        let auth = CountAuth()
        // MDM adopts a NEW device identity; the old attempt's config
        // is queued from before the change.
        try store.adoptConfiguration(cfg(9))
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        do {
            try await coordinator.signInAndIssue(
                configuration: cfg(7),
                email: "test@example.test", password: "fixture",
                totpCode: nil, deviceID: 7, origin: origin(),
                auth: auth, issuance: InstantIssuer(),
                currentOrigin: { self.origin() })
            XCTFail("superseded configuration admitted")
        } catch SignInCoordinator.SignInError.staleAttempt {}
        XCTAssertEqual(auth.calls, 0)
    }
}

final class BundleAuthorityBindingTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg() -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: 7,
                         datasetBaseURL: base)
    }
    // A bundle whose authority does not equal the admitted nonce is
    // rejected BEFORE ANY REQUEST (zero HTTP), as signed out.
    func testMismatchedBundleAuthorityIsSignedOutZeroHTTP() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        _ = store.admit(configuration: cfg())
        let origin = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: 7)
        // Bundle written under a FOREIGN nonce (rotation-gap stale).
        let vault = FakeCredentials([CredentialBundle.storageKey:
            makeBundle(origin: origin, dataset: "tok",
                       authority: "dead-beef-nonce")])
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [FixtureProtocol.self]
        var requests = 0
        FixtureProtocol.handler = { _ in
            requests += 1
            return (503, [:], Data())
        }
        let sync = FilterSyncController(
            configuration: cfg(), credentials: vault,
            session: URLSession(configuration: sessionConfig),
            ruleStore: store,
            prefilterFile: dir.appendingPathComponent("pre.json"))
        await sync.syncNow()
        XCTAssertEqual(requests, 0)
        XCTAssertEqual(sync.state, .signedOut)
    }
    // A well-formed bundle committed under the CURRENT nonce admits.
    func testCurrentAuthorityBundleAdmits() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        _ = store.admit(configuration: cfg())
        let origin = FilterRuleStore.configFingerprint(
            controlPlane: base, dataset: base, doh: nil,
            tenantID: 0, deviceID: 7)
        let vault = FakeCredentials([CredentialBundle.storageKey:
            makeBundle(origin: origin, dataset: "tok",
                       authority: store.currentEpoch() ?? "")])
        var requests = 0
        FixtureProtocol.handler = { _ in
            requests += 1
            return (401, [:], Data())
        }
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.protocolClasses = [FixtureProtocol.self]
        let sync = FilterSyncController(
            configuration: cfg(), credentials: vault,
            session: URLSession(configuration: sessionConfig),
            ruleStore: store,
            prefilterFile: dir.appendingPathComponent("pre.json"))
        await sync.syncNow()
        XCTAssertEqual(requests, 1,
            "a current-authority bundle must reach the network")
    }
}

final class LockedArtifactRemovalTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg() -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: 7,
                         datasetBaseURL: base)
    }
    // Cache removal is part of the locked invalidation transaction:
    // a conditional invalidation removes the registered prefilter
    // artifact, and a new identity's cache committed AFTER survives
    // an OLD catch's invalidation attempt (stale nonce: no-op).
    func testInvalidationRemovesRegisteredArtifact() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let nonce = try XCTUnwrap(store.admit(configuration: cfg()))
        let cache = dir.appendingPathComponent("pre.json")
        try Data("cache".utf8).write(to: cache)
        store.registerArtifact(cache)
        XCTAssertTrue(try store.invalidateIfCurrent(
            expectedEpoch: nonce))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: cache.path),
            "invalidation must remove the cache under the lock")
    }
    func testStaleInvalidationKeepsNewIdentityCache() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        let oldNonce = try XCTUnwrap(store.admit(
            configuration: cfg()))
        let cache = dir.appendingPathComponent("pre.json")
        store.registerArtifact(cache)
        // A new identity is fully adopted (authority rotated).
        try store.adoptConfiguration(cfg())
        // ...and its cache is committed under the new authority.
        let staged = dir.appendingPathComponent("staged")
        try Data("new-cache".utf8).write(to: staged)
        let newNonce = try XCTUnwrap(store.currentEpoch())
        try store.commitArtifact(from: staged, to: cache,
                                 expectedEpoch: newNonce)
        // The OLD session's delayed invalidation must be a no-op.
        XCTAssertFalse(try store.invalidateIfCurrent(
            expectedEpoch: oldNonce))
        XCTAssertEqual(String(data: try Data(contentsOf: cache),
                              encoding: .utf8), "new-cache")
    }
}

// MARK: - Round 10: current-source coalescing (captured config is never authoritative)

final class TenthReviewRegressionTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ id: Int) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: id,
                         datasetBaseURL: base)
    }
    // Rapid A -> B push: a lifecycle task enqueued while A was
    // current executes AFTER B lands. The owner reads the CURRENT
    // source at execution time, so the stale captured configuration
    // is never re-adopted and the runs coalesce to B.
    func testQueuedApplyCoalescesToCurrentSource() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        var current = cfg(7)
        let coordinator = SignInCoordinator(
            ruleStore: store, vault: FakeCredentials([:]),
            configurationSource: { current })
        // Observer for A enqueues a task; B lands before it executes.
        current = cfg(9)
        let first = try await coordinator.applyCurrentConfiguration()
        XCTAssertEqual(first, .adopted)
        XCTAssertNotNil(store.admit(configuration: cfg(9)),
                        "the CURRENT source must be the adopted one")
        XCTAssertNil(store.admit(configuration: cfg(7)),
                     "a stale captured configuration was re-adopted")
        // A second queued task (scheduled for B) sees the same source.
        let second = try await coordinator.applyCurrentConfiguration()
        XCTAssertEqual(second, .alreadyCurrent)
    }
    // A sign-in attempt captured against A is refused when the source
    // is already B: it admits nothing and never reaches the network.
    func testSigninCapturedAgainstSupersededSourceRefused() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = FilterRuleStore(directory: dir)
        final class CountAuth: SessionSigningIn {
            var calls = 0
            func signIn(email: String, password: String,
                        totpCode: String?) async throws -> String {
                calls += 1
                return "cookie"
            }
        }
        let auth = CountAuth()
        final class Issuer: DatasetCredentialIssuing {
            func mintDatasetCredential(deviceID: Int,
                                       sessionCookie: String) async throws -> String {
                "dataset"
            }
        }
        var current = cfg(7)
        let coordinator = SignInCoordinator(
            ruleStore: store, vault: FakeCredentials([:]),
            configurationSource: { current })
        current = cfg(9)
        do {
            try await coordinator.signInAndIssue(
                configuration: cfg(7),
                email: "test@example.test", password: "fixture",
                totpCode: nil, deviceID: 7, origin: "o",
                auth: auth, issuance: Issuer(),
                currentOrigin: { "o" })
            XCTFail("stale captured configuration admitted")
        } catch SignInCoordinator.SignInError.staleAttempt {
        } catch { XCTFail("unexpected error: \(error)") }
        XCTAssertEqual(auth.calls, 0,
            "stale captured configuration reached the network")
        XCTAssertNil(store.mirroredConfiguration(),
                     "refused attempt must not admit/mirror anything")
    }
    // No configuration source installed: current-source apply fails
    // closed instead of trusting any caller-captured copy.
    func testApplyCurrentConfigurationWithoutSourceFailsClosed() async {
        let coordinator = SignInCoordinator(ruleStore: nil,
                                            vault: FakeCredentials([:]))
        do {
            _ = try await coordinator.applyCurrentConfiguration()
            XCTFail("missing source must fail closed")
        } catch SignInCoordinator.SignInError.storeNotReady {
        } catch { XCTFail("unexpected error: \(error)") }
    }
}

// MARK: - Round 11: sign-out remote logout requires a bound client

final class SignOutOrchestrationTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func cfg(_ id: Int = 7) -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: base, deviceID: id,
                         datasetBaseURL: base)
    }
    final class CountSignOut: SessionSigningOut {
        let vault: CredentialVault
        var calls = 0
        var cookies: [String] = []
        var bundleGoneAtCall = false
        init(vault: CredentialVault) { self.vault = vault }
        func signOut(sessionCookie: String) async throws {
            calls += 1
            cookies.append(sessionCookie)
            bundleGoneAtCall = CredentialBundle.load(from: vault) == nil
        }
    }
    private func seed() throws -> (FilterRuleStore, URL, FakeCredentials) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let store = FilterRuleStore(directory: dir)
        try store.mirrorConfiguration(cfg())
        _ = store.admit(configuration: cfg())
        let vault = FakeCredentials([:])
        let bundle = CredentialBundle(
            session: "cookie-old", sessionOrigin: "origin-old",
            datasetCredential: "ds", datasetOrigin: "origin-old",
            authority: "nonce")
        try vault.save(key: CredentialBundle.storageKey,
                       value: bundle.encoded())
        return (store, dir, vault)
    }
    // Client provably bound to the bundle's session origin: the old
    // cookie reaches the server that issued it, AFTER local teardown.
    func testBoundClientReceivesCookieAfterLocalTeardown() async throws {
        let (store, dir, vault) = try seed()
        defer { try? FileManager.default.removeItem(at: dir) }
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        let remote = CountSignOut(vault: vault)
        try await coordinator.signOut(remoteLogout: remote,
                                      boundToOrigin: "origin-old")
        XCTAssertEqual(remote.calls, 1)
        XCTAssertEqual(remote.cookies, ["cookie-old"])
        XCTAssertTrue(remote.bundleGoneAtCall,
                      "remote logout ran before local teardown")
        XCTAssertNil(CredentialBundle.load(from: vault))
    }
    // A config change replaced the client (its origin differs from
    // the bundle's): the old cookie is NEVER disclosed to the new
    // server; local teardown still ran completely.
    func testReplacedClientNeverReceivesOldCookie() async throws {
        let (store, dir, vault) = try seed()
        defer { try? FileManager.default.removeItem(at: dir) }
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        let remote = CountSignOut(vault: vault)
        try await coordinator.signOut(remoteLogout: remote,
                                      boundToOrigin: "origin-new")
        XCTAssertEqual(remote.calls, 0,
                       "old cookie disclosed to a new server")
        XCTAssertNil(CredentialBundle.load(from: vault),
                     "local teardown must still run")
    }
    // No client at all: local-only teardown, nothing thrown.
    func testNilClientIsLocalOnly() async throws {
        let (store, dir, vault) = try seed()
        defer { try? FileManager.default.removeItem(at: dir) }
        let coordinator = SignInCoordinator(ruleStore: store,
                                            vault: vault)
        try await coordinator.signOut(
            remoteLogout: CountSignOut?.none, boundToOrigin: nil)
        XCTAssertNil(CredentialBundle.load(from: vault))
    }
}

// MARK: - Stage 10: Apple prefilter cross-language vectors

/// The Python dataset builder and this Swift implementation must
/// produce byte-identical Apple-format prefilters. The vectors file
/// (tools/apple-prefilter-vectors.json) is generated by
/// tools/gen-apple-prefilter-vectors.py from the PYTHON builder; these
/// tests recompute every value in Swift and require exact agreement.
final class ApplePrefilterVectorTests: XCTestCase {
    struct Vectors: Decodable {
        struct Bloom: Decodable {
            let capacity: Int
            let fp_rate: Double
            let bit_count: Int
            let hash_count: Int
            let murmur_seed: UInt32
            let bytes_hex: String
            let tag: String
            let items: [String]
            let absent: [String]
            let positions: [String: [Int]]
        }
        let bloom: Bloom
        let fnv1a32: [String: UInt32]
        let murmur3_32: [String: [String: UInt32]]
        let punycode: [String: String]
    }

    func loadVectors() throws -> Vectors {
        guard let root = ProcessInfo.processInfo
            .environment["KG_REPO_ROOT"]
        else { throw XCTSkip("KG_REPO_ROOT not set") }
        let url = URL(fileURLWithPath: root)
            .appendingPathComponent("tools/apple-prefilter-vectors.json")
        return try JSONDecoder().decode(
            Vectors.self, from: Data(contentsOf: url))
    }

    func testFnv1a32MatchesPython() throws {
        for (input, expected) in try loadVectors().fnv1a32 {
            XCTAssertEqual(
                ApplePrefilterHash.fnv1a32(Array(input.utf8)),
                expected, "fnv1a32(\(input))")
        }
    }

    func testMurmur3MatchesPython() throws {
        for (input, bySeed) in try loadVectors().murmur3_32 {
            for (seedText, expected) in bySeed {
                XCTAssertEqual(
                    ApplePrefilterHash.murmur3_32(
                        Array(input.utf8), seed: UInt32(seedText)!),
                    expected, "murmur3(\(input), seed \(seedText))")
            }
        }
    }

    func testPunycodeMatchesPython() throws {
        for (input, expected) in try loadVectors().punycode {
            XCTAssertEqual(try Punycode.encode(input), expected,
                           "punycode(\(input))")
        }
    }

    func testBloomBitsAndTagMatchPython() throws {
        let vectors = try loadVectors().bloom
        let byteCount = (vectors.bit_count + 7) / 8
        var bits = [UInt8](repeating: 0, count: byteCount)
        for (item, expectedPositions) in vectors.positions {
            let computed = ApplePrefilterHash.positions(
                punycodeASCII: Array(try Punycode.encode(item).utf8),
                bitCount: vectors.bit_count,
                hashCount: vectors.hash_count,
                murmurSeed: vectors.murmur_seed)
            XCTAssertEqual(computed, expectedPositions,
                           "positions(\(item))")
            for position in computed {
                bits[position / 8] |= UInt8(1 << (position % 8))
            }
        }
        let hex = bits.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(hex, vectors.bytes_hex, "bit array bytes")
        XCTAssertEqual(
            SHA256.hash(data: Data(bits)).map {
                String(format: "%02x", $0)
            }.joined(),
            vectors.tag, "tag must be the SHA-256 of the bit array")
        // Membership: every item present, every absent string absent.
        for item in vectors.items {
            let positions = ApplePrefilterHash.positions(
                punycodeASCII: Array(try Punycode.encode(item).utf8),
                bitCount: vectors.bit_count,
                hashCount: vectors.hash_count,
                murmurSeed: vectors.murmur_seed)
            XCTAssertTrue(positions.allSatisfy {
                bits[$0 / 8] & UInt8(1 << ($0 % 8)) != 0
            }, "\(item) must be present")
        }
        for entry in vectors.absent {
            let positions = ApplePrefilterHash.positions(
                punycodeASCII: Array(try Punycode.encode(entry).utf8),
                bitCount: vectors.bit_count,
                hashCount: vectors.hash_count,
                murmurSeed: vectors.murmur_seed)
            XCTAssertFalse(positions.allSatisfy {
                bits[$0 / 8] & UInt8(1 << ($0 % 8)) != 0
            }, "\(entry) must be absent")
        }
    }

    func testParametersRejectForeignFormat() throws {
        XCTAssertThrowsError(try ApplePrefilterParameters(
            format: "legacy-sha256", bitCount: 24, hashCount: 3,
            murmurSeed: 1, byteCount: 3,
            sha256: String(repeating: "a", count: 64))) { error in
            guard case ApplePrefilterParameters.ValidationError
                .wrongFormat = error
            else { return XCTFail("expected wrongFormat, got \(error)") }
        }
        // bit_count/bytes mismatch fails closed.
        XCTAssertThrowsError(try ApplePrefilterParameters(
            format: ApplePrefilterParameters.expectedFormat,
            bitCount: 24, hashCount: 3, murmurSeed: 1, byteCount: 4,
            sha256: String(repeating: "a", count: 64)))
    }
}

// MARK: - Stage 10: DoH token provider lifecycle

final class DohTokenProviderTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: config)
    }

    func testMintCachesAndRefreshesNearExpiry() async throws {
        var mints = 0
        var clock = Date(timeIntervalSince1970: 1_000_000)
        let lock = NSLock()
        FixtureProtocol.handler = { request in
            lock.lock(); mints += 1; lock.unlock()
            XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"),
                           "kg_session=live")
            return (200, [:], Data(
                #"{"device_id":7,"credential":"tok-\#(UUID().uuidString)","scope":"doh","policy_id":1}"#
                    .utf8))
        }
        let provider = DohTokenProvider(
            issuer: CredentialIssuanceClient(baseURL: base,
                                             session: session()),
            deviceID: 7,
            now: { clock },
            sessionCookie: { "live" })
        let first = try await provider.currentToken()
        let second = try await provider.currentToken()
        XCTAssertEqual(first, second, "fresh token is reused")
        XCTAssertEqual(mints, 1, "no second mint while fresh")
        // Advance past 75% of the fallback lifetime: next call renews.
        clock = clock.addingTimeInterval(16 * 60)
        let third = try await provider.currentToken()
        XCTAssertNotEqual(third, first)
        XCTAssertEqual(mints, 2)
        provider.invalidate()
        _ = try await provider.currentToken()
        XCTAssertEqual(mints, 3, "invalidation forces a fresh mint")
    }

    func testConcurrentCallersShareOneMint() async throws {
        var mints = 0
        let lock = NSLock()
        FixtureProtocol.handler = { _ in
            lock.lock(); mints += 1; lock.unlock()
            return (200, [:], Data(
                #"{"device_id":7,"credential":"shared","scope":"doh","policy_id":1}"#
                    .utf8))
        }
        let provider = DohTokenProvider(
            issuer: CredentialIssuanceClient(baseURL: base,
                                             session: session()),
            deviceID: 7, sessionCookie: { "live" })
        async let a = provider.currentToken()
        async let b = provider.currentToken()
        async let c = provider.currentToken()
        let results = try await [a, b, c]
        XCTAssertEqual(Set(results), ["shared"],
                       "single-flight: concurrent callers share the mint")
        XCTAssertEqual(mints, 1)
    }

    func testNoSessionFailsClosed() async throws {
        let provider = DohTokenProvider(
            issuer: CredentialIssuanceClient(baseURL: base,
                                             session: session()),
            deviceID: 7, sessionCookie: { nil })
        do {
            _ = try await provider.currentToken()
            XCTFail("mint without a session succeeded")
        } catch DohTokenProvider.TokenError.unauthorized {
            // expected: fail closed, no token
        }
    }

    func testServer401MapsToUnauthorized() async throws {
        FixtureProtocol.handler = { _ in (401, [:], Data()) }
        let provider = DohTokenProvider(
            issuer: CredentialIssuanceClient(baseURL: base,
                                             session: session()),
            deviceID: 7, sessionCookie: { "stale" })
        do {
            _ = try await provider.currentToken()
            XCTFail("401 mint succeeded")
        } catch DohTokenProvider.TokenError.unauthorized {
            // expected
        }
    }
}

// MARK: - Stage 10: DNS proxy relay (wire validation, fail closed)

final class DNSProxyRelayTests: XCTestCase {
    /// Minimal valid wire query: ID 0x1234, flags RD, one question.
    func query(id: UInt16 = 0x1234) -> Data {
        var q = Data([UInt8(id >> 8), UInt8(id & 0xFF),
                      0x01, 0x00, 0x00, 0x01,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        q.append(contentsOf: [3]) // "www"
        q.append(contentsOf: "www".utf8)
        q.append(contentsOf: [0]) // root
        q.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
        return q
    }

    func testRejectsMalformedQueries() {
        XCTAssertThrowsError(try DNSProxyRelay.validate(query: Data()))
        var response = query()
        response[2] = 0x81 // QR=1: a RESPONSE must never be relayed
        XCTAssertThrowsError(try DNSProxyRelay.validate(query: response))
        var truncated = query()
        truncated[2] |= 0x02 // TC=1: truncated input is refused
        XCTAssertThrowsError(
            try DNSProxyRelay.validate(query: truncated))
        var zeroQuestions = query()
        zeroQuestions[5] = 0
        XCTAssertThrowsError(
            try DNSProxyRelay.validate(query: zeroQuestions))
        var notify = query()
        notify[2] |= 0x20 // opcode 4 (NOTIFY): not a resolver lookup
        XCTAssertThrowsError(try DNSProxyRelay.validate(query: notify))
        var oversized = query()
        oversized.append(Data(repeating: 0,
                              count: DNSProxyRelay.maximumQueryBytes))
        XCTAssertThrowsError(
            try DNSProxyRelay.validate(query: oversized))
    }

    func testServfailMirrorsTransactionID() throws {
        let servfail = try XCTUnwrap(
            DNSProxyRelay.servfailResponse(to: query(id: 0xBEEF)))
        XCTAssertEqual(servfail[0], 0xBE)
        XCTAssertEqual(servfail[1], 0xEF)
        XCTAssertEqual(servfail[2] & 0x80, 0x80, "QR set")
        XCTAssertEqual(servfail[3] & 0x0F, 2, "RCODE = SERVFAIL")
    }

    func testRelayRejectsMismatchedTransactionID() async throws {
        // A resolver answer under a different transaction ID is never
        // handed to the client: SERVFAIL instead.
        let answer = try XCTUnwrap(
            DNSProxyRelay.servfailResponse(to: query(id: 0x9999)))
        let result = await DNSProxyRelay.relay(query: query()) { _ in
            answer
        }
        let relayed = try XCTUnwrap(result)
        XCTAssertEqual(relayed[0], 0x12)
        XCTAssertEqual(relayed[1], 0x34, "client sees the SERVFAIL, "
                       + "not the foreign answer")
        XCTAssertEqual(relayed[3] & 0x0F, 2)
    }

    func testRelayFailureIsServfailNeverEmpty() async throws {
        let result = await DNSProxyRelay.relay(query: query()) { _ in
            throw DNSProxyRelay.RelayRejection.tooSmall
        }
        let relayed = try XCTUnwrap(result)
        XCTAssertEqual(relayed[3] & 0x0F, 2,
                       "upstream failure answers SERVFAIL")
    }
}

// MARK: - Stage 10: URL Filter prefilter source (fail closed)

final class URLFilterPrefilterSourceTests: XCTestCase {
    let fingerprint = "fixture-fingerprint"

    func writeSnapshot(fingerprint: String? = nil,
                       format: String = "apple-fnv1a-murmur3-doublehash-v1",
                       bits: [UInt8] = [0xAB, 0xCD, 0xEF],
                       corruptSHA: Bool = false,
                       tamperBits: Bool = false,
                       fetchedAt: Date? = Date()) throws -> URL {
        let hash = SHA256.hash(data: Data(bits)).map {
            String(format: "%02x", $0)
        }.joined()
        let manifest: [String: Any] = [
            "version": 3, "rule_count": 1, "blocked_count": 1,
            "provenance": "fixture",
            "prefilter": [
                "format": format,
                "bit_count": 24, "hash_count": 3,
                "murmur_seed": 1262944257,
                "bytes": 3,
                "sha256": corruptSHA
                    ? String(repeating: "0", count: 64) : hash,
            ],
        ]
        var snapshot: [String: Any] = [
            "manifest": manifest,
            "prefilter": Data(tamperBits ? [0x00, 0x00, 0x00] : bits)
                .base64EncodedString(),
            "endpointFingerprint": fingerprint ?? self.fingerprint,
        ]
        // The on-disk format stores seconds since 1970 explicitly.
        // Pass nil to simulate a legacy artifact with no age record.
        if let fetchedAt {
            snapshot["fetchedAt"] = fetchedAt.timeIntervalSince1970
        }
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try JSONSerialization.data(withJSONObject: snapshot)
            .write(to: file)
        return file
    }

    func testValidArtifactLoads() throws {
        let file = try writeSnapshot()
        defer { try? FileManager.default.removeItem(at: file) }
        let artifact = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: fingerprint).load()
        let a = try XCTUnwrap(artifact)
        XCTAssertEqual(a.data, Data([0xAB, 0xCD, 0xEF]))
        XCTAssertEqual(a.bitCount, 24)
        XCTAssertEqual(a.hashCount, 3)
        XCTAssertEqual(a.murmurSeed, 1262944257)
        XCTAssertEqual(a.datasetVersion, 3)
        XCTAssertEqual(a.tag, SHA256.hash(data: a.data).map {
            String(format: "%02x", $0)
        }.joined(), "tag is the SHA-256 of the bit array")
    }

    /// USE-TIME EXPIRY, the "OS never wakes the app" guarantee for
    /// the prefilter layer: a fully valid artifact (right identity,
    /// right hash, right format) that is older than maxArtifactAge is
    /// INVALID at load time, so the control provider fails closed
    /// instead of enforcing unboundedly stale policy. No timer,
    /// background task or disk event is needed for this to take
    /// effect.
    func testExpiredArtifactIsInvalidAtUseTime() throws {
        let old = Date().addingTimeInterval(
            -URLFilterPrefilterSource.maxArtifactAge - 3600)
        let file = try writeSnapshot(fetchedAt: old)
        defer { try? FileManager.default.removeItem(at: file) }
        let source = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: fingerprint)
        XCTAssertEqual(source.loadResult(), .invalid)
        XCTAssertNil(source.load())
    }

    /// Just inside the horizon the same artifact still loads: the
    /// expiry check is the age boundary, not a blunt refusal.
    func testArtifactJustInsideHorizonLoads() throws {
        let recent = Date().addingTimeInterval(
            -URLFilterPrefilterSource.maxArtifactAge + 3600)
        let file = try writeSnapshot(fetchedAt: recent)
        defer { try? FileManager.default.removeItem(at: file) }
        let source = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: fingerprint)
        guard case .artifact = source.loadResult() else {
            return XCTFail("in-window artifact refused")
        }
    }

    /// A legacy artifact with NO age record cannot prove its
    /// freshness: refused (decode fails), never silently trusted.
    func testLegacyArtifactWithoutFetchedAtIsInvalid() throws {
        let file = try writeSnapshot(fetchedAt: nil)
        defer { try? FileManager.default.removeItem(at: file) }
        let source = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: fingerprint)
        XCTAssertEqual(source.loadResult(), .invalid)
    }

    /// A far-future download timestamp would pin the artifact's age
    /// near zero forever (never expiring): refused like any other
    /// unprovable freshness claim. Small clock adjustments inside
    /// futureTimestampTolerance still load.
    func testFarFutureFetchedAtIsInvalid() throws {
        let future = Date().addingTimeInterval(3600)
        let file = try writeSnapshot(fetchedAt: future)
        defer { try? FileManager.default.removeItem(at: file) }
        let source = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: fingerprint)
        XCTAssertEqual(source.loadResult(), .invalid)
        let slightSkew = Date().addingTimeInterval(
            URLFilterPrefilterSource.futureTimestampTolerance / 2)
        let skewed = try writeSnapshot(fetchedAt: slightSkew)
        defer { try? FileManager.default.removeItem(at: skewed) }
        let skewedSource = URLFilterPrefilterSource(
            artifactFile: skewed, endpointFingerprint: fingerprint)
        guard case .artifact = skewedSource.loadResult() else {
            return XCTFail("clock-skewed artifact within tolerance refused")
        }
    }

    func testLoadResultDistinguishesInvalidFromUnchanged() throws {
        let file = try writeSnapshot()
        defer { try? FileManager.default.removeItem(at: file) }
        let source = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: fingerprint)
        guard case .artifact = source.loadResult() else {
            return XCTFail("valid artifact not returned")
        }
        let tag = try XCTUnwrap(source.load()).tag
        XCTAssertEqual(source.loadResult(existingTag: tag), .unchanged)
        // Foreign identity with the SAME tag on record: invalid,
        // never "unchanged" - a previous identity's prefilter must
        // not be silently retained.
        XCTAssertEqual(source.loadResult(existingTag: tag),
                       .unchanged)
        let foreign = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: "other")
        XCTAssertEqual(foreign.loadResult(existingTag: tag), .invalid)
        let missing = URLFilterPrefilterSource(
            artifactFile: FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString),
            endpointFingerprint: fingerprint)
        XCTAssertEqual(missing.loadResult(), .invalid)
    }

    func testUnchangedTagMeansNoUpdate() throws {
        let file = try writeSnapshot()
        defer { try? FileManager.default.removeItem(at: file) }
        let source = URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: fingerprint)
        let tag = try XCTUnwrap(source.load()).tag
        XCTAssertNil(source.load(existingTag: tag),
                     "same tag: the system needs no new prefilter")
    }

    func testFailClosedCases() throws {
        // Missing file
        XCTAssertNil(URLFilterPrefilterSource(
            artifactFile: FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString),
            endpointFingerprint: fingerprint).load())
        // Foreign identity
        let foreign = try writeSnapshot(fingerprint: "other-server")
        defer { try? FileManager.default.removeItem(at: foreign) }
        XCTAssertNil(URLFilterPrefilterSource(
            artifactFile: foreign,
            endpointFingerprint: fingerprint).load(),
            "a foreign server's artifact is never served")
        // Wrong format
        let legacy = try writeSnapshot(format: "legacy-sha256")
        defer { try? FileManager.default.removeItem(at: legacy) }
        XCTAssertNil(URLFilterPrefilterSource(
            artifactFile: legacy,
            endpointFingerprint: fingerprint).load())
        // Manifest sha256 that is not the artifact's hash
        let corrupt = try writeSnapshot(corruptSHA: true)
        defer { try? FileManager.default.removeItem(at: corrupt) }
        XCTAssertNil(URLFilterPrefilterSource(
            artifactFile: corrupt,
            endpointFingerprint: fingerprint).load())
        // Bytes tampered after a valid manifest
        let tampered = try writeSnapshot(tamperBits: true)
        defer { try? FileManager.default.removeItem(at: tampered) }
        XCTAssertNil(URLFilterPrefilterSource(
            artifactFile: tampered,
            endpointFingerprint: fingerprint).load())
        // Empty current identity: never bind
        let file = try writeSnapshot()
        defer { try? FileManager.default.removeItem(at: file) }
        XCTAssertNil(URLFilterPrefilterSource(
            artifactFile: file, endpointFingerprint: "").load())
    }
}

// MARK: - Stage 10: PIR configuration pair validation

final class PIRConfigurationTests: XCTestCase {
    func testPIRPairIsBothOrNeither() {
        let name = "kg-test-\(UUID())"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        var dict: [String: Any] = [
            "controlPlaneBaseURL": "https://fixture.example",
            "deviceID": 7,
        ]
        defaults.set(dict, forKey: "com.apple.configuration.managed")
        var config = AppConfiguration.managed(defaults: defaults)
        XCTAssertNil(config.pirServerURL)
        XCTAssertNil(config.pirPrivacyPassIssuerURL)
        // Only one PIR key: the pair is invalid - BOTH drop (a
        // half-configured URL Filter must never reach the system).
        dict["pirServerURL"] = "https://pir.fixture.example"
        defaults.set(dict, forKey: "com.apple.configuration.managed")
        config = AppConfiguration.managed(defaults: defaults)
        XCTAssertNil(config.pirServerURL, "lone PIR server is dropped")
        XCTAssertNil(config.pirPrivacyPassIssuerURL)
        // Complete pair over HTTPS: kept.
        dict["pirPrivacyPassIssuerURL"] =
            "https://issuer.fixture.example"
        defaults.set(dict, forKey: "com.apple.configuration.managed")
        config = AppConfiguration.managed(defaults: defaults)
        XCTAssertEqual(config.pirServerURL?.host,
                       "pir.fixture.example")
        XCTAssertEqual(config.pirPrivacyPassIssuerURL?.host,
                       "issuer.fixture.example")
        // HTTP PIR endpoints are refused like every other endpoint.
        dict["pirServerURL"] = "http://pir.fixture.example"
        defaults.set(dict, forKey: "com.apple.configuration.managed")
        config = AppConfiguration.managed(defaults: defaults)
        XCTAssertNil(config.pirServerURL)
        XCTAssertNil(config.pirPrivacyPassIssuerURL)
    }
}

// MARK: - Stage 10: application blocking policy (portable model)

final class AppBlockingPolicyTests: XCTestCase {

    func testServerContractDecodes() throws {
        let json = Data(#"{"mode":"blocklist","bundle_ids":["com.example.game","net.example.social"],"saved":true,"updated_at":"2026-11-17T00:00:00"}"#.utf8)
        let policy = try JSONDecoder().decode(
            AppBlockingPolicy.self, from: json)
        XCTAssertEqual(policy.mode, .blocklist)
        XCTAssertEqual(policy.bundleIDs,
                       ["com.example.game", "net.example.social"])
        XCTAssertTrue(policy.saved)
    }

    func testUnsavedServerRecordMeansNoPolicy() throws {
        // Server has no stored policy: {"mode":"blocklist",
        // "bundle_ids":[],"saved":false}. The mirror must not treat
        // this as "block nothing"; it is "no policy".
        let json = Data(#"{"mode":"blocklist","bundle_ids":[],"saved":false}"#.utf8)
        let policy = try JSONDecoder().decode(
            AppBlockingPolicy.self, from: json)
        XCTAssertFalse(policy.saved)
    }

    func testBundleIDValidationMatchesServer() {
        // Same contract as mdm/app_management.validate_bundle_ids.
        XCTAssertThrowsError(
            try AppBlockingPolicy(mode: .blocklist,
                                  bundleIDs: ["not a bundle id"]))
        XCTAssertThrowsError(
            try AppBlockingPolicy(mode: .blocklist,
                                  bundleIDs: ["com.example.app",
                                              "com.example.app"]))
        XCTAssertNoThrow(
            try AppBlockingPolicy(mode: .allowlist,
                                  bundleIDs: ["com.example.app",
                                              "net.example.other-2"]))
    }

    func testStoreIsIdentityBoundAndFailSafe() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("app-policy.json")
        let store = AppBlockingPolicyStore(snapshotFile: file)
        let policy = try AppBlockingPolicy(
            mode: .blocklist, bundleIDs: ["com.example.game"])
        // Empty fingerprint: refused.
        XCTAssertThrowsError(
            try store.save(policy, endpointFingerprint: ""))
        XCTAssertNil(store.load(endpointFingerprint: "fp-1"))
        try store.save(policy, endpointFingerprint: "fp-1")
        XCTAssertEqual(store.load(endpointFingerprint: "fp-1"), policy)
        // Foreign identity: fail safe, never apply.
        XCTAssertNil(store.load(endpointFingerprint: "fp-2"))
        // Corrupt file: fail safe.
        try Data("not json".utf8).write(to: file)
        XCTAssertNil(store.load(endpointFingerprint: "fp-1"))
        store.clear()
        XCTAssertNil(store.load(endpointFingerprint: "fp-1"))
    }
}

final class AppBlockingPolicyClientTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: config)
    }

    func testFetchHitsDeviceRouteWithSession() async throws {
        FixtureProtocol.handler = { request in
            XCTAssertEqual(request.url?.path,
                           "/api/devices/7/app-policy")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"),
                           "kg_session=live")
            return (200, [:], Data(
                #"{"mode":"blocklist","bundle_ids":["com.example.game"],"saved":true}"#
                    .utf8))
        }
        let policy = try await AppBlockingPolicyClient(
            baseURL: base, session: session())
            .fetch(deviceID: 7, sessionCookie: "live")
        XCTAssertEqual(policy.mode, .blocklist)
        XCTAssertEqual(policy.bundleIDs, ["com.example.game"])
    }

    func testErrorsMap() async throws {
        FixtureProtocol.handler = { _ in (401, [:], Data()) }
        let client = AppBlockingPolicyClient(baseURL: base,
                                             session: session())
        do {
            _ = try await client.fetch(deviceID: 7, sessionCookie: "x")
            XCTFail("401 fetch succeeded")
        } catch AppBlockingPolicyClient.FetchError.unauthorized {}
        FixtureProtocol.handler = { _ in (404, [:], Data()) }
        do {
            _ = try await client.fetch(deviceID: 7, sessionCookie: "x")
            XCTFail("404 fetch succeeded")
        } catch AppBlockingPolicyClient.FetchError.deviceNotFound {}
        FixtureProtocol.handler = { _ in (200, [:], Data("junk".utf8)) }
        do {
            _ = try await client.fetch(deviceID: 7, sessionCookie: "x")
            XCTFail("malformed fetch succeeded")
        } catch AppBlockingPolicyClient.FetchError.malformedResponse {}
    }
}

/// Reachability and entitlement guards for the personally-owned app
/// blocking route (independent-review finding: AppShieldController was
/// unreachable). The UI layer is Apple-only and UNCOMPILED here, so
/// these are static checks of the call graph and the entitlements it
/// requires - they fail if the wiring is removed or drifts.
final class AppShieldReachabilityTests: XCTestCase {

    private func repoRoot() throws -> URL {
        guard let root = ProcessInfo.processInfo
            .environment["KG_REPO_ROOT"]
        else { throw XCTSkip("KG_REPO_ROOT not set") }
        return URL(fileURLWithPath: root)
    }

    private func source(_ rel: String) throws -> String {
        try String(contentsOf: repoRoot().appendingPathComponent(rel),
                   encoding: .utf8)
    }

    /// The app must actually EMBED the blocking section: controller
    /// code that no view calls is dead code, and dead code is not a
    /// feature.
    func testMainViewEmbedsAppBlockingSection() throws {
        let app = try source("ios/Sources/KosherGuard/KosherGuardApp.swift")
        XCTAssertTrue(app.contains("AppBlockingSection()"),
                      "FilterStatusView must embed AppBlockingSection")
        XCTAssertTrue(app.contains("App blocking (this device)"),
                      "the section must be visibly labelled")
    }

    /// The section must perform the full real flow: Apple's consent
    /// prompt, the picker, shield application and explicit removal -
    /// each a direct call into the controller/framework, not a stub.
    func testSectionCallsRealShieldFlow() throws {
        let view = try source(
            "ios/Sources/KosherGuard/AppBlockingView.swift")
        for needle in [
            // The view asks the controller; the controller owns the
            // Apple call (checked in testControllerLifecycleDiscipline).
            "controller.requestAuthorization()",
            "familyActivityPicker(",
            "controller.applyShield(selection:",
            "controller.clearShield()",
            "AppShieldController()",
            "AuthorizationCenter.shared.authorizationStatus",
        ] {
            XCTAssertTrue(view.contains(needle),
                          "AppBlockingView missing \(needle)")
        }
        // Consent discipline: authorization may only be requested from
        // the button action, never on appear/init.
        XCTAssertFalse(view.contains(".onAppear"),
                       "consent must not be requested on appear")
        XCTAssertFalse(view.contains("requestAuthorization() }\n\n    init"),
                       "consent must not be requested from init")
        // An unknown future authorization state must degrade to
        // NOT authorized, never to shielding. The switch uses a plain
        // `default` (not @unknown default) because iOS 26.4 added the
        // availability-annotated known case .approvedWithDataAccess,
        // which @unknown default cannot cover; the default branch
        // handles it explicitly and every other unknown state must
        // still fail closed.
        XCTAssertTrue(view.contains("== .approvedWithDataAccess"),
                      "iOS 26.4 approvedWithDataAccess must be handled")
        guard let defaultBranch = view.range(of: "default:") else {
            XCTFail("authorizationStatus switch must have a default branch")
            return
        }
        XCTAssertTrue(
            view[defaultBranch.lowerBound...].contains(
                "state = .notAuthorized"),
            "unknown AuthorizationStatus must fail closed")
    }

    /// The controller must only clear shields explicitly (no implicit
    /// clear on fetch/sync paths) and the store must be named so
    /// settings persist across launches.
    func testControllerLifecycleDiscipline() throws {
        let controller = try source(
            "ios/Sources/KosherGuard/AppShieldController.swift")
        XCTAssertTrue(controller.contains(
            #"ManagedSettingsStore.Name("kosherguard-app-blocking")"#))
        // The controller owns the Apple consent call.
        XCTAssertTrue(controller.contains(
            "AuthorizationCenter.shared.requestAuthorization"))
        // Removal is a real store clear, not a no-op.
        XCTAssertTrue(controller.contains("clearAllSettings"))
        // No network/policy path may touch shields: the controller
        // must not reference the policy client/store at all.
        for forbidden in ["AppBlockingPolicyClient",
                          "AppBlockingPolicyStore", "URLSession"] {
            XCTAssertFalse(controller.contains(forbidden),
                           "shield controller must stay device-local "
                           + "(found \(forbidden))")
        }
    }

    /// Every entitlements file must declare exactly the keys its
    /// target's code requires - nothing missing, nothing extra to
    /// audit. Keys checked against the sources that use them.
    /// Remote shield gate (Stage 10): activation-only, consent-bound,
    /// no upload, no category escalation.
    func testRemoteShieldGateSemantics() throws {
        let view = try source(
            "ios/Sources/KosherGuard/AppBlockingView.swift")
        for needle in [
            // Gate-off is a distinct, honest state - not hidden.
            "case remotePaused",
            "Turned off by your administrator",
            // The gate is read from the identity-bound mirror, and the
            // shield is applied only when the gate is not OFF.
            "currentRemoteGate()",
            ".load(endpointFingerprint: fingerprint)?.shieldActive",
            // Gate OFF pauses via clearShield but keeps the selection.
            "Kept on this iPhone.",
            // Authorization is re-checked on every refresh (including
            // every sync-triggered one): the switch on
            // authorizationStatus precedes any shield application.
            "AuthorizationCenter.shared.authorizationStatus",
            // The sync generation observation re-evaluates on each
            // completed policy mirror.
            "sync.appPolicyGeneration",
            // Always-visible remote-control disclosure (needles stay
            // inside single string literals of the view source).
            "administrator can turn this blocking on ",
            "or off remotely.",
            "They can never see or change which ",
            "apps you picked",
        ] {
            XCTAssertTrue(view.contains(needle),
                          "remote gate missing \(needle)")
        }
        // The selection is never uploaded and the gate never widens
        // the consented scope: no network calls, no .all/.all-except
        // category policy anywhere in the shield path.
        for forbidden in ["URLSession", "URLRequest",
                          "session.upload(",
                          ".all(except:", "ActivityCategoryPolicy.all"] {
            XCTAssertFalse(view.contains(forbidden),
                           "shield path must not contain \(forbidden)")
        }
        // "uploaded" may appear in documentation only.
        XCTAssertFalse(view.contains("upload("),
                       "no upload call in the shield path")
        let controller = try source(
            "ios/Sources/KosherGuard/AppShieldController.swift")
        for forbidden in [".all(except:", "ActivityCategoryPolicy.all"] {
            XCTAssertFalse(controller.contains(forbidden),
                           "controller must not escalate scope "
                           + "(\(forbidden))")
        }
        // The contract decodes the gate with a safe default.
        let policy = try source(
            "ios/Sources/URLFilter/AppBlockingPolicy.swift")
        XCTAssertTrue(policy.contains(#"case shieldActive = "shield_active""#))
        XCTAssertTrue(policy.contains(
            "decodeIfPresent(\n            Bool.self, forKey: .shieldActive) ?? false"),
                      "missing gate must decode to false")
        // The app bumps the observed generation only after a
        // successful mirror save, and every manual sync re-pulls the
        // mirror (which re-checks authorization downstream).
        let app = try source(
            "ios/Sources/KosherGuard/KosherGuardApp.swift")
        XCTAssertTrue(app.contains("appPolicyGeneration += 1"))
        XCTAssertTrue(app.contains(
            "refreshAppPolicyMirror(configuration: configuration,"))
        // Mirror reads/writes go through the store's single path
        // accessor - never a hand-derived sibling path.
        XCTAssertTrue(view.contains("store.appPolicyMirrorFile"))
        XCTAssertTrue(app.contains("store.appPolicyMirrorFile"))
        // Save is the identity-checked, race-safe store call.
        XCTAssertTrue(app.contains("saveAppPolicyMirrorIfCurrent("))
        // Sign-out notifies observers so the gate re-evaluates NOW.
        XCTAssertTrue(app.contains("onIdentityTeardown"))
        XCTAssertTrue(app.contains("noteIdentityTeardown"))
        // Identity teardown removes the mirror with the other
        // identity files.
        let store = try source(
            "ios/Sources/URLFilter/FilterRuleStore.swift")
        XCTAssertTrue(store.contains(
            "[snapshotFile, floorFile, bootstrapFile,\n"
                + "                     appPolicyMirrorFile]"),
                      "teardown must remove the app-policy mirror")
    }

    func testAllEntitlementFilesConsistent() throws {
        func keys(_ rel: String) throws -> Set<String> {
            let text = try source(rel)
            var out = Set<String>()
            for line in text.components(separatedBy: .newlines) {
                if let m = line.firstMatch(of: #/<key>([^<]+)</key>/#) {
                    out.insert(String(m.1))
                }
            }
            return out
        }
        let app = try keys("ios/Configuration/App.entitlements")
        XCTAssertTrue(app.contains("com.apple.developer.family-controls"))
        XCTAssertTrue(app.contains(
            "com.apple.developer.networking.networkextension"))
        XCTAssertTrue(app.contains("com.apple.security.application-groups"))
        // URL Filter extension: url-filter-provider + the shared group
        // (its prefilter source reads the shared container).
        let urlExt = try keys(
            "ios/Configuration/URLFilterExtension.entitlements")
        XCTAssertTrue(urlExt.contains(
            "com.apple.developer.networking.networkextension"),
                      "URL Filter extension must declare its provider "
                      + "entitlement")
        XCTAssertTrue(urlExt.contains(
            "com.apple.security.application-groups"))
        // DNS proxy extension: dns-proxy provider capability.
        let dnsExt = try keys(
            "ios/Configuration/DNSProxyExtension.entitlements")
        XCTAssertTrue(dnsExt.contains(
            "com.apple.developer.networking.networkextension"))
        // Every file declares the shared app group the code reads
        // (FilterRuleStore.appGroupIdentifier is the single literal).
        let filterExt = try keys(
            "ios/Configuration/FilterExtension.entitlements")
        XCTAssertTrue(filterExt.contains(
            "com.apple.security.application-groups"))
        // No entitlements file may declare an application group other
        // than the single shared one the code uses.
        for rel in ["ios/Configuration/App.entitlements",
                    "ios/Configuration/URLFilterExtension.entitlements",
                    "ios/Configuration/DNSProxyExtension.entitlements",
                    "ios/Configuration/FilterExtension.entitlements",
                    "ios/Configuration/FilterControlExtension.entitlements"] {
            let text = try source(rel)
            for m in text.matches(of: #/<string>(group\.[^<]+)</string>/#) {
                XCTAssertEqual(String(m.1), "group.com.kosherguard.shared",
                               "\(rel) declares an unexpected app group")
            }
        }
    }

    /// The URL Filter extension packaging must match Apple's official
    /// "Filtering traffic by URL" sample exactly: EXAppExtensionAttributes
    /// with the url-filter-control extension point, @main provider
    /// class with required init, conformance in an extension, and
    /// only the two documented PrefilterData cases.
    func testURLFilterExtensionMatchesAppleTemplate() throws {
        let plist = try source(
            "ios/Configuration/URLFilterExtension-Info.plist")
        XCTAssertTrue(plist.contains("EXAppExtensionAttributes"))
        XCTAssertTrue(plist.contains(
            "com.apple.networkextension.url-filter-control"),
                      "extension point must be the Apple sample value")
        XCTAssertFalse(plist.contains("<key>NSExtensionPrincipalClass</key>"),
                       "the sample declares no principal class")
        XCTAssertFalse(plist.contains(
            "<string>com.apple.networkextension.url-filter</string>"),
                       "the old guessed identifier must not return")
        let provider = try source(
            "ios/Sources/URLFilterExtension/URLFilterControlProvider.swift")
        for needle in [
            "@main",
            "required init()",
            "extension URLFilterControlProvider: NEURLFilterControlProvider",
            ".smallFilter(",
        ] {
            XCTAssertTrue(provider.contains(needle),
                          "provider missing \(needle)")
        }
        XCTAssertFalse(provider.contains(".bytes("),
                       ".bytes is not a documented PrefilterData case")
    }

    /// Every entitlement the new flow needs must be declared in the
    /// app target's entitlements file (still requiring Apple's
    /// approval; declared != granted).
    func testFamilyControlsEntitlementDeclared() throws {
        let ent = try source("ios/Configuration/App.entitlements")
        XCTAssertTrue(ent.contains("com.apple.developer.family-controls"),
                      "family-controls entitlement must be declared")
        XCTAssertTrue(ent.contains("group.com.kosherguard.shared"),
                      "app group for selection persistence must be declared")
        // The selection store must use the same app group the
        // entitlements declare, with no silent private fallback.
        let view = try source(
            "ios/Sources/KosherGuard/AppBlockingView.swift")
        XCTAssertTrue(view.contains("FilterRuleStore.appGroupIdentifier"))
        XCTAssertFalse(view.contains("documentDirectory"),
                       "no silent fallback to a private container")
    }
}

// MARK: - Personal lane (Stage 12 batch 1)

final class PersonalConfigurationTests: XCTestCase {
    func testHTTPSURLValidation() {
        XCTAssertNotNil(PersonalConfiguration.validatedHTTPSURL(
            "https://cp.example.test"))
        XCTAssertNotNil(PersonalConfiguration.validatedHTTPSURL(
            "https://cp.example.test:8443/base"))
        // Credentials are never sent to a plaintext or
        // credential-embedding origin; queries/fragments are not a
        // base URL.
        XCTAssertNil(PersonalConfiguration.validatedHTTPSURL(
            "http://cp.example.test"))
        XCTAssertNil(PersonalConfiguration.validatedHTTPSURL(
            "https://user:pw@cp.example.test"))
        XCTAssertNil(PersonalConfiguration.validatedHTTPSURL(
            "https://cp.example.test/?a=b"))
        XCTAssertNil(PersonalConfiguration.validatedHTTPSURL(
            "https://cp.example.test/#frag"))
        XCTAssertNil(PersonalConfiguration.validatedHTTPSURL(""))
        XCTAssertNil(PersonalConfiguration.validatedHTTPSURL("https://"))
    }

    func testStoreRoundtripAndCorruption() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = PersonalConfigurationStore(directory: dir)
        XCTAssertNil(store.load())
        let config = PersonalConfiguration(
            controlPlaneBaseURL: URL(string: "https://cp.example.test")!,
            datasetBaseURL: URL(string: "https://data.example.test"),
            dohServerURL: nil, pirServerURL: nil,
            pirPrivacyPassIssuerURL: nil, deviceID: 7,
            registrationKey: "kg-" + String(repeating: "a", count: 32),
            deviceName: "Personal device (aaaaaa)")
        try store.save(config)
        XCTAssertEqual(store.load(), config)
        // A corrupt file reads as ABSENT (setup re-runs), never as a
        // partial configuration.
        try Data("not json".utf8).write(to: store.file)
        XCTAssertNil(store.load())
        try store.save(config)
        try store.clear()
        XCTAssertNil(store.load())
    }

    func testResolverPrecedence() {
        let personal = PersonalConfiguration(
            controlPlaneBaseURL: URL(string: "https://cp.personal.test")!,
            datasetBaseURL: URL(string: "https://data.personal.test"),
            dohServerURL: nil, pirServerURL: nil,
            pirPrivacyPassIssuerURL: nil, deviceID: 9,
            registrationKey: "kg-x", deviceName: "p")
        // Complete managed configuration always wins.
        let managedComplete = AppConfiguration(
            controlPlaneBaseURL: URL(string: "https://cp.managed.test"),
            deviceID: 3,
            datasetBaseURL: URL(string: "https://data.managed.test"))
        let resolved = AppConfiguration.current(
            managed: managedComplete, personal: personal)
        XCTAssertEqual(resolved.deviceID, 3)
        // Incomplete managed + personal: personal applies.
        let managedPartial = AppConfiguration(
            controlPlaneBaseURL: URL(string: "https://cp.managed.test"),
            deviceID: nil, issues: ["deviceID missing"])
        let resolved2 = AppConfiguration.current(
            managed: managedPartial, personal: personal)
        XCTAssertEqual(resolved2.deviceID, 9)
        XCTAssertEqual(resolved2.controlPlaneBaseURL,
                       URL(string: "https://cp.personal.test"))
        XCTAssertTrue(resolved2.issues.isEmpty)
        // Neither: the managed read is returned as-is so its per-key
        // issues explain what is missing.
        let resolved3 = AppConfiguration.current(
            managed: managedPartial, personal: nil)
        XCTAssertEqual(resolved3.issues, ["deviceID missing"])
        XCTAssertNil(resolved3.deviceID)
    }

    func testPendingRegistrationIdentity() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = PersonalConfigurationStore(directory: dir)
        let first = try store.loadOrCreatePendingRegistration()
        XCTAssertTrue(first.registrationKey.hasPrefix("kg-"))
        XCTAssertEqual(first.registrationKey.count, 35)
        XCTAssertFalse(first.deviceName.isEmpty)
        XCTAssertTrue(first.deviceName.contains(
            String(first.registrationKey.suffix(6))))
        // A retry reuses the SAME identity (idempotency).
        XCTAssertEqual(try store.loadOrCreatePendingRegistration(), first)
        // A corrupt/invalid pending file regenerates rather than
        // crash-looping setup.
        let pendingFile = dir.appendingPathComponent(
            "pending-registration.json")
        try Data(#"{"registration_key":"bogus","device_name":""}"#.utf8)
            .write(to: pendingFile)
        let second = try store.loadOrCreatePendingRegistration()
        XCTAssertNotEqual(second.registrationKey, first.registrationKey)
        try store.clearPendingRegistration()
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: pendingFile.path))
    }
}

final class ClientConfigClientTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: config)
    }

    func testAllNullsMeansNotDeployed() async throws {
        FixtureProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/api/client-config")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"),
                           "kg_session=fixture")
            return (200, [:], Data(#"{"dataset_base_url":null,"doh_server_url":null,"pir_server_url":null,"pir_privacy_pass_issuer_url":null}"#.utf8))
        }
        let client = ClientConfigClient(baseURL: base,
                                        session: session())
        let config = try await client.fetch(sessionCookie: "fixture")
        XCTAssertNil(config.datasetBaseURL)
        XCTAssertNil(config.dohServerURL)
        XCTAssertNil(config.pirServerURL)
        XCTAssertNil(config.pirPrivacyPassIssuerURL)
        XCTAssertTrue(config.issues.isEmpty)
    }

    func testValuesValidatedAndLonePIRDropped() async throws {
        FixtureProtocol.handler = { _ in
            (200, [:], Data(#"{"dataset_base_url":"https://data.example.test","doh_server_url":"http://insecure.example.test","pir_server_url":"https://pir.example.test","pir_privacy_pass_issuer_url":null}"#.utf8))
        }
        let client = ClientConfigClient(baseURL: base,
                                        session: session())
        let config = try await client.fetch(sessionCookie: "fixture")
        XCTAssertEqual(config.datasetBaseURL,
                       URL(string: "https://data.example.test"))
        // A non-https value is dropped and NAMED, never used.
        XCTAssertNil(config.dohServerURL)
        // Exactly one PIR value is a configuration error: BOTH are
        // dropped so the app never runs a mismatched PIR pair.
        XCTAssertNil(config.pirServerURL)
        XCTAssertNil(config.pirPrivacyPassIssuerURL)
        XCTAssertEqual(config.issues.count, 2)
    }

    func testUnauthorizedAndUnexpectedStatus() async throws {
        FixtureProtocol.handler = { _ in (401, [:], Data()) }
        let client = ClientConfigClient(baseURL: base,
                                        session: session())
        do {
            _ = try await client.fetch(sessionCookie: "fixture")
            XCTFail("accepted 401")
        } catch ClientConfigClient.ClientConfigError.unauthorized {}
        FixtureProtocol.handler = { _ in (500, [:], Data()) }
        do {
            _ = try await client.fetch(sessionCookie: "fixture")
            XCTFail("accepted 500")
        } catch ClientConfigClient.ClientConfigError
                .unexpectedStatus(let code) {
            XCTAssertEqual(code, 500)
        }
        FixtureProtocol.handler = { _ in (200, [:], Data("junk".utf8)) }
        do {
            _ = try await client.fetch(sessionCookie: "fixture")
            XCTFail("accepted malformed body")
        } catch ClientConfigClient.ClientConfigError.malformedResponse {}
    }
}

final class PersonalRegistrationClientTests: XCTestCase {
    let base = URL(string: "https://fixture.example")!
    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return URLSession(configuration: config)
    }

    func testRegisterAndAdopt() async throws {
        FixtureProtocol.handler = { request in
            XCTAssertEqual(request.url?.path,
                           "/api/devices/personal-registration")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"),
                           "kg_session=fixture")
            XCTAssertEqual(request.value(
                forHTTPHeaderField: "X-KosherGuard-Request"), "1")
            return (200, [:], Data(#"{"id":7,"name":"Personal device (aaaaaa)","state":"active","created":true}"#.utf8))
        }
        let client = PersonalRegistrationClient(baseURL: base,
                                                session: session())
        let reg = try await client.register(
            name: "Personal device (aaaaaa)",
            registrationKey: "kg-" + String(repeating: "a", count: 32),
            sessionCookie: "fixture")
        XCTAssertEqual(reg.deviceID, 7)
        XCTAssertTrue(reg.created)
        // A repeated key ADOPTS the existing row (created=false),
        // which is the whole point of the idempotency contract.
        FixtureProtocol.handler = { _ in
            (200, [:], Data(#"{"id":7,"name":"Personal device (aaaaaa)","state":"active","created":false}"#.utf8))
        }
        let again = try await client.register(
            name: "Personal device (aaaaaa)",
            registrationKey: "kg-" + String(repeating: "a", count: 32),
            sessionCookie: "fixture")
        XCTAssertEqual(again.deviceID, 7)
        XCTAssertFalse(again.created)
    }

    func testRejectionMatrix() async throws {
        let client = PersonalRegistrationClient(baseURL: base,
                                                session: session())
        FixtureProtocol.handler = { _ in (401, [:], Data()) }
        do {
            _ = try await client.register(
                name: "n", registrationKey: "k", sessionCookie: "s")
            XCTFail("accepted 401")
        } catch PersonalRegistrationClient.RegistrationError
                .unauthorized {}
        FixtureProtocol.handler = { _ in (409, [:], Data()) }
        do {
            _ = try await client.register(
                name: "n", registrationKey: "k", sessionCookie: "s")
            XCTFail("accepted 409")
        } catch PersonalRegistrationClient.RegistrationError
                .nameConflict {}
        // A zero device id is not a usable registration.
        FixtureProtocol.handler = { _ in
            (200, [:], Data(#"{"id":0,"name":"n","state":"active","created":true}"#.utf8))
        }
        do {
            _ = try await client.register(
                name: "n", registrationKey: "k", sessionCookie: "s")
            XCTFail("accepted id 0")
        } catch PersonalRegistrationClient.RegistrationError
                .invalidPayload {}
        FixtureProtocol.handler = { _ in (200, [:], Data("junk".utf8)) }
        do {
            _ = try await client.register(
                name: "n", registrationKey: "k", sessionCookie: "s")
            XCTFail("accepted malformed body")
        } catch PersonalRegistrationClient.RegistrationError
                .malformedResponse {}
    }
}

// Fakes for the setup orchestration seams.
final class FakeSignIn: SessionSigningIn, @unchecked Sendable {
    enum Mode { case ok(String, delayNanos: UInt64), invalid, rateLimited }
    let mode: Mode
    private let lock = NSLock()
    private var _calls = 0
    private var _started = false
    var calls: Int { lock.lock(); defer { lock.unlock() }; return _calls }
    var started: Bool { lock.lock(); defer { lock.unlock() }; return _started }
    init(_ mode: Mode) { self.mode = mode }
    func signIn(email: String, password: String,
                totpCode: String?) async throws -> String {
        lock.lock(); _calls += 1; _started = true; lock.unlock()
        switch mode {
        case .ok(let cookie, let delay):
            if delay > 0 { try? await Task.sleep(nanoseconds: delay) }
            return cookie
        case .invalid:
            throw AuthSessionClient.AuthError.invalidCredentials
        case .rateLimited:
            throw AuthSessionClient.AuthError.rateLimited
        }
    }
}
final class FakeSignOut: SessionSigningOut {
    private(set) var cookies: [String] = []
    func signOut(sessionCookie: String) async throws {
        cookies.append(sessionCookie)
    }
}
final class FakeConfigFetch: ClientConfigFetching {
    enum Mode {
        case ok(ClientConfigClient.ServiceConfig)
        case unauthorized
    }
    let mode: Mode
    private(set) var calls = 0
    init(_ mode: Mode) { self.mode = mode }
    func fetchConfig(sessionCookie: String) async throws
        -> ClientConfigClient.ServiceConfig {
        calls += 1
        switch mode {
        case .ok(let config): return config
        case .unauthorized:
            throw ClientConfigClient.ClientConfigError.unauthorized
        }
    }
}
final class FakeRegistration: PersonalDeviceRegistering {
    enum Mode {
        case ok(PersonalRegistrationClient.Registration)
        case unauthorized, nameConflict
    }
    let mode: Mode
    private(set) var calls = 0
    init(_ mode: Mode) { self.mode = mode }
    func register(name: String, registrationKey: String,
                  sessionCookie: String) async throws
        -> PersonalRegistrationClient.Registration {
        calls += 1
        switch mode {
        case .ok(let reg): return reg
        case .unauthorized:
            throw PersonalRegistrationClient.RegistrationError
                .unauthorized
        case .nameConflict:
            throw PersonalRegistrationClient.RegistrationError
                .nameConflict
        }
    }
}

final class PersonalSetupCoordinatorTests: XCTestCase {
    func tempStore() -> (PersonalConfigurationStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (PersonalConfigurationStore(directory: dir), dir)
    }
    let services = ClientConfigClient.ServiceConfig(
        datasetBaseURL: URL(string: "https://data.example.test"),
        dohServerURL: URL(string: "https://dns.example.test"),
        pirServerURL: nil, pirPrivacyPassIssuerURL: nil, issues: [])
    let registration = PersonalRegistrationClient.Registration(
        deviceID: 7, name: "Personal device (aaaaaa)",
        state: "active", created: true)

    func testHappyPathPersistsAndSignsOut() async throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let signOut = FakeSignOut()
        let coordinator = PersonalSetupCoordinator(store: store)
        let config = try await coordinator.setUp(
            serverURL: "https://cp.example.test",
            email: "g@example.test", password: "pw", totpCode: "123456",
            auth: FakeSignIn(.ok("session-1", delayNanos: 0)),
            config: FakeConfigFetch(.ok(services)),
            registration: FakeRegistration(.ok(registration)),
            signOut: signOut)
        XCTAssertEqual(config.deviceID, 7)
        XCTAssertEqual(config.controlPlaneBaseURL,
                       URL(string: "https://cp.example.test"))
        XCTAssertEqual(config.datasetBaseURL,
                       URL(string: "https://data.example.test"))
        XCTAssertTrue(config.registrationKey.hasPrefix("kg-"))
        // Persisted, and the pending identity was consumed.
        XCTAssertEqual(store.load(), config)
        XCTAssertFalse(FileManager.default.fileExists(atPath:
            dir.appendingPathComponent("pending-registration.json").path))
        // The temporary setup session never lingers server-side.
        XCTAssertEqual(signOut.cookies, ["session-1"])
    }

    func testInvalidServerURLDoesNoNetwork() async throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let auth = FakeSignIn(.ok("s", delayNanos: 0))
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: "http://cp.example.test",
                email: "g@example.test", password: "pw", totpCode: nil,
                auth: auth, config: FakeConfigFetch(.ok(services)),
                registration: FakeRegistration(.ok(registration)),
                signOut: nil)
            XCTFail("accepted http URL")
        } catch PersonalSetupCoordinator.SetupError.invalidServerURL {}
        XCTAssertEqual(auth.calls, 0)
    }

    func testBadCredentialsRegisterNothingAndSignOut() async throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let signOut = FakeSignOut()
        let registration = FakeRegistration(.ok(self.registration))
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: "https://cp.example.test",
                email: "g@example.test", password: "wrong",
                totpCode: nil,
                auth: FakeSignIn(.ok("session-2", delayNanos: 0)),
                config: FakeConfigFetch(.unauthorized),
                registration: registration,
                signOut: signOut)
            XCTFail("accepted rejected discovery")
        } catch PersonalSetupCoordinator.SetupError
                .invalidCredentials {}
        XCTAssertEqual(registration.calls, 0)
        XCTAssertNil(store.load())
        // Even a mid-flow failure signs the session out.
        XCTAssertEqual(signOut.cookies, ["session-2"])
    }

    func testInactiveDeviceIsSurfacedNotWorkedAround() async throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let inactive = PersonalRegistrationClient.Registration(
            deviceID: 7, name: "Personal device (aaaaaa)",
            state: "inactive", created: false)
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: "https://cp.example.test",
                email: "g@example.test", password: "pw", totpCode: nil,
                auth: FakeSignIn(.ok("s", delayNanos: 0)),
                config: FakeConfigFetch(.ok(services)),
                registration: FakeRegistration(.ok(inactive)),
                signOut: nil)
            XCTFail("adopted an inactive device")
        } catch PersonalSetupCoordinator.SetupError
                .deviceNotActive(let state) {
            XCTAssertEqual(state, "inactive")
        }
        XCTAssertNil(store.load())
    }

    func testConcurrentSetupRefused() async throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let coordinator = PersonalSetupCoordinator(store: store)
        let slowAuth = FakeSignIn(.ok("s", delayNanos: 150_000_000))
        async let first = coordinator.setUp(
            serverURL: "https://cp.example.test",
            email: "g@example.test", password: "pw", totpCode: nil,
            auth: slowAuth,
            config: FakeConfigFetch(.ok(services)),
            registration: FakeRegistration(.ok(registration)),
            signOut: nil)
        // Wait until the FIRST attempt actually holds the actor and is
        // inside its slow sign-in; only then is the second attempt a
        // genuine concurrency probe rather than a scheduling race.
        let deadline = Date().addingTimeInterval(5)
        while !slowAuth.started, Date() < deadline {
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertTrue(slowAuth.started, "first setup never started")
        do {
            _ = try await coordinator.setUp(
                serverURL: "https://cp.example.test",
                email: "g@example.test", password: "pw", totpCode: nil,
                auth: FakeSignIn(.ok("s", delayNanos: 0)),
                config: FakeConfigFetch(.ok(services)),
                registration: FakeRegistration(.ok(registration)),
                signOut: nil)
            XCTFail("second setup ran concurrently")
        } catch PersonalSetupCoordinator.SetupError
                .alreadyInProgress {}
        _ = try await first
    }

    func testPersistenceFailureIsDistinctAndSignsOut() async throws {
        // A directory that cannot be created forces the store to
        // fail; the error is the distinct persistence case and the
        // session is still signed out.
        let store = PersonalConfigurationStore(directory: URL(
            fileURLWithPath: "/proc/kg-\(UUID().uuidString)"))
        let signOut = FakeSignOut()
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: "https://cp.example.test",
                email: "g@example.test", password: "pw", totpCode: nil,
                auth: FakeSignIn(.ok("session-3", delayNanos: 0)),
                config: FakeConfigFetch(.ok(services)),
                registration: FakeRegistration(.ok(registration)),
                signOut: signOut)
            XCTFail("accepted an unwritable store")
        } catch PersonalSetupCoordinator.SetupError
                .persistenceFailed {}
        XCTAssertEqual(signOut.cookies, ["session-3"])
    }
}

// MARK: - Personal lane corrections (review batch 1)

final class PersonalLaneCorrectionTests: XCTestCase {
    func tempStore() -> (PersonalConfigurationStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        return (PersonalConfigurationStore(directory: dir), dir)
    }
    let services = ClientConfigClient.ServiceConfig(
        datasetBaseURL: URL(string: "https://data.example.test"),
        dohServerURL: nil, pirServerURL: nil,
        pirPrivacyPassIssuerURL: nil, issues: [])

    // A generic URLError (network failure) is NOT one of the typed
    // client errors: it must still route to .failed AND still run the
    // best-effort sign-out. Regression: the session used to leak.
    func testGenericNetworkErrorStillSignsOut() async throws {
        struct FailingConfig: ClientConfigFetching {
            func fetchConfig(sessionCookie: String) async throws
                -> ClientConfigClient.ServiceConfig {
                throw URLError(.notConnectedToInternet)
            }
        }
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let signOut = FakeSignOut()
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: "https://cp.example.test",
                email: "g@example.test", password: "pw", totpCode: nil,
                auth: FakeSignIn(.ok("session-x", delayNanos: 0)),
                config: FailingConfig(),
                registration: FakeRegistration(.ok(
                    PersonalRegistrationClient.Registration(
                        deviceID: 1, name: "n", state: "active",
                        created: true))),
                signOut: signOut)
            XCTFail("accepted a network failure")
        } catch PersonalSetupCoordinator.SetupError.failed {}
        XCTAssertEqual(signOut.cookies, ["session-x"])
    }

    // Cancellation-shaped errors take the same cleanup path.
    func testCancellationStillSignsOut() async throws {
        struct CancellingConfig: ClientConfigFetching {
            func fetchConfig(sessionCookie: String) async throws
                -> ClientConfigClient.ServiceConfig {
                throw CancellationError()
            }
        }
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let signOut = FakeSignOut()
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: "https://cp.example.test",
                email: "g@example.test", password: "pw", totpCode: nil,
                auth: FakeSignIn(.ok("session-c", delayNanos: 0)),
                config: CancellingConfig(),
                registration: FakeRegistration(.ok(
                    PersonalRegistrationClient.Registration(
                        deviceID: 1, name: "n", state: "active",
                        created: true))),
                signOut: signOut)
            XCTFail("accepted cancellation")
        } catch PersonalSetupCoordinator.SetupError.failed {}
        XCTAssertEqual(signOut.cookies, ["session-c"])
    }

    // Name-conflict recovery: the SAME registration key is retried
    // with a regenerated display name, so recovery never creates a
    // second device row and never dead-ends.
    final class ConflictThenOk: PersonalDeviceRegistering {
        private let lock = NSLock()
        private var _calls = 0
        var calls: Int { lock.lock(); defer { lock.unlock() }
            return _calls }
        private(set) var names: [String] = []
        func register(name: String, registrationKey: String,
                      sessionCookie: String) async throws
            -> PersonalRegistrationClient.Registration {
            lock.lock(); _calls += 1; names.append(name); lock.unlock()
            if _calls == 1 {
                throw PersonalRegistrationClient.RegistrationError
                    .nameConflict
            }
            return PersonalRegistrationClient.Registration(
                deviceID: 7, name: name, state: "active", created: true)
        }
    }

    func testNameConflictRegeneratesNameKeepsKey() async throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let registration = ConflictThenOk()
        let coordinator = PersonalSetupCoordinator(store: store)
        let config = try await coordinator.setUp(
            serverURL: "https://cp.example.test",
            email: "g@example.test", password: "pw", totpCode: nil,
            auth: FakeSignIn(.ok("s", delayNanos: 0)),
            config: FakeConfigFetch(.ok(services)),
            registration: registration, signOut: nil)
        XCTAssertEqual(registration.calls, 2)
        XCTAssertEqual(registration.names.count, 2)
        XCTAssertNotEqual(registration.names[0], registration.names[1])
        // Idempotency intact: one key throughout, one device row.
        XCTAssertEqual(config.deviceID, 7)
        XCTAssertEqual(store.load()?.deviceName, registration.names[1])
    }

    final class AlwaysConflict: PersonalDeviceRegistering {
        private let lock = NSLock()
        private var _calls = 0
        var calls: Int { lock.lock(); defer { lock.unlock() }
            return _calls }
        func register(name: String, registrationKey: String,
                      sessionCookie: String) async throws
            -> PersonalRegistrationClient.Registration {
            lock.lock(); _calls += 1; lock.unlock()
            throw PersonalRegistrationClient.RegistrationError
                .nameConflict
        }
    }

    func testPersistentNameConflictIsBounded() async throws {
        let (store, dir) = tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let registration = AlwaysConflict()
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: "https://cp.example.test",
                email: "g@example.test", password: "pw", totpCode: nil,
                auth: FakeSignIn(.ok("s", delayNanos: 0)),
                config: FakeConfigFetch(.ok(services)),
                registration: registration, signOut: nil)
            XCTFail("persistent conflict accepted")
        } catch PersonalSetupCoordinator.SetupError.nameConflict {}
        // Initial + two retries, then an honest failure.
        XCTAssertEqual(registration.calls, 3)
        XCTAssertNil(store.load())
    }

    // PIR URLs are host-only (NSPIRConfiguration matches by host).
    func testPIRHostOnlyValidation() {
        XCTAssertNotNil(PersonalConfiguration.validatedHostOnlyHTTPSURL(
            "https://pir.example.test"))
        XCTAssertNotNil(PersonalConfiguration.validatedHostOnlyHTTPSURL(
            "https://pir.example.test:8443"))
        XCTAssertNil(PersonalConfiguration.validatedHostOnlyHTTPSURL(
            "https://pir.example.test/pir"))
        XCTAssertNil(PersonalConfiguration.validatedHostOnlyHTTPSURL(
            "https://pir.example.test/?q=1"))
        XCTAssertNil(PersonalConfiguration.validatedHostOnlyHTTPSURL(
            "https://user:pw@pir.example.test"))
        XCTAssertNil(PersonalConfiguration.validatedHostOnlyHTTPSURL(
            "http://pir.example.test"))
    }

    func testDiscoveryDropsPathPIRWithIssue() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        FixtureProtocol.handler = { _ in
            (200, [:], Data(#"{"dataset_base_url":null,"doh_server_url":null,"pir_server_url":"https://pir.example.test/pir","pir_privacy_pass_issuer_url":"https://issuer.example.test"}"#.utf8))
        }
        let client = ClientConfigClient(
            baseURL: URL(string: "https://fixture.example")!,
            session: URLSession(configuration: config))
        let fetched = try await client.fetch(sessionCookie: "fixture")
        // The path-shaped PIR URL is dropped; the lone issuer then
        // also drops under the pair rule - never a mismatched pair.
        XCTAssertNil(fetched.pirServerURL)
        XCTAssertNil(fetched.pirPrivacyPassIssuerURL)
        XCTAssertFalse(fetched.issues.isEmpty)
    }
}
