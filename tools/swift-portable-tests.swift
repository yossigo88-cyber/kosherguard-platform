import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
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
    let manifest = Data(#"{"version":2,"rule_count":1,"blocked_count":1,"provenance":"fixture","prefilter":{"bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}"#.utf8)

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
        do { _ = try await updater.refresh(credential:"fixture",now:now); XCTFail("accepted 401") }
        catch PrefilterUpdater.UpdateError.fetchFailed {}
        XCTAssertEqual(updater.currentVersion,0)
        do { _ = try await updater.refresh(credential:"fixture",now:now.addingTimeInterval(1)); XCTFail("polled too soon") }
        catch PrefilterUpdater.UpdateError.tooSoon {}
    }
}
