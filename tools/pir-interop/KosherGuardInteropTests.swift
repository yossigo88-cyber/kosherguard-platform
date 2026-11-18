// KosherGuard PIR local interop test (tools/pir-interop/).
//
// Copied into the apple/pir-service-example checkout at
// Tests/PIRServiceTests/ by .github/workflows/pir-local-interop.yml
// (no modification to Apple's sources; this file joins Apple's own
// test target so it can use the same @testable surface Apple's tests
// use).
//
// What runs here is Apple's real code end to end over REAL loopback
// HTTP (HummingbirdTesting `.live`, a genuine socket server + HTTP
// client):
//   * the server: Apple's buildApplication + ReloadService - the exact
//     application the PIRService binary wraps (Sources/PIRService/
//     main.swift is a ~20-line argument parser around these calls) -
//     loading the KosherGuard dataset processed by Apple's
//     PIRProcessDatabase from url-filter-server's real textpb export;
//   * the client: Apple's PIRServiceTesting.PIRClient - Privacy Pass
//     token issuance, config fetch, evaluation-key generation/upload,
//     encrypted query generation and response decryption.
// This file adds NO cryptography and reimplements NO protocol piece.
//
// Environment:
//   KG_PIR_WORKDIR      directory holding service-config.json and the
//                       processed url-0.bin / url-0.params.txtpb
//   KG_PIR_EXPECT_MODE  "base" (default) or "update" (dataset after
//                       adding newly-blocked.example)

import Foundation
import HomomorphicEncryption
import Hummingbird
import HummingbirdTesting
@testable import PIRService
@testable import PIRServiceTesting
import PrivateInformationRetrieval
import Testing
import Util

struct KosherGuardInteropTests {
    static let usecase = "com.kosherguard.app.url.filtering"

    @Test
    func kosherGuardDatasetRoundTrip() async throws {
        let workdir = try #require(
            ProcessInfo.processInfo.environment["KG_PIR_WORKDIR"],
            "KG_PIR_WORKDIR must point at the processed dataset directory")
        let updateMode = ProcessInfo.processInfo.environment["KG_PIR_EXPECT_MODE"] == "update"
        // loadUsecase resolves "<fileStem>-<shard>.{params.txtpb,bin}"
        // relative to the process working directory.
        // NOTE: on Linux (swift-corelibs-foundation)
        // changeCurrentDirectoryPath is a NON-throwing Bool on both
        // platforms (swift-6.1-RELEASE Foundation and
        // swift-corelibs-foundation alike; the earlier
        // throws-on-Linux diagnosis was wrong). A false result for a
        // bad path must not slip through silently, so require the
        // actual CWD afterwards: plain property access + ==, no
        // throwing call inside the #require macro expansion (run
        // 44237436996 rejected one even with `try` inside).
        _ = FileManager.default.changeCurrentDirectoryPath(workdir)
        #require(FileManager.default.currentDirectoryPath == workdir)

        // Same wiring as Sources/PIRService/main.swift.
        let usecaseStore = UsecaseStore()
        let privacyPassState = try PrivacyPassState()
        let reportStore = ReportStore()
        let app = try await buildApplication(
            usecaseStore: usecaseStore,
            privacyPassState: privacyPassState,
            reportStore: reportStore)
        let reloadService = ReloadService(
            configFile: URL(fileURLWithPath: "\(workdir)/service-config.json"),
            usecaseStore: usecaseStore,
            privacyPassState: privacyPassState,
            reportStore: reportStore,
            logger: app.logger)
        try await reloadService.reloadConfiguration()

        try await app.test(.live) { client in
            // DEVICE dataset semantics (Apple's NEURLFilterDataFormat.md
            // at the pinned revision): PRESENCE of a keyword means
            // block; the value is Apple's ignored placeholder "1".
            // Present assertions pin byte-exact round trips; absent
            // assertions are the security boundary - an allow-only
            // host, and a host whose explicit allow beats a category
            // block, must NOT exist in the device dataset, because
            // presence on device would BLOCK them.
            var present: [(keyword: String, value: String)] = [
                ("blocked-example.com", "1"),
                ("ads-tracker.example", "1"),
            ]
            if updateMode {
                present.append(("newly-blocked.example", "1"))
            }
            let absent = [
                "allowed-example.com",
                "precedence-example.com",
                "not-in-dataset.example",
            ]

            // Current-platform path (iOS/macOS 27.3: public key from the
            // token issuer directory).
            var pirClient = PIRClient<MulPirClient<Bfv<UInt32>>>(
                connection: client, platform: .iOS27_3, userToken: "AAAA")
            let keywords = present.map { Array($0.keyword.utf8) }
                + absent.map { Array($0.utf8) }
            let results = try await pirClient.request(
                keywords: keywords, usecase: Self.usecase)
            #expect(results.count == keywords.count)

            for (expectation, result) in zip(present, results) {
                let decoded = result.map { String(decoding: $0, as: UTF8.self) }
                print("PIR-QUERY present \(expectation.keyword) -> \(decoded ?? "<nil>")")
                #expect(decoded == expectation.value)
            }
            for (keyword, result) in zip(absent, results.dropFirst(present.count)) {
                let decoded = result.map { String(decoding: $0, as: UTF8.self) }
                print("PIR-QUERY absent \(keyword) -> \(decoded ?? "<nil>")")
                #expect(decoded == nil,
                        "\(keyword) must be ABSENT from the device dataset (presence means block)")
            }

            // Legacy-platform path (token-key-for-user-token endpoint).
            var legacyClient = PIRClient<MulPirClient<Bfv<UInt32>>>(
                connection: client, platform: .iOS18, userToken: "AAAA")
            let legacyResult = try await legacyClient.request(
                keywords: [Array("blocked-example.com".utf8)], usecase: Self.usecase)
            let legacyDecoded = legacyResult.first?.map { String(decoding: $0, as: UTF8.self) }
            print("PIR-QUERY ios18 blocked-example.com -> \(legacyDecoded ?? "<nil>")")
            #expect(legacyDecoded == "1")

            // An unknown user token must be rejected at /issue (401).
            var unauthorizedClient = PIRClient<MulPirClient<Bfv<UInt32>>>(
                connection: client, platform: .iOS27_3, userToken: "INVALID")
            await #expect {
                try await unauthorizedClient.request(
                    keywords: [Array("blocked-example.com".utf8)], usecase: Self.usecase)
            } throws: { error in
                if let error = error as? PIRClientError,
                   case let .failedToFetchToken(status, _) = error
                {
                    return status == .unauthorized
                }
                return false
            }
            print("PIR-AUTH invalid user token rejected at /issue with 401, as expected")
        }
        print("PIR-LOOPBACK-RESULT: PASS (mode: \(updateMode ? "update" : "base"))")
    }
}
