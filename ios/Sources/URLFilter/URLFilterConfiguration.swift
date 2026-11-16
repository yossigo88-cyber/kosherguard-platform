// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation
import NetworkExtension

/// iOS 26 NEURLFilterManager integration.
///
/// Honest coverage statement (from the investigation, 5.4): the URL
/// Filter examines WebKit/URLSession traffic only; verdicts are
/// binary (block or allow - no "warn and override"); PIR + the
/// Apple-hosted relay make per-device reporting impossible by design;
/// MDM-pushed configuration requires a supervised device.
///
/// The PIR database use case must be named
/// `<app-bundle-id>.url.filtering` and registered in the CloudKit
/// Console (Identity & Trust page) before the off-device lookup works.
@available(iOS 26.0, *)
struct URLFilterConfiguration {

    /// Configure the system URL Filter for the standalone-app route
    /// (no supervision, no MDM - and therefore no removal protection;
    /// the MDM route is the managed path and lives in the MDM
    /// configuration payload instead).
    static func enableStandaloneFilter() async throws {
        let manager = NEURLFilterManager.shared
        manager.isEnabled = true
        try await manager.saveToPreferences()
    }

    static func disableFilter() async throws {
        let manager = NEURLFilterManager.shared
        manager.isEnabled = false
        try await manager.saveToPreferences()
    }

    /// Current honest state for the app UI: enabled != filtered; the
    /// prefilter and PIR database must both be ready for real verdicts.
    static func isFilterEnabled() -> Bool {
        return NEURLFilterManager.shared.isEnabled
    }
}
