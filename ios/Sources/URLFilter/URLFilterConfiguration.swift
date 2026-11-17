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
/// Console (Identity & Trust page) before the off-device lookup works
/// (developer.apple.com/documentation/networkextension/url-filters,
/// read 2026-11-17). Registration is an Apple-side setup step listed
/// in the stage report's Apple-dependent task list.
@available(iOS 26.0, *)
struct URLFilterConfiguration {

    enum ConfigurationError: Error, Equatable {
        /// The managed configuration does not carry the PIR endpoint
        /// pair, or either value failed URL validation. Enabling the
        /// URL Filter without them would produce a filter that can
        /// never resolve a prefilter hit - fail closed instead.
        case notConfigured(String)
    }

    /// Configure (or reconfigure) the system URL Filter from the
    /// CURRENT managed configuration. Values are re-read on every
    /// call - a captured configuration is never authoritative.
    ///
    /// - controlProviderBundleIdentifier: the bundle ID of the
    ///   DEDICATED URL Filter extension target (KosherGuardURLFilter)
    ///   whose entry point conforms to NEURLFilterControlProvider -
    ///   NOT the NEFilterControlProvider extension.
    /// - shouldFailClosed: policy default TRUE. When the off-device
    ///   PIR lookup cannot complete, the system blocks rather than
    ///   silently allowing uncategorized content past the filter.
    static func enable(
        from configuration: AppConfiguration,
        controlProviderBundleIdentifier: String =
            "com.kosherguard.app.URLFilterExtension",
        prefilterFetchInterval: TimeInterval = 3600,
        shouldFailClosed: Bool = true
    ) async throws {
        guard let pirServer = configuration.pirServerURL else {
            throw ConfigurationError.notConfigured("pirServerURL")
        }
        guard let issuer = configuration.pirPrivacyPassIssuerURL else {
            throw ConfigurationError.notConfigured("pirPrivacyPassIssuerURL")
        }
        // NSPIRConfiguration (grounded in Apple's PIR-service
        // onboarding documentation, read 2026-11-17): the app
        // Info.plist statically declares the PIR endpoints; from
        // iOS/macOS 27.3 the system REJECTS any mismatch between
        // these runtime values and the plist. Validate the match
        // here so a misconfigured deployment fails at enable time
        // with a clear error instead of a system rejection later.
        if let declared = Bundle.main.object(
            forInfoDictionaryKey: "NSPIRConfiguration")
            as? [String: Any] {
            if let declaredPIR = declared["PIRServerURL"] as? String,
               let declaredURL = URL(string: declaredPIR),
               declaredURL.host(percentEncoded: false)
                    != pirServer.host(percentEncoded: false) {
                throw ConfigurationError.notConfigured(
                    "pirServerURL does not match the Info.plist "
                    + "NSPIRConfiguration.PIRServerURL")
            }
            if let declaredIssuer =
                    declared["PrivacyPassIssuerURL"] as? String,
               let declaredURL = URL(string: declaredIssuer),
               declaredURL.host(percentEncoded: false)
                    != issuer.host(percentEncoded: false) {
                throw ConfigurationError.notConfigured(
                    "pirPrivacyPassIssuerURL does not match the "
                    + "Info.plist NSPIRConfiguration."
                    + "PrivacyPassIssuerURL")
            }
        }
        let manager = NEURLFilterManager.shared
        try await manager.loadFromPreferences()
        // PRIVACY: the PIR path exists so the server can NEVER learn
        // which URL a device asked about (queries arrive through
        // Apple's OHTTP relay, authenticated by Privacy Pass). A
        // per-device authentication token on this call would
        // re-identify every query and break that model, so the token
        // is deliberately empty; whether the deployment adds a
        // service-wide (identical for all devices) abuse-prevention
        // token is an operations decision, recorded in the stage
        // report - never a per-device credential here.
        try manager.setConfiguration(
            pirServerURL: pirServer,
            pirPrivacyPassIssuerURL: issuer,
            pirAuthenticationToken: "",
            controlProviderBundleIdentifier: controlProviderBundleIdentifier)
        manager.prefilterFetchInterval = prefilterFetchInterval
        manager.shouldFailClosed = shouldFailClosed
        manager.localizedDescription = "KosherGuard URL Filter"
        manager.isEnabled = true
        try await manager.saveToPreferences()
    }

    static func disableFilter() async throws {
        // NSPIRConfiguration (grounded in Apple's PIR-service
        // onboarding documentation, read 2026-11-17): the app
        // Info.plist statically declares the PIR endpoints; from
        // iOS/macOS 27.3 the system REJECTS any mismatch between
        // these runtime values and the plist. Validate the match
        // here so a misconfigured deployment fails at enable time
        // with a clear error instead of a system rejection later.
        if let declared = Bundle.main.object(
            forInfoDictionaryKey: "NSPIRConfiguration")
            as? [String: Any] {
            if let declaredPIR = declared["PIRServerURL"] as? String,
               let declaredURL = URL(string: declaredPIR),
               declaredURL.host(percentEncoded: false)
                    != pirServer.host(percentEncoded: false) {
                throw ConfigurationError.notConfigured(
                    "pirServerURL does not match the Info.plist "
                    + "NSPIRConfiguration.PIRServerURL")
            }
            if let declaredIssuer =
                    declared["PrivacyPassIssuerURL"] as? String,
               let declaredURL = URL(string: declaredIssuer),
               declaredURL.host(percentEncoded: false)
                    != issuer.host(percentEncoded: false) {
                throw ConfigurationError.notConfigured(
                    "pirPrivacyPassIssuerURL does not match the "
                    + "Info.plist NSPIRConfiguration."
                    + "PrivacyPassIssuerURL")
            }
        }
        let manager = NEURLFilterManager.shared
        try await manager.loadFromPreferences()
        manager.isEnabled = false
        try await manager.saveToPreferences()
    }

    /// Current honest state for the app UI: enabled != filtered; the
    /// prefilter and PIR database must both be ready for real verdicts.
    static func isFilterEnabled() -> Bool {
        return NEURLFilterManager.shared.isEnabled
    }
}
