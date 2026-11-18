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
        /// The endpoints are provably undeployable placeholder hosts
        /// (RFC 2606/6761 reserved names, e.g. the shipped
        /// *.kosherguard.example.com stand-ins). Refused BEFORE any
        /// NEURLFilterManager call: enabling with placeholders would
        /// install a filter whose PIR lookups can never complete,
        /// which under shouldFailClosed blocks all WebKit/URLSession
        /// traffic for no reason. The honest state is "URL database
        /// service not deployed" - the filter stays off.
        case placeholderHosts(String)
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
        // PLACEHOLDER REFUSAL, before any system call: standards-
        // reserved hosts (the shipped *.kosherguard.example.com
        // stand-ins included) can never be a deployed PIR service.
        // Portable-XCTested policy (PIREndpointPolicy).
        if let problem = PIREndpointPolicy.deploymentProblem(
            pirServer: pirServer, issuer: issuer) {
            throw ConfigurationError.placeholderHosts(problem)
        }
        // NSPIRConfiguration (grounded in Apple's PIR-service
        // onboarding documentation, read 2026-11-17): the app
        // Info.plist statically declares the PIR endpoints; from
        // iOS/macOS 27.3 the system REJECTS any mismatch between
        // these runtime values and the plist. Validate the match
        // here so a misconfigured deployment fails at enable time
        // with a clear error instead of a system rejection later.
        let declared = Bundle.main.object(
            forInfoDictionaryKey: "NSPIRConfiguration") as? [String: Any]
        if let problem = PIREndpointPolicy.declarationProblem(
            declaredPIR: declared?["PIRServerURL"] as? String,
            declaredIssuer: declared?["PrivacyPassIssuerURL"] as? String,
            runtimePIR: pirServer, runtimeIssuer: issuer) {
            throw ConfigurationError.notConfigured(problem)
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
        // No pirServer/issuer values exist in this scope BY DESIGN:
        // they are per-call inputs of enable(from:), bound from the
        // CURRENT managed configuration, used to fail closed when
        // unconfigured, to cross-check the Info.plist
        // NSPIRConfiguration declaration, and to build the
        // setConfiguration call. Disabling never reconfigures the
        // PIR endpoints, so the enable-time plist-mismatch validation
        // does not apply here - and must not: disableFilter() is the
        // fail-closed path the caller takes precisely when the PIR
        // keys are missing or invalid, so it has to stay able to
        // turn the filter off in exactly that state.
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

    /// A readback of the SYSTEM's own state, distinct from what this
    /// process last attempted: loadFromPreferences re-reads the
    /// persisted configuration, then isEnabled / status /
    /// lastDisconnectError come from the manager, not from our
    /// bookkeeping. status is the NEURLFilterManager.Status enum
    /// (invalid/stopped/starting/running/stopping per Apple's
    /// documentation, fetched 2026-11-17) rendered with
    /// String(describing:) so a future SDK case cannot crash the
    /// readback. UNVERIFIED on device - no iOS build exists.
    struct SystemReadback: Equatable {
        var isEnabled: Bool
        var status: String
        var lastError: String?

        var summary: String {
            var s = isEnabled
                ? "enabled, status \(status)"
                : "off, status \(status)"
            if let lastError { s += " - last error: \(lastError)" }
            return s
        }
    }

    static func readSystemStatus() async -> SystemReadback {
        let manager = NEURLFilterManager.shared
        do {
            try await manager.loadFromPreferences()
        } catch {
            return SystemReadback(
                isEnabled: manager.isEnabled,
                status: "preferences unreadable",
                lastError: String(describing: error))
        }
        let status = await manager.status
        let disconnectError = await manager.lastDisconnectError
        return SystemReadback(
            isEnabled: manager.isEnabled,
            status: String(describing: status),
            lastError: disconnectError.map { String(describing: $0) })
    }
}
