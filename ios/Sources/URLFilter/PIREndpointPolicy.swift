// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The caller
// (URLFilterConfiguration.enable) is Apple-only - see ios/README.md.
import Foundation

/// Deployability policy for the URL Filter's PIR endpoints, the gate
/// that keeps PLACEHOLDER hosts from ever reaching
/// NEURLFilterManager.setConfiguration.
///
/// Why this exists: App-Info.plist must statically declare the PIR
/// endpoints (NSPIRConfiguration) and the runtime values must match
/// it, so while the declared hosts are undeployed placeholders, ANY
/// configuration that could enable the URL Filter is necessarily
/// pointing at non-existent servers. Enabling then would hand the
/// system a filter whose PIR lookups can never complete - with
/// shouldFailClosed = true that blocks all WebKit/URLSession traffic
/// for no reason. Refusing at enable time is the honest state: the
/// URL database service is not deployed yet.
///
/// Non-deployable hosts (can NEVER be a real service, by standards):
/// RFC 2606 documentation domains (example.com/net/org + subdomains)
/// and the RFC 6761 special-use TLDs .example/.invalid/.test plus
/// localhost names. The current placeholder hosts
/// (pir/issuer.kosherguard.example.com) fall under example.com.
public enum PIREndpointPolicy {

    /// A problem string when either endpoint cannot be a deployed
    /// PIR service, nil when both are deployable in principle. This
    /// says nothing about whether the service is ACTUALLY deployed -
    /// only that the endpoints are not provable placeholders.
    public static func deploymentProblem(pirServer: URL,
                                         issuer: URL) -> String? {
        for (label, url) in [("pirServerURL", pirServer),
                             ("pirPrivacyPassIssuerURL", issuer)] {
            if let problem = endpointProblem(url) {
                return "\(label): \(problem)"
            }
        }
        return nil
    }

    /// The static Info.plist declaration must match the runtime
    /// values (from iOS/macOS 27.3 the system REJECTS a mismatch -
    /// see the NSPIRConfiguration comment in App-Info.plist).
    /// Compares hosts only, case-insensitively, ignoring a trailing
    /// dot. A declared key that is absent imposes no constraint here.
    /// Returns a problem string on mismatch, nil when consistent.
    public static func declarationProblem(
        declaredPIR: String?, declaredIssuer: String?,
        runtimePIR: URL, runtimeIssuer: URL
    ) -> String? {
        func normalizedHost(_ raw: String?) -> String? {
            raw.flatMap { URL(string: $0) }?
                .host(percentEncoded: false)?
                .lowercased().trimmingTrailingDots()
        }
        let runtimePIRHost = runtimePIR.host(percentEncoded: false)?
            .lowercased().trimmingTrailingDots()
        let runtimeIssuerHost = runtimeIssuer.host(percentEncoded: false)?
            .lowercased().trimmingTrailingDots()
        if let declared = normalizedHost(declaredPIR),
           declared != runtimePIRHost {
            return "pirServerURL does not match the Info.plist "
                + "NSPIRConfiguration.PIRServerURL"
        }
        if let declared = normalizedHost(declaredIssuer),
           declared != runtimeIssuerHost {
            return "pirPrivacyPassIssuerURL does not match the "
                + "Info.plist NSPIRConfiguration.PrivacyPassIssuerURL"
        }
        return nil
    }

    private static func endpointProblem(_ url: URL) -> String? {
        // NSPIRConfiguration takes hosts only: no credentials, port,
        // path, query or fragment (same shape AppConfiguration
        // already enforces for managed values).
        guard url.scheme?.lowercased() == "https",
              let host = url.host(percentEncoded: false)?.lowercased(),
              url.user == nil, url.password == nil, url.port == nil,
              url.path.isEmpty || url.path == "/",
              url.query == nil, url.fragment == nil
        else {
            return "must be a host-only https:// URL"
        }
        let h = host.trimmingTrailingDots()
        if h == "localhost" || h.hasSuffix(".localhost")
            || h.hasSuffix(".invalid")
            || h.hasSuffix(".test")
            || h.hasSuffix(".example")
            || h == "example.com" || h.hasSuffix(".example.com")
            || h == "example.net" || h.hasSuffix(".example.net")
            || h == "example.org" || h.hasSuffix(".example.org") {
            return "host is a standards-reserved non-deployable name "
                + "(placeholder)"
        }
        return nil
    }
}

private extension String {
    func trimmingTrailingDots() -> String {
        var s = self
        while s.hasSuffix(".") { s.removeLast() }
        return s
    }
}
