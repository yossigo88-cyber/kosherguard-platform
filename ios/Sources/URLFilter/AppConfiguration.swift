// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). Reading the real
// com.apple.configuration.managed suite on a supervised device is
// UNVERIFIED - see ios/README.md.
import Foundation

/// Server configuration supplied by MDM-managed App Configuration
/// (the standard `com.apple.configuration.managed` UserDefaults
/// suite a supervised device's MDM server pushes). This is the real
/// configuration mechanism for the platform - the same MDM channel
/// that enrolls the device supplies where its control plane is and
/// which device record it owns. No live server URL or secret is
/// baked into the build; without managed configuration the app is
/// honestly "not configured".
///
/// Keys (pushed by the control plane's InstallApplication managed
/// Configuration - mdm/app_management.py, or by another MDM):
/// - "controlPlaneBaseURL" (string, https, required): auth, rules
///   export and credential issuance.
/// - "datasetBaseURL" (string, https, required for sync): the
///   url-filter-server base for manifest/prefilter downloads.
/// - "dohServerURL" (string, https, optional): the dns-edge DoH
///   endpoint for app-mediated resolution (DNSOverHTTPSClient).
/// - "deviceID" (integer or digit-string, required): the control
///   plane's device record id.
/// - "pirServerURL" (string, https, optional - required to enable the
///   iOS 26 URL Filter): the Private Information Retrieval endpoint
///   for off-device verdicts.
/// - "pirPrivacyPassIssuerURL" (string, https, optional - required
///   with pirServerURL): the Privacy Pass issuer the system uses for
///   anonymous PIR authentication.
public struct AppConfiguration: Equatable {
    public let controlPlaneBaseURL: URL?
    public let datasetBaseURL: URL?
    public let dohServerURL: URL?
    public let pirServerURL: URL?
    public let pirPrivacyPassIssuerURL: URL?
    public let deviceID: Int?
    /// Human-readable per-key problems, for the UI and support.
    /// A key that is absent and optional produces no issue; absent
    /// and required, or present and invalid, does.
    public let issues: [String]

    private static let suite = "com.apple.configuration.managed"

    public init(controlPlaneBaseURL: URL?, deviceID: Int?,
                datasetBaseURL: URL? = nil, dohServerURL: URL? = nil,
                pirServerURL: URL? = nil,
                pirPrivacyPassIssuerURL: URL? = nil,
                issues: [String] = []) {
        self.controlPlaneBaseURL = controlPlaneBaseURL
        self.datasetBaseURL = datasetBaseURL
        self.dohServerURL = dohServerURL
        self.pirServerURL = pirServerURL
        self.pirPrivacyPassIssuerURL = pirPrivacyPassIssuerURL
        self.deviceID = deviceID
        self.issues = issues
    }

    /// Read the managed configuration pushed by MDM. Every supplied
    /// value is validated; invalid values are dropped (never used)
    /// and named in `issues`.
    public static func managed(defaults: UserDefaults = .standard) -> AppConfiguration {
        let managed = defaults.dictionary(forKey: suite) ?? [:]
        var issues: [String] = []

        func secureURL(_ key: String, required: Bool) -> URL? {
            guard let raw = managed[key] else {
                if required { issues.append("\(key) is missing") }
                return nil
            }
            guard let string = raw as? String,
                  let url = URL(string: string) else {
                issues.append("\(key) is not a valid URL")
                return nil
            }
            // Credentials must never be sent to plaintext or
            // malformed origins.
            guard url.scheme?.lowercased() == "https",
                  url.host != nil, url.user == nil,
                  url.password == nil else {
                issues.append("\(key) must be a plain https:// URL")
                return nil
            }
            return url
        }

        let controlPlane = secureURL("controlPlaneBaseURL", required: true)
        let dataset = secureURL("datasetBaseURL", required: true)
        let doh = secureURL("dohServerURL", required: false)
        // The PIR pair is jointly optional: exactly one present is a
        // configuration error (surfaced in issues, both dropped).
        var pir = secureURL("pirServerURL", required: false)
        var issuer = secureURL("pirPrivacyPassIssuerURL", required: false)
        if (pir == nil) != (issuer == nil) {
            issues.append(
                "pirServerURL and pirPrivacyPassIssuerURL must both be set")
            pir = nil
            issuer = nil
        }

        // deviceID: accept a real integer or a digit string (some MDM
        // consoles only push strings); reject bools, fractions and
        // non-positives.
        let deviceID: Int?
        switch managed["deviceID"] {
        case let number as NSNumber:
            // UserDefaults stores booleans as NSNumber too; a bool is
            // never a device id. Bool numbers carry objCType "c" on
            // both Apple platforms and swift-corelibs-foundation; a
            // genuine one-byte id is indistinguishable and also
            // rejected, which is safe: device ids are server-assigned
            // row ids, never booleans.
            if String(cString: number.objCType) == "c" {
                issues.append("deviceID must be a positive integer")
                deviceID = nil
                break
            }
            let value = number.intValue
            if Double(value) == number.doubleValue, value > 0 {
                deviceID = value
            } else {
                issues.append("deviceID must be a positive integer")
                deviceID = nil
            }
        case let string as String:
            if let value = Int(string), value > 0 {
                deviceID = value
            } else {
                issues.append("deviceID must be a positive integer")
                deviceID = nil
            }
        case .none:
            issues.append("deviceID is missing")
            deviceID = nil
        case .some:
            issues.append("deviceID must be a positive integer")
            deviceID = nil
        }

        return AppConfiguration(controlPlaneBaseURL: controlPlane,
                                deviceID: deviceID,
                                datasetBaseURL: dataset,
                                dohServerURL: doh,
                                pirServerURL: pir,
                                pirPrivacyPassIssuerURL: issuer,
                                issues: issues)
    }
}
