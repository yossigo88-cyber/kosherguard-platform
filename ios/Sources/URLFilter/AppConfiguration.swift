// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation

/// Server configuration supplied by MDM-managed App Configuration
/// (the standard `com.apple.configuration.managed` UserDefaults
/// suite a supervised device's MDM server pushes). This is the real
/// configuration mechanism for the platform - the same MDM channel
/// that enrolls the device supplies where its control plane is and
/// which device record it owns. No live server URL or secret is
/// baked into the build; without managed configuration the app is
/// honestly "not configured".
public struct AppConfiguration {
    public let controlPlaneBaseURL: URL?
    public let deviceID: Int?

    private static let suite = "com.apple.configuration.managed"

    /// Read the managed configuration pushed by MDM. Both keys are
    /// required for the credential flow; anything missing yields nil
    /// for that key and the caller reports "not configured".
    public init(controlPlaneBaseURL: URL?, deviceID: Int?) {
        self.controlPlaneBaseURL = controlPlaneBaseURL
        self.deviceID = deviceID
    }

    public static func managed(defaults: UserDefaults = .standard) -> AppConfiguration {
        let managed = defaults.dictionary(forKey: suite) ?? [:]
        let url = (managed["controlPlaneBaseURL"] as? String).flatMap(URL.init(string:))
        // Credentials must never be sent to plaintext or malformed origins.
        let secureURL = url.flatMap { candidate -> URL? in
            guard candidate.scheme?.lowercased() == "https",
                  candidate.host != nil, candidate.user == nil,
                  candidate.password == nil else { return nil }
            return candidate
        }
        let id = managed["deviceID"] as? Int
        return AppConfiguration(controlPlaneBaseURL: secureURL,
                                deviceID: id.flatMap { $0 > 0 ? $0 : nil })
    }
}
