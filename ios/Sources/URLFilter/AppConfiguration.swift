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
struct AppConfiguration {
    let controlPlaneBaseURL: URL?
    let deviceID: Int?

    private static let suite = "com.apple.configuration.managed"

    /// Read the managed configuration pushed by MDM. Both keys are
    /// required for the credential flow; anything missing yields nil
    /// for that key and the caller reports "not configured".
    static func managed(
        defaults: UserDefaults = UserDefaults(
            suiteName: "com.apple.configuration.managed") ?? .standard
    ) -> AppConfiguration {
        let urlString = defaults.string(forKey: "controlPlaneBaseURL")
        return AppConfiguration(
            controlPlaneBaseURL: urlString.flatMap(URL.init(string:)),
            deviceID: defaults.object(forKey: "deviceID") as? Int)
    }
}
