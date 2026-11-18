// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The app-group
// container resolution is Darwin-only and UNVERIFIED on device - see
// ios/README.md.
import Foundation

/// Personal-lane (unsupervised iPhone) configuration.
///
/// The managed lane's configuration arrives through MDM
/// (com.apple.configuration.managed). A personal iPhone has no MDM, so
/// the guardian sets the device up inside the app: server address,
/// sign-in, service discovery (ClientConfigClient) and idempotent
/// device registration (PersonalRegistrationClient) produce THIS
/// record, persisted in the shared app-group store directory.
///
/// Once persisted, the record feeds the SAME lifecycle the managed
/// lane uses: AppConfiguration.current(managed:personal:) resolves it
/// into an AppConfiguration, SignInCoordinator.applyConfiguration
/// adopts it into the shared store (authority rotation + identity
/// clear atomic with the mirror write), and every sync/prefilter
/// artifact stays bound to its endpoint fingerprint exactly as before.
///
/// PRECEDENCE: a complete managed configuration always
/// wins over the personal record (a device that later comes under MDM
/// follows its MDM identity; the adoption path clears the personal
/// identity's data). An absent or incomplete managed configuration
/// falls back to the personal record.
public struct PersonalConfiguration: Codable, Equatable {
    public let controlPlaneBaseURL: URL
    public let datasetBaseURL: URL?
    public let dohServerURL: URL?
    public let pirServerURL: URL?
    public let pirPrivacyPassIssuerURL: URL?
    public let deviceID: Int
    /// The idempotency key the device registered with ("kg-" + 32
    /// hex). Treated as a device-secret: never logged, never sent
    /// anywhere but the owning control plane's registration endpoint.
    public let registrationKey: String
    public let deviceName: String

    public init(controlPlaneBaseURL: URL, datasetBaseURL: URL?,
                dohServerURL: URL?, pirServerURL: URL?,
                pirPrivacyPassIssuerURL: URL?, deviceID: Int,
                registrationKey: String, deviceName: String) {
        self.controlPlaneBaseURL = controlPlaneBaseURL
        self.datasetBaseURL = datasetBaseURL
        self.dohServerURL = dohServerURL
        self.pirServerURL = pirServerURL
        self.pirPrivacyPassIssuerURL = pirPrivacyPassIssuerURL
        self.deviceID = deviceID
        self.registrationKey = registrationKey
        self.deviceName = deviceName
    }

    /// The AppConfiguration view of this record. `issues` is empty:
    /// every value was validated at setup time. A missing dataset /
    /// PIR endpoint stays nil and the corresponding feature reports
    /// itself unavailable downstream - never substituted.
    public func appConfiguration() -> AppConfiguration {
        AppConfiguration(controlPlaneBaseURL: controlPlaneBaseURL,
                         deviceID: deviceID,
                         datasetBaseURL: datasetBaseURL,
                         dohServerURL: dohServerURL,
                         pirServerURL: pirServerURL,
                         pirPrivacyPassIssuerURL: pirPrivacyPassIssuerURL,
                         issues: [])
    }

    /// Validation shared by the setup form and the discovery client:
    /// a plain https URL with a host and no credentials, query or
    /// fragment. Anything else is refused (credentials must never be
    /// sent to a plaintext or credential-embedding origin).
    public static func validatedHTTPSURL(_ raw: String) -> URL? {
        guard let url = URL(string: raw),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil
        else { return nil }
        return url
    }

    /// PIR server / Privacy Pass issuer URLs are stricter: Apple's
    /// NSPIRConfiguration matches the static Info.plist declaration
    /// BY HOST, so a path would be silently meaningless and can
    /// diverge from the declared endpoint. Only https://host[:port]
    /// validates.
    public static func validatedHostOnlyHTTPSURL(_ raw: String)
        -> URL? {
        guard let url = validatedHTTPSURL(raw),
              url.path.isEmpty || url.path == "/"
        else { return nil }
        return url
    }
}

public extension AppConfiguration {
    /// The effective configuration for this device. A MANAGED
    /// configuration that carries the sync-required keys (control
    /// plane, dataset, device id) always wins - a supervised/managed
    /// device follows its MDM identity. Otherwise the personal-lane
    /// record applies. With neither, the managed read is returned
    /// as-is so its per-key `issues` explain what is missing.
    static func current(managed: AppConfiguration,
                        personal: PersonalConfiguration?)
        -> AppConfiguration {
        let managedComplete = managed.controlPlaneBaseURL != nil
            && managed.datasetBaseURL != nil
            && managed.deviceID != nil
        if managedComplete { return managed }
        if let personal { return personal.appConfiguration() }
        return managed
    }
}

/// File persistence for the personal record, in the SAME directory the
/// shared FilterRuleStore uses (the app-group container on device), so
/// setup state and the rule store share one lifecycle home. Atomic
/// writes; a corrupt file reads as absent (setup re-runs), never as a
/// partial configuration.
public struct PersonalConfigurationStore {
    public let file: URL

    public init(directory: URL) {
        self.file = directory.appendingPathComponent(
            "personal-configuration.json")
    }

    #if canImport(Darwin)
    /// The store in the shared app-group container, or nil when the
    /// container is unavailable (entitlement not active): the honest
    /// "persistence unavailable" state, never a silent private
    /// fallback the extensions cannot see.
    public static func shared(
        fileManager: FileManager = .default)
        -> PersonalConfigurationStore? {
        guard let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier:
                FilterRuleStore.appGroupIdentifier)
        else { return nil }
        return PersonalConfigurationStore(directory: container)
    }
    #endif

    public func load() -> PersonalConfiguration? {
        guard let data = FileManager.default.contents(atPath: file.path)
        else { return nil }
        return try? JSONDecoder().decode(PersonalConfiguration.self,
                                         from: data)
    }

    public func save(_ configuration: PersonalConfiguration) throws {
        try FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        options.insert(.completeFileProtectionUntilFirstUserAuthentication)
        #endif
        try JSONEncoder().encode(configuration).write(to: file,
                                                      options: options)
    }

    public func clear() throws {
        if FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.removeItem(at: file)
        }
    }
}

/// The per-install registration identity (key + display name),
/// persisted SEPARATELY from the completed configuration so a failed
/// or interrupted setup retries with the SAME registration key - the
/// server then returns the same device row instead of accumulating
/// duplicates. Generated once per install.
public struct PendingRegistration: Codable, Equatable {
    public let registrationKey: String
    public let deviceName: String
}

public extension PersonalConfigurationStore {
    private var pendingFile: URL {
        file.deletingLastPathComponent()
            .appendingPathComponent("pending-registration.json")
    }

    /// The existing pending identity, or a freshly generated one.
    /// The key is "kg-" + 32 lowercase hex chars (UUID without
    /// dashes); the name embeds enough of the key to stay unique per
    /// install without leaking the whole key into device lists.
    func loadOrCreatePendingRegistration() throws -> PendingRegistration {
        if let data = FileManager.default.contents(
            atPath: pendingFile.path),
           let pending = try? JSONDecoder().decode(
               PendingRegistration.self, from: data),
           pending.registrationKey.hasPrefix("kg-"),
           pending.registrationKey.count == 35,
           !pending.deviceName.isEmpty {
            return pending
        }
        let key = "kg-" + UUID().uuidString.replacingOccurrences(
            of: "-", with: "").lowercased()
        let suffix = String(key.suffix(6))
        let pending = PendingRegistration(
            registrationKey: key,
            deviceName: "Personal device (\(suffix))")
        try FileManager.default.createDirectory(
            at: pendingFile.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        options.insert(.completeFileProtectionUntilFirstUserAuthentication)
        #endif
        try JSONEncoder().encode(pending).write(to: pendingFile,
                                                options: options)
        return pending
    }

    /// A name conflict means another device in the family already
    /// holds the auto-generated display name. Recovery keeps the SAME
    /// registration key (idempotency ownership is keyed by it, never
    /// by name) and only picks a fresh unique-looking suffix, so a
    /// retry cannot create a second device row and never dead-ends on
    /// an uneditable name.
    func regeneratePendingName() throws -> PendingRegistration {
        guard let data = FileManager.default.contents(
            atPath: pendingFile.path),
           var pending = try? JSONDecoder().decode(
               PendingRegistration.self, from: data)
        else {
            // Nothing pending: create a fresh identity wholesale.
            return try loadOrCreatePendingRegistration()
        }
        let suffix = String(UUID().uuidString.replacingOccurrences(
            of: "-", with: "").lowercased().prefix(6))
        pending = PendingRegistration(
            registrationKey: pending.registrationKey,
            deviceName: "Personal device (\(suffix))")
        var options: Data.WritingOptions = [.atomic]
        #if canImport(Darwin)
        options.insert(.completeFileProtectionUntilFirstUserAuthentication)
        #endif
        try JSONEncoder().encode(pending).write(to: pendingFile,
                                                options: options)
        return pending
    }

    /// Setup completed or was explicitly torn down: the pending
    /// identity has served its purpose (the completed configuration
    /// carries the key from here on).
    func clearPendingRegistration() throws {
        if FileManager.default.fileExists(atPath: pendingFile.path) {
            try FileManager.default.removeItem(at: pendingFile)
        }
    }
}
