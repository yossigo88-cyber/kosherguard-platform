// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import SwiftUI
#if canImport(URLFilter)
import URLFilter
#endif

/// Guardian-facing status: what the filter is doing on THIS device,
/// stated honestly. "Protection active" requires an actually-running
/// extension; a configured-but-not-running filter is not protection.
struct FilterStatus: Equatable {
    enum ExtensionState: String {
        case notInstalled = "Not installed"
        case enabled = "Enabled"
        case running = "Running"
        case failed = "Failed"
    }

    var extensionState: ExtensionState
    var prefilterVersion: Int?
    var enrollmentState: String

    var protectionSummary: String {
        switch extensionState {
        case .running:
            return "Filtering is active for WebKit and URLSession traffic."
        case .enabled:
            return "Filter is enabled but not running yet."
        case .notInstalled:
            return "Filtering is not installed on this device."
        case .failed:
            return "The filter failed. Re-enroll or contact support."
        }
    }
}

/// Call site for the scoped-credential request path: sign in natively
/// (AuthSessionClient), mint a scoped credential
/// (CredentialIssuanceClient), store both in the Keychain
/// (KeychainCredentialStore), clear them on sign-out or a 401 (a dead
/// session must not linger as a stored credential). Server URL and
/// device ID come from MDM-managed App Configuration
/// (AppConfiguration) - the real configuration mechanism, not a
/// baked-in URL. UNCOMPILED/UNSIGNED/UNTESTED: never run.
@Observable
final class CredentialController {
    enum State: String {
        case notConfigured = "Not configured by MDM"
        case signedOut = "Not signed in"
        case signingIn = "Signing in"
        case issuing = "Requesting device credential"
        case issued = "Device credential issued"
        case failed = "Failed"
    }
    private(set) var state: State = .notConfigured
    private(set) var lastError: String?

    private var auth: AuthSessionClient?
    private var issuance: CredentialIssuanceClient?
    private let store: KeychainCredentialStore
    private var deviceID: Int?
    private var configObserver: NSObjectProtocol?
    private var configurationOrigin: String?
    /// THE one lifecycle owner (portable-tested): sign-in, sign-out
    /// and managed-configuration adoption/invalidation are all
    /// serialized through this single actor, shared by every view
    /// model, so no observer can independently adopt or delete
    /// outside the authority lock. STORED (a computed property would
    /// create a fresh actor per access and silently break both the
    /// in-flight exclusivity and the single-owner guarantee).
    static let lifecycle = SignInCoordinator(
        ruleStore: FilterRuleStore.appGroupStore(),
        vault: KeychainCredentialStore(
            accessGroup: KeychainCredentialStore.sharedAccessGroup),
        // The CURRENT source of truth: every lifecycle task re-reads
        // the managed configuration at execution time, so rapid
        // A -> B pushes coalesce to the latest source.
        configurationSource: { AppConfiguration.managed() })
    private var coordinator: SignInCoordinator { Self.lifecycle }

    /// The endpoint fingerprint of a configuration: the identity the
    /// stored credentials are bound to (origin hosts + device id).
    private static func origin(of configuration: AppConfiguration)
        -> String? {
        guard let control = configuration.controlPlaneBaseURL,
              let dataset = configuration.datasetBaseURL,
              let deviceID = configuration.deviceID
        else { return nil }
        return FilterRuleStore.configFingerprint(
            controlPlane: control, dataset: dataset,
            doh: configuration.dohServerURL,
            tenantID: 0, deviceID: deviceID)
    }

    init(store: KeychainCredentialStore = KeychainCredentialStore(accessGroup: KeychainCredentialStore.sharedAccessGroup),
         configuration: AppConfiguration = .managed()) {
        self.store = store
        configureClients(configuration)
        // MDM can push a new managed configuration at any time:
        // rebuild the clients so the sign-in form can NEVER send
        // credentials to the OLD server/device, and drop the stored
        // origin-bound credentials (they belong to the old origin).
        configObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            self?.reconfigure(AppConfiguration.managed())
        }
    }

    private var latestConfiguration: AppConfiguration = .managed()

    private func configureClients(_ configuration: AppConfiguration) {
        latestConfiguration = configuration
        configurationOrigin = Self.origin(of: configuration)
        if let baseURL = configuration.controlPlaneBaseURL,
           let deviceID = configuration.deviceID {
            self.auth = AuthSessionClient(baseURL: baseURL,
                                          session: .shared)
            self.issuance = CredentialIssuanceClient(baseURL: baseURL,
                                                     session: .shared)
            self.deviceID = deviceID
            self.state = .signedOut
        } else {
            self.auth = nil
            self.issuance = nil
            self.deviceID = nil
            self.state = .notConfigured
        }
    }

    /// Managed-configuration change: rebuild clients against the NEW
    /// origin and clear the stored credentials atomically with the
    /// rule store's epoch (the store adoption happens in
    /// FilterSyncViewModel.configure). No password is ever sent to an
    /// origin other than the currently configured one, and no token
    /// is reused across identities.
    func reconfigure(_ configuration: AppConfiguration) {
        let newOrigin = Self.origin(of: configuration)
        guard newOrigin != configurationOrigin else { return }
        // ONE lifecycle owner: adoption/invalidation AND credential
        // teardown run serialized through the shared actor - no
        /// independent deletes outside the authority lock.
        Task {
            // Reads the CURRENT managed configuration at execution
            // time; a queued task for a superseded push coalesces.
            try? await Self.lifecycle.applyCurrentConfiguration()
        }
        lastError = nil
        configureClients(configuration)
    }

    /// Reachable user action: the sign-in form calls this. Full flow:
    /// sign in -> mint a dataset-scoped credential for this device ->
    /// persist both in the Keychain. Dataset scope is the only scope
    /// useful to the app today (prefilter updates); doh stays refused
    /// until the held server change lands.
    func signInAndIssue(email: String, password: String,
                        totpCode: String?) async {
        // Orchestration lives in SignInCoordinator (portable, XCTested
        // with delayed fakes): exclusive in-flight, non-null attempt
        // token, per-await authority checks, conditional session
        // rotation, and a single atomic credential-bundle write -
        // two concurrent attempts can never interleave into a mixed
        // session/dataset state.
        guard let auth, let issuance, let deviceID,
              let origin = configurationOrigin
        else { return }
        struct AuthAdapter: SessionSigningIn {
            let client: AuthSessionClient
            func signIn(email: String, password: String,
                        totpCode: String?) async throws -> String {
                try await client.signIn(.init(
                    email: email, password: password,
                    totpCode: totpCode))
            }
        }
        struct IssuanceAdapter: DatasetCredentialIssuing {
            let client: CredentialIssuanceClient
            func mintDatasetCredential(deviceID: Int,
                                       sessionCookie: String)
                async throws -> String {
                do {
                    return try await client.mint(
                        deviceID: deviceID, scope: .dataset,
                        sessionCookie: sessionCookie).token
                } catch CredentialIssuanceClient.IssuanceError
                    .unauthorized {
                    throw SignInCoordinator.SignInError.sessionRejected
                }
            }
        }
        state = .signingIn
        do {
            try await coordinator.signInAndIssue(
                configuration: latestConfiguration,
                email: email, password: password, totpCode: totpCode,
                deviceID: deviceID, origin: origin,
                auth: AuthAdapter(client: auth),
                issuance: IssuanceAdapter(client: issuance),
                currentOrigin: { [weak self] in
                    self?.configurationOrigin
                })
            state = .issued
        } catch SignInCoordinator.SignInError.alreadyInProgress {
            lastError = "Sign-in already in progress."
        } catch SignInCoordinator.SignInError.storeNotReady {
            lastError = "Rule store not ready for sign-in; "
                + "re-apply the managed configuration."
            state = .failed
        } catch SignInCoordinator.SignInError.staleAttempt {
            lastError = "Configuration changed during sign-in; "
                + "try again."
            state = .failed
        } catch SignInCoordinator.SignInError.sessionRejected {
            lastError = "Session rejected; sign in again."
            state = .failed
        } catch {
            lastError = String(describing: error)
            state = .failed
        }
    }

    /// Sign out: LOCAL invalidation FIRST, server notification LAST.
    /// The device stops presenting credentials immediately - the
    /// server call is best-effort and must never delay, block or
    /// gate local teardown (a network hang must not keep a
    /// signed-out device's credentials live).
    func signOut() async {
        struct AuthSignOutAdapter: SessionSigningOut {
            let client: AuthSessionClient
            func signOut(sessionCookie: String) async throws {
                try await client.signOut(sessionCookie: sessionCookie)
            }
        }
        // Capture the client AND the origin it is bound to BEFORE
        // the await: configureClients replaces both together, and a
        // managed-config change during the await can swap self.auth
        // for a client bound to a NEW server - the old session
        // cookie must NEVER be sent there. The coordinator compares
        // the captured origin against the bundle's session origin
        // and omits the remote logout unless they provably match.
        let boundClient = auth
        let boundOrigin = configurationOrigin
        // ONE lifecycle owner: local teardown first (bundle, store
        // clear, in-lock prefilter removal), remote logout last,
        // strict and serialized with sign-in/config changes.
        do {
            try await Self.lifecycle.signOut(
                remoteLogout: boundClient.map(AuthSignOutAdapter.init),
                boundToOrigin: boundOrigin)
        } catch {
            lastError = "Sign-out cleanup incomplete: \(error)"
        }
        state = auth == nil ? .notConfigured : .signedOut
    }
}

/// Reachable user action for filter-data sync: reads MDM-managed
/// configuration, the Keychain-stored session/credential, pulls the
/// guardian's explicit rules (FilterRulesClient) into the shared
/// app-group FilterRuleStore the extension reads, and the Bloom
/// prefilter (PrefilterUpdater) into the app-group snapshot file.
/// Every outcome - including "not configured by MDM" and "sign in
/// first" - is a visible state, never a silent no-op.
/// UNCOMPILED/UNSIGNED/UNTESTED: never run.
@Observable
final class FilterSyncViewModel {
    private(set) var stateDescription: String = "Not synced yet"
    private(set) var canSync = false
    private var controller: FilterSyncController?
    private var configObserver: NSObjectProtocol?

    init() {
        // Re-read the managed configuration when MDM changes it
        // (UserDefaults.didChangeNotification is the supported
        // observation point; the controller's init mirrors the new
        // configuration and fails closed on endpoint/identity
        // changes). UNVERIFIED on device - no iOS build exists.
        configObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification,
            object: nil, queue: .main
        ) { [weak self] _ in self?.configure() }
        configure()
    }

    private func configure() {
        let store = FilterRuleStore.appGroupStore()
        // CURRENT-SOURCE ORDERING: the lifecycle adoption runs FIRST
        // (the shared actor re-reads the managed configuration at
        // execution time, coalescing rapid A -> B pushes); the
        // controller is built only AFTER it settles, from the managed
        // configuration re-read at that moment - NEVER from a copy
        // captured before the await.
        Task {
            if let store {
                // ONE lifecycle owner (shared actor): adoption /
                // invalidation AND credential teardown are serialized
                // with sign-in/sign-out - no independent deletes or
                // adopts outside the authority lock.
                do {
                    switch try await CredentialController.lifecycle
                        .applyCurrentConfiguration() {
                    case .invalidated:
                        store.recordStatus("rules cleared: managed "
                            + "configuration invalid or removed")
                    case .adopted:
                        store.recordStatus("rules cleared: "
                            + "configuration changed")
                    case .alreadyCurrent:
                        break
                    }
                } catch {
                    store.recordStatus("configuration lifecycle "
                        + "failed: \(error)")
                }
            }
            let confirmed = AppConfiguration.managed()
            // URL FILTER (iOS 26+): enable/disable follows the
            // CURRENT managed configuration, re-read after the
            // lifecycle settles - never a captured copy. Missing PIR
            // keys simply leave the URL Filter off; the NEFilter
            // explicit-rule path is unaffected. A removed/invalid
            // configuration disables it explicitly (fail closed).
            if #available(iOS 26.0, *) {
                do {
                    if confirmed.pirServerURL != nil,
                       confirmed.pirPrivacyPassIssuerURL != nil {
                        try await URLFilterConfiguration.enable(
                            from: confirmed)
                    } else {
                        try await URLFilterConfiguration.disableFilter()
                    }
                } catch {
                    store?.recordStatus("URL Filter configuration "
                        + "failed: \(error)")
                }
            }
            await MainActor.run {
                self.rebuildController(configuration: confirmed,
                                       store: store)
            }
        }
    }

    private func rebuildController(configuration: AppConfiguration,
                                   store: FilterRuleStore?) {
        let controller = FilterSyncController(
            configuration: configuration,
            credentials: KeychainCredentialStore(accessGroup: KeychainCredentialStore.sharedAccessGroup),
            session: .shared,
            ruleStore: store,
            prefilterFile: store?.snapshotFile
                .deletingLastPathComponent()
                .appendingPathComponent("prefilter-snapshot.json"))
        controller.onStateChange = { [weak self] state in
            DispatchQueue.main.async { self?.apply(state) }
        }
        self.controller = controller
        apply(controller.state)
        // Surface the store's own status sidecar (cleared-on-401,
        // identity change, no effective policy): the sync state alone
        // never shows why the extension currently has no rules.
        if let note = store?.readStatus()?["state"], !note.isEmpty {
            stateDescription += " Store: \(note)."
        }
        if case .notConfigured = controller.state {
            canSync = false
        } else {
            canSync = true
        }
        // Pull-based app policy mirror (Stage 10): refresh the
        // device-local copy of the control plane's application
        // policy, bound to the current endpoint identity. On the
        // supervised route the MDM profile is the enforcement; this
        // mirror feeds the personally-owned route's visibility and
        // future shield application. A fetch failure changes nothing
        // (fail safe: the last good policy stays).
        if let baseURL = configuration.controlPlaneBaseURL,
           let deviceID = configuration.deviceID,
           let store {
            let keychain = KeychainCredentialStore(
                accessGroup: KeychainCredentialStore.sharedAccessGroup)
            let fingerprint = FilterSyncController.bootstrap(
                for: configuration, tenantID: nil)?.endpointFingerprint
                ?? ""
            let policyFile = store.snapshotFile
                .deletingLastPathComponent()
                .appendingPathComponent("app-policy.json")
            Task {
                guard let cookie = CredentialBundle.load(
                    from: keychain)?.session, !cookie.isEmpty,
                    !fingerprint.isEmpty
                else { return }
                if let policy = try? await AppBlockingPolicyClient(
                    baseURL: baseURL).fetch(
                        deviceID: deviceID,
                        sessionCookie: cookie) {
                    try? AppBlockingPolicyStore(snapshotFile: policyFile)
                        .save(policy,
                              endpointFingerprint: fingerprint)
                }
            }
        }
    }

    private func apply(_ state: FilterSyncController.State) {
        switch state {
        case .notConfigured(let problem):
            stateDescription = "Not configured: \(problem)"
        case .signedOut:
            stateDescription = "Sign in first (device credential section)."
        case .ready:
            stateDescription = "Ready to sync."
        case .syncing:
            stateDescription = "Syncing filter data"
        case .synced(let prefilter, let rules):
            let prefilterText = prefilter.map { "prefilter v\($0)" } ?? "prefilter current"
            let rulesText = rules.map { "rules generation \($0)" } ?? "no explicit rules"
            stateDescription = "Synced: \(prefilterText), \(rulesText)."
        case .persistenceUnavailable(let detail):
            stateDescription = "Sync could not save: \(detail)"
        case .invalidated(let reason):
            stateDescription = "Filtering data cleared: \(reason)."
        case .failed(let reason):
            stateDescription = "Sync failed: \(reason)"
        }
    }

    func syncNow() {
        guard let controller else { return }
        Task { await controller.syncNow() }
    }
}

@main
struct KosherGuardApp: App {
    @State private var credentials = CredentialController()
    @State private var sync = FilterSyncViewModel()

    var body: some Scene {
        WindowGroup {
            FilterStatusView()
                .environment(credentials)
                .environment(sync)
        }
    }
}

struct FilterStatusView: View {
    @Environment(CredentialController.self) private var credentials
    @Environment(FilterSyncViewModel.self) private var sync
    @State private var status = FilterStatus(
        extensionState: .notInstalled,
        prefilterVersion: nil,
        enrollmentState: "Not enrolled")

    var body: some View {
        NavigationStack {
            List {
                Section("Protection") {
                    LabeledContent("Filter",
                                   value: status.extensionState.rawValue)
                    Text(status.protectionSummary)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section("URL database") {
                    LabeledContent(
                        "Prefilter version",
                        value: status.prefilterVersion.map(String.init)
                            ?? "none")
                }
                Section("Management") {
                    LabeledContent("Enrollment",
                                   value: status.enrollmentState)
                    LabeledContent("Device credential",
                                   value: credentials.state.rawValue)
                }
                Section("Filter data") {
                    Text(sync.stateDescription)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button("Sync filter data now") { sync.syncNow() }
                        .disabled(!sync.canSync)
                }
                Section("Device credential sign-in") {
                    CredentialSignInView()
                }
            }
            .navigationTitle("KosherGuard")
        }
    }
}

/// The reachable user action for the credential flow. Disabled with
/// an explanation when MDM has not supplied a server configuration.
struct CredentialSignInView: View {
    @Environment(CredentialController.self) private var credentials
    @State private var email = ""
    @State private var password = ""
    @State private var totpCode = ""

    var body: some View {
        if case .notConfigured = credentials.state {
            Text("This device has no MDM-supplied server configuration.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            TextField("Email", text: $email)
                .textContentType(.emailAddress)
                .keyboardType(.emailAddress)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            SecureField("Password", text: $password)
            TextField("Authenticator code (if enabled)", text: $totpCode)
                .keyboardType(.numberPad)
            Button("Sign in and request credential") {
                Task {
                    await credentials.signInAndIssue(
                        email: email, password: password,
                        totpCode: totpCode.isEmpty ? nil : totpCode)
                }
            }
            .disabled(email.isEmpty || password.isEmpty)
            if let error = credentials.lastError {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
        }
    }
}

#Preview {
    FilterStatusView()
        .environment(CredentialController())
}
