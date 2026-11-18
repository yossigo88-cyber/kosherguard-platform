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

extension AppConfiguration {
    /// The effective configuration on THIS device: the MDM-managed
    /// configuration when it is complete (supervised/managed lane),
    /// otherwise the personal-lane record the in-app setup persisted
    /// (unsupervised lane), otherwise the managed read with its
    /// per-key issues. Apple-only: the personal store resolves the
    /// app-group container, which does not exist in the portable
    /// build.
    static func currentOnDevice(
        defaults: UserDefaults = .standard) -> AppConfiguration {
        AppConfiguration.current(
            managed: managed(defaults: defaults),
            personal: PersonalConfigurationStore.shared()?.load())
    }
}

/// Call site for the scoped-credential request path: sign in natively
/// (AuthSessionClient), mint a scoped credential
/// (CredentialIssuanceClient), store both in the Keychain
/// (KeychainCredentialStore), clear them on sign-out or a 401 (a dead
/// session must not linger as a stored credential). Server URL and
/// device ID come from the effective configuration
/// (AppConfiguration.currentOnDevice: MDM-managed configuration, or
/// the personal-lane setup record on an unsupervised device) - never
/// a baked-in URL. UNCOMPILED/UNSIGNED/UNTESTED: never run.
@Observable
final class CredentialController {
    enum State: String {
        case notConfigured = "Not set up"
        case signedOut = "Not signed in"
        case signingIn = "Signing in"
        case issuing = "Requesting device credential"
        case issued = "Device credential issued"
        case failed = "Failed"
    }
    private(set) var state: State = .notConfigured
    private(set) var lastError: String?
    /// Wired by the app shell so sign-out resets observers that hold
    /// identity-derived state (the remote shield gate) immediately.
    /// UI-facing notification only; the coordinator owns teardown.
    var onIdentityTeardown: (() -> Void)?

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
        // the effective configuration (managed OR personal-lane) at
        // execution time, so rapid A -> B changes coalesce to the
        // latest source.
        configurationSource: { AppConfiguration.currentOnDevice() })
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
         configuration: AppConfiguration = .currentOnDevice()) {
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
            self?.reconfigure(AppConfiguration.currentOnDevice())
        }
    }

    private var latestConfiguration: AppConfiguration =
        .currentOnDevice()

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
        // The identity teardown deleted the app-policy mirror under
        // the store lock; observers re-evaluate the shield gate
        // immediately (unknown gate = purely local behavior).
        onIdentityTeardown?()
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
    /// URL Filter enablement as last attempted by this process:
    /// honest to what the app DID, not to system state it cannot
    /// observe without device APIs. Starts at notInstalled; a
    /// successful enable() moves it to enabled, a successful disable
    /// or a configuration without the PIR pair moves it back.
    private(set) var urlFilterState: FilterStatus.ExtensionState =
        .notInstalled
    /// Bumped after every successful app-policy mirror save. The
    /// app-blocking section observes this and re-evaluates the remote
    /// shield gate (including re-checking Screen Time authorization)
    /// on every completed policy sync.
    private(set) var appPolicyGeneration = 0
    private var controller: FilterSyncController?

    /// Re-run configuration discovery (managed re-read, lifecycle
    /// adoption, URL Filter enable/disable, controller rebuild) after
    /// an event the UserDefaults observer cannot see - the personal
    /// lane persists its configuration as a FILE, not a defaults
    /// entry, so setup completion calls this explicitly.
    func reconfigureNow() {
        configure()
    }

    /// Sign-out/identity-teardown hook (wired from
    /// CredentialController): the mirrored app policy - including
    /// the remote shield gate - is deleted with the identity, and
    /// the app-blocking section must re-evaluate NOW, not at the
    /// next app restart.
    func noteIdentityTeardown() {
        Task { @MainActor [weak self] in
            self?.appPolicyGeneration += 1
        }
    }

    /// Explicit user control (the Protection section toggle): the
    /// guardian turns the URL Filter on or off on THIS device. On
    /// goes through the same gates as automatic configuration
    /// (PIR pair present, endpoints deployable per PIREndpointPolicy,
    /// plist match inside enable()); off is always allowed and never
    /// revalidates endpoints (fail-closed path). Every outcome ends
    /// in a SYSTEM readback so the shown state is the manager's own.
    func setURLFilterEnabled(_ enabled: Bool) {
        guard #available(iOS 26.0, *) else { return }
        let store = FilterRuleStore.appGroupStore()
        Task {
            do {
                if enabled {
                    let confirmed = AppConfiguration.currentOnDevice()
                    guard let pirServer = confirmed.pirServerURL,
                          let issuer =
                              confirmed.pirPrivacyPassIssuerURL
                    else {
                        store?.recordStatus("URL Filter not enabled: "
                            + "PIR endpoints not configured")
                        await MainActor.run {
                            self.urlFilterState = .notInstalled
                        }
                        return
                    }
                    if let problem =
                        PIREndpointPolicy.deploymentProblem(
                            pirServer: pirServer, issuer: issuer) {
                        try await URLFilterConfiguration.disableFilter()
                        store?.recordStatus("URL Filter off: PIR "
                            + "endpoints not deployed (" + problem
                            + ")")
                        await MainActor.run {
                            self.urlFilterState = .notInstalled
                        }
                        return
                    }
                    try await URLFilterConfiguration.enable(
                        from: confirmed)
                } else {
                    try await URLFilterConfiguration.disableFilter()
                }
            } catch {
                store?.recordStatus("URL Filter "
                    + (enabled ? "enable" : "disable")
                    + " failed: \(error)")
                await MainActor.run { self.urlFilterState = .failed }
            }
            await self.refreshURLFilterSystemStatus()
        }
    }

    /// Re-read the SYSTEM's URL Filter state and reflect it in the
    /// UI: urlFilterState follows the manager's own isEnabled/Status
    /// when the readback succeeds (running finally means the system
    /// says running), falling back to the last attempted outcome.
    func refreshURLFilterSystemStatus() async {
        guard #available(iOS 26.0, *) else { return }
        let readback = await URLFilterConfiguration.readSystemStatus()
        await MainActor.run {
            self.systemReadback = readback.summary
            switch (readback.isEnabled, readback.status) {
            case (true, "running"):
                self.urlFilterState = .running
            case (true, _):
                if self.urlFilterState != .failed {
                    self.urlFilterState = .enabled
                }
            case (false, _):
                if self.urlFilterState != .failed {
                    self.urlFilterState = .notInstalled
                }
            }
        }
    }
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
            let confirmed = AppConfiguration.currentOnDevice()
            // URL FILTER (iOS 26+): enable/disable follows the
            // CURRENT effective configuration, re-read after the
            // lifecycle settles - never a captured copy. Missing PIR
            // keys simply leave the URL Filter off; the NEFilter
            // explicit-rule path is unaffected. A removed/invalid
            // configuration disables it explicitly (fail closed).
            // PLACEHOLDER endpoints (RFC 2606/6761 reserved names,
            // e.g. the shipped *.kosherguard.example.com stand-ins)
            // are NOT an error: the URL database service is not
            // deployed yet, so the filter is left off with an honest
            // status. Enabling would hand the system PIR lookups
            // that can never complete, which under shouldFailClosed
            // blocks ALL WebKit/URLSession traffic for no reason.
            if #available(iOS 26.0, *) {
                do {
                    if let pirServer = confirmed.pirServerURL,
                       let issuer = confirmed.pirPrivacyPassIssuerURL {
                        if let problem =
                            PIREndpointPolicy.deploymentProblem(
                                pirServer: pirServer, issuer: issuer) {
                            try await URLFilterConfiguration
                                .disableFilter()
                            store?.recordStatus("URL Filter off: "
                                + "PIR endpoints not deployed ("
                                + problem + ")")
                            await MainActor.run {
                                self.urlFilterState = .notInstalled
                            }
                        } else {
                            try await URLFilterConfiguration.enable(
                                from: confirmed)
                            await MainActor.run {
                                self.urlFilterState = .enabled
                            }
                        }
                    } else {
                        try await URLFilterConfiguration.disableFilter()
                        await MainActor.run {
                            self.urlFilterState = .notInstalled
                        }
                    }
                } catch {
                    store?.recordStatus("URL Filter configuration "
                        + "failed: \(error)")
                    await MainActor.run {
                        self.urlFilterState = .failed
                    }
                }
            }
            // Reflect the SYSTEM's own state after every automatic
            // configure pass too, so the UI never rests on what this
            // process merely attempted.
            await refreshURLFilterSystemStatus()
            await MainActor.run {
                self.rebuildController(configuration: confirmed,
                                       store: store)
                // The lifecycle may have invalidated the identity
                // (and with it the app-policy mirror): re-evaluate
                // the shield gate even when no new fetch follows.
                self.appPolicyGeneration += 1
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
        refreshAppPolicyMirror(configuration: configuration,
                               store: store)
    }

    /// Pull-based app policy mirror (Stage 10): refresh the
    /// device-local copy of the control plane's application policy,
    /// bound to the current endpoint identity. On the supervised
    /// route the MDM profile is the enforcement; on a
    /// personally-owned device the server policy CANNOT select apps
    /// (opaque device-local tokens) - the mirrored `shield_active`
    /// flag can only gate ACTIVATION of the device's own locally
    /// consented selection (see AppShieldViewModel), never choose or
    /// widen it. A fetch failure changes nothing (fail safe: the
    /// last good policy and its gate stay).
    private func refreshAppPolicyMirror(
        configuration: AppConfiguration, store: FilterRuleStore?) {
        guard let baseURL = configuration.controlPlaneBaseURL,
              let deviceID = configuration.deviceID,
              let store
        else { return }
        let keychain = KeychainCredentialStore(
            accessGroup: KeychainCredentialStore.sharedAccessGroup)
        let fingerprint = FilterSyncController.bootstrap(
            for: configuration, tenantID: nil)?.endpointFingerprint
            ?? ""
        let policyFile = store.appPolicyMirrorFile
        Task {
            guard let cookie = CredentialBundle.load(
                from: keychain)?.session, !cookie.isEmpty,
                !fingerprint.isEmpty
            else { return }
            guard let policy = try? await AppBlockingPolicyClient(
                baseURL: baseURL).fetch(
                    deviceID: deviceID,
                    sessionCookie: cookie),
               let data = try? AppBlockingPolicyStore(
                   snapshotFile: policyFile)
                    .encodedSnapshot(policy,
                                     endpointFingerprint: fingerprint)
            else { return }
            // Atomic vs sign-out/identity teardown: the store drops
            // the save when its current identity no longer matches
            // the fingerprint this policy was fetched under, so a
            // late in-flight fetch can never resurrect the old
            // identity's gate after sign-out.
            let saved = (try? store.saveAppPolicyMirrorIfCurrent(
                data, endpointFingerprint: fingerprint)) ?? false
            if saved {
                await MainActor.run { self.appPolicyGeneration += 1 }
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
        let configuration = AppConfiguration.currentOnDevice()
        let store = FilterRuleStore.appGroupStore()
        Task {
            await controller.syncNow()
            // Recheck the remote shield gate on every manual sync:
            // the mirror refresh bumps appPolicyGeneration, and the
            // observing app-blocking section re-verifies Screen Time
            // authorization before keeping the shield active.
            refreshAppPolicyMirror(configuration: configuration,
                                   store: store)
        }
    }

    /// Background-refresh entry point (BGTaskScheduler): runs the
    /// SAME tested sync path as the manual button and reports whether
    /// a sync completed, which drives the task's completion status
    /// and the failure backoff cadence. A controller in a
    /// non-syncable state (not configured, signed out) reports false:
    /// the refresh did nothing useful and the cadence backs off
    /// instead of polling hourly forever. Freshness is an
    /// optimization only - use-time expiry fails closed when the OS
    /// never grants a refresh.
    func syncForBackground() async -> Bool {
        guard let controller else { return false }
        let configuration = AppConfiguration.currentOnDevice()
        let store = FilterRuleStore.appGroupStore()
        await controller.syncNow()
        refreshAppPolicyMirror(configuration: configuration,
                               store: store)
        if case .synced = controller.state { return true }
        return false
    }
}

@main
struct KosherGuardApp: App {
    @State private var credentials: CredentialController
    @State private var sync: FilterSyncViewModel
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let credentials = CredentialController()
        let sync = FilterSyncViewModel()
        // Sign-out deletes the identity-bound app-policy mirror under
        // the store lock; the shield section re-evaluates the remote
        // gate immediately, not at the next app restart.
        credentials.onIdentityTeardown = { [weak sync] in
            sync?.noteIdentityTeardown()
        }
        _credentials = State(wrappedValue: credentials)
        _sync = State(wrappedValue: sync)
        #if canImport(BackgroundTasks)
        // Background policy refresh (BGTaskScheduler). Registration
        // MUST happen before launch finishes. OS-DISCRETIONARY: the
        // task may run late or never; freshness here is an
        // optimization, and enforcement fails closed at the use-time
        // expiry horizons when no refresh runs (see
        // BackgroundRefreshPolicy / BackgroundRefreshScheduler).
        BackgroundRefreshScheduler.shared.register { [weak sync] in
            guard let sync else { return false }
            return await sync.syncForBackground()
        }
        BackgroundRefreshScheduler.shared.scheduleNext()
        #endif
    }

    var body: some Scene {
        WindowGroup {
            FilterStatusView()
                .environment(credentials)
                .environment(sync)
                #if canImport(BackgroundTasks)
                // Leaving the foreground is the natural moment to
                // request the next background refresh (same-identifier
                // submit replaces, never stacks).
                .onChange(of: scenePhase) { _, phase in
                    if phase == .background {
                        BackgroundRefreshScheduler.shared.scheduleNext()
                    }
                }
                #endif
        }
    }
}

struct FilterStatusView: View {
    @Environment(CredentialController.self) private var credentials
    @Environment(FilterSyncViewModel.self) private var sync
    private var status: FilterStatus {
        FilterStatus(
            extensionState: sync.urlFilterState,
            prefilterVersion: nil,
            enrollmentState: "Not enrolled")
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Protection") {
                    LabeledContent("Filter",
                                   value: status.extensionState.rawValue)
                    Text(status.protectionSummary)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    // The SYSTEM's own readback
                    // (NEURLFilterManager isEnabled/Status/last
                    // error), not what this process last attempted.
                    LabeledContent("System state",
                                   value: sync.systemReadback)
                    // Explicit guardian control. On is gated (PIR
                    // endpoints configured and deployable); off is
                    // always available.
                    Toggle("URL filtering on this device", isOn:
                        Binding(
                            get: { sync.urlFilterState == .enabled
                                || sync.urlFilterState == .running },
                            set: { sync.setURLFilterEnabled($0) }))
                    Button("Re-read system state") {
                        Task { await sync
                            .refreshURLFilterSystemStatus() }
                    }
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
                // Personally-owned, device-local app blocking (Screen
                // Time route). Separate from the supervised MDM
                // bundle-ID policy on purpose: the server cannot pick
                // apps here. Consent is Apple's system prompt, only
                // ever from the button inside this section.
                Section("App blocking (this device)") {
                    AppBlockingSection()
                }
                Section("Device credential sign-in") {
                    CredentialSignInView()
                }
            }
            .navigationTitle("KosherGuard")
        }
    }
}

/// Personal-lane setup orchestration for an unsupervised device:
/// server address + guardian sign-in -> service discovery ->
/// idempotent device registration -> persisted configuration
/// (PersonalSetupCoordinator), then the regular tested credential
/// flow (signInAndIssue) mints the device credential under the
/// lifecycle authority model. No MDM involved; no endpoint invented:
/// every service URL comes from the server's own discovery response.
@Observable
final class PersonalSetupViewModel {
    enum Phase {
        case idle
        case working
        case failed
        case done
    }
    var serverURL = ""
    var email = ""
    var password = ""
    var totpCode = ""
    private(set) var phase: Phase = .idle
    private(set) var lastError: String?

    func setUp(credentials: CredentialController,
               sync: FilterSyncViewModel) async {
        guard let store = PersonalConfigurationStore.shared() else {
            phase = .failed
            lastError = "The shared app-group container is unavailable "
                + "(entitlement or provisioning not active), so setup "
                + "cannot persist this device's configuration."
            return
        }
        guard let base =
                PersonalConfiguration.validatedHTTPSURL(serverURL)
        else {
            phase = .failed
            lastError = "Enter the server address as a plain "
                + "https:// URL."
            return
        }
        phase = .working
        lastError = nil
        struct AuthAdapter: SessionSigningIn {
            let client: AuthSessionClient
            func signIn(email: String, password: String,
                        totpCode: String?) async throws -> String {
                try await client.signIn(.init(
                    email: email, password: password,
                    totpCode: totpCode))
            }
        }
        struct SignOutAdapter: SessionSigningOut {
            let client: AuthSessionClient
            func signOut(sessionCookie: String) async throws {
                try await client.signOut(sessionCookie: sessionCookie)
            }
        }
        struct ConfigAdapter: ClientConfigFetching {
            let client: ClientConfigClient
            func fetchConfig(sessionCookie: String) async throws
                -> ClientConfigClient.ServiceConfig {
                try await client.fetch(sessionCookie: sessionCookie)
            }
        }
        struct RegistrationAdapter: PersonalDeviceRegistering {
            let client: PersonalRegistrationClient
            func register(name: String, registrationKey: String,
                          sessionCookie: String) async throws
                -> PersonalRegistrationClient.Registration {
                try await client.register(
                    name: name, registrationKey: registrationKey,
                    sessionCookie: sessionCookie)
            }
        }
        let coordinator = PersonalSetupCoordinator(store: store)
        do {
            _ = try await coordinator.setUp(
                serverURL: serverURL, email: email, password: password,
                totpCode: totpCode.isEmpty ? nil : totpCode,
                auth: AuthAdapter(
                    client: AuthSessionClient(baseURL: base)),
                config: ConfigAdapter(
                    client: ClientConfigClient(baseURL: base)),
                registration: RegistrationAdapter(
                    client: PersonalRegistrationClient(baseURL: base)),
                signOut: SignOutAdapter(
                    client: AuthSessionClient(baseURL: base)))
        } catch let error as PersonalSetupCoordinator.SetupError {
            phase = .failed
            switch error {
            case .invalidServerURL:
                lastError = "Enter the server address as a plain "
                    + "https:// URL."
            case .invalidCredentials:
                lastError = "Sign-in was rejected. Check the email, "
                    + "password and authenticator code."
            case .rateLimited:
                lastError = "Too many attempts; wait and try again."
            case .nameConflict:
                lastError = "That device name is already registered; "
                    + "try again."
            case .deviceNotActive(let state):
                lastError = "This device is registered but \(state); "
                    + "a guardian must reactivate it in the dashboard."
            case .storeUnavailable, .persistenceFailed:
                lastError = "Could not store the setup on this device."
            case .alreadyInProgress:
                lastError = "Setup is already running."
            case .failed(let detail):
                lastError = "Setup failed: \(detail)"
            }
            return
        } catch {
            phase = .failed
            lastError = "Setup failed: \(error.localizedDescription)"
            return
        }
        // Adopt the new identity through the ONE lifecycle owner
        // (authority rotation and identity clear are atomic with the
        // mirror write), refresh the clients against it, then run the
        // regular tested credential flow so the session and dataset
        // credential land as ONE atomic keychain bundle.
        do {
            try await CredentialController.lifecycle
                .applyCurrentConfiguration()
        } catch {
            phase = .failed
            lastError = "Could not activate the new configuration: "
                + "\(error.localizedDescription)"
            return
        }
        credentials.reconfigure(AppConfiguration.currentOnDevice())
        sync.reconfigureNow()
        await credentials.signInAndIssue(
            email: email, password: password,
            totpCode: totpCode.isEmpty ? nil : totpCode)
        phase = .done
    }
}

/// The reachable personal-lane setup UI, shown in place of the
/// sign-in form when the device has neither a managed configuration
/// nor a personal setup record.
struct PersonalSetupView: View {
    @Environment(CredentialController.self) private var credentials
    @Environment(FilterSyncViewModel.self) private var sync
    @State private var model = PersonalSetupViewModel()

    var body: some View {
        Text("This device is not set up. Enter your KosherGuard "
             + "server address and sign in to register it.")
            .font(.footnote)
            .foregroundStyle(.secondary)
        TextField("Server address (https://...)", text: $model.serverURL)
            .textContentType(.URL)
            .keyboardType(.URL)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
        TextField("Email", text: $model.email)
            .textContentType(.emailAddress)
            .keyboardType(.emailAddress)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
        SecureField("Password", text: $model.password)
        TextField("Authenticator code (if enabled)", text: $model.totpCode)
            .keyboardType(.numberPad)
        Button("Set up and sign in") {
            Task { await model.setUp(credentials: credentials, sync: sync) }
        }
        .disabled(model.serverURL.isEmpty || model.email.isEmpty
                  || model.password.isEmpty || model.phase == .working)
        if model.phase == .working {
            Text("Setting up...").font(.footnote)
                .foregroundStyle(.secondary)
        }
        if let error = model.lastError {
            Text(error).font(.footnote).foregroundStyle(.red)
        }
    }
}

/// The reachable user action for the credential flow. When the device
/// has no configuration at all, the personal-lane setup is offered
/// instead (an unsupervised iPhone has no MDM to supply one).
struct CredentialSignInView: View {
    @Environment(CredentialController.self) private var credentials
    @State private var email = ""
    @State private var password = ""
    @State private var totpCode = ""

    var body: some View {
        if case .notConfigured = credentials.state {
            PersonalSetupView()
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
