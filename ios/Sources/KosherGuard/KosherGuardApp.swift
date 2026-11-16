// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import SwiftUI
import URLFilter

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

    init(store: KeychainCredentialStore = KeychainCredentialStore(),
         configuration: AppConfiguration = .managed()) {
        self.store = store
        if let baseURL = configuration.controlPlaneBaseURL,
           let deviceID = configuration.deviceID {
            self.auth = AuthSessionClient(baseURL: baseURL,
                                          session: .shared)
            self.issuance = CredentialIssuanceClient(baseURL: baseURL,
                                                     session: .shared)
            self.deviceID = deviceID
            self.state = .signedOut
        }
    }

    /// Reachable user action: the sign-in form calls this. Full flow:
    /// sign in -> mint a dataset-scoped credential for this device ->
    /// persist both in the Keychain. Dataset scope is the only scope
    /// useful to the app today (prefilter updates); doh stays refused
    /// until the held server change lands.
    func signInAndIssue(email: String, password: String,
                        totpCode: String?) async {
        guard let auth, let issuance, let deviceID else { return }
        state = .signingIn
        do {
            let cookie = try await auth.signIn(.init(
                email: email, password: password, totpCode: totpCode))
            try store.save(key: "session", value: cookie)
            state = .issuing
            let credential = try await issuance.mint(
                deviceID: deviceID, scope: .dataset,
                sessionCookie: cookie)
            try store.save(key: "credential.dataset",
                           value: credential.token)
            state = .issued
        } catch CredentialIssuanceClient.IssuanceError.unauthorized {
            // Dead session: clear it so the next attempt signs in
            // fresh instead of replaying a rejected cookie.
            try? store.delete(key: "session")
            lastError = "Session rejected; sign in again."
            state = .failed
        } catch {
            lastError = String(describing: error)
            state = .failed
        }
    }

    /// Sign out server-side and clear every stored credential.
    func signOut() async {
        if let cookie = try? store.read(key: "session"), let cookie {
            try? await auth?.signOut(sessionCookie: cookie)
        }
        try? store.delete(key: "session")
        try? store.delete(key: "credential.dataset")
        state = auth == nil ? .notConfigured : .signedOut
    }
}

@main
struct KosherGuardApp: App {
    @State private var credentials = CredentialController()

    var body: some Scene {
        WindowGroup {
            FilterStatusView()
                .environment(credentials)
        }
    }
}

struct FilterStatusView: View {
    @Environment(CredentialController.self) private var credentials
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
