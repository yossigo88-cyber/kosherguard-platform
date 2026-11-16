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
/// (KeychainCredentialStore). This is the real flow as code - still
/// UNCOMPILED/UNSIGNED/UNTESTED with no configured server URL in this
/// build, so it has never run; that is stated, not hidden.
@Observable
final class CredentialController {
    enum State: String {
        case signedOut = "Not signed in"
        case signingIn = "Signing in"
        case issuing = "Requesting device credential"
        case issued = "Device credential issued"
        case failed = "Failed"
    }
    private(set) var state: State = .signedOut
    private(set) var lastError: String?

    private let auth: AuthSessionClient
    private let issuance: CredentialIssuanceClient
    private let store: KeychainCredentialStore

    init(baseURL: URL, session: URLSession = .shared,
         store: KeychainCredentialStore = KeychainCredentialStore()) {
        self.auth = AuthSessionClient(baseURL: baseURL, session: session)
        self.issuance = CredentialIssuanceClient(baseURL: baseURL,
                                                 session: session)
        self.store = store
    }

    /// Full native flow: sign in, mint a dataset-scoped credential for
    /// this device, persist both in the Keychain. Dataset scope is the
    /// only scope useful to the app today (prefilter updates); doh
    /// stays refused until the held server change lands.
    func signInAndIssue(email: String, password: String,
                        totpCode: String?, deviceID: Int) async {
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
        } catch {
            lastError = String(describing: error)
            state = .failed
        }
    }
}

@main
struct KosherGuardApp: App {
    // FIXTURE base URL: this build has no configured server, so the
    // controller is created against an invalid host and cannot reach
    // anything. A signed build would read this from MDM configuration.
    @State private var credentials = CredentialController(
        baseURL: URL(string: "https://control-plane.invalid")!)

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
            }
            .navigationTitle("KosherGuard")
        }
    }
}

#Preview {
    FilterStatusView()
}
