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

/// Call site for the scoped-credential request path: the app owns a
/// CredentialIssuanceClient and surfaces issuance state honestly.
/// "Not requested" is the only state reachable in this build - there
/// is no server session acquisition (native token exchange) yet, so
/// no mint can actually run; the UI says so instead of pretending.
@Observable
final class CredentialController {
    enum State: String {
        case notRequested = "Not requested (sign-in for devices not built)"
        case issued = "Issued"
        case failed = "Issuance failed"
    }
    private(set) var state: State = .notRequested
    private let client: CredentialIssuanceClient?

    init(client: CredentialIssuanceClient?) {
        self.client = client
    }

    /// Wired for the future native-auth flow: without a guardian
    /// session (see CredentialIssuanceClient docs) there is nothing
    /// to send, so this is a deliberate no-op that keeps the honest
    /// state. It exists so the call site is real and reviewable.
    func requestDatasetCredential(deviceID: Int) async {
        guard client != nil else { return }  // stays .notRequested
    }
}

@main
struct KosherGuardApp: App {
    @State private var credentials = CredentialController(client: nil)

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
