// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import SwiftUI

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

@main
struct KosherGuardApp: App {
    var body: some Scene {
        WindowGroup {
            FilterStatusView()
        }
    }
}

struct FilterStatusView: View {
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
                }
            }
            .navigationTitle("KosherGuard")
        }
    }
}

#Preview {
    FilterStatusView()
}
