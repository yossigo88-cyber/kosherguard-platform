// STATUS: UNCOMPILED, UNSIGNED, UNTESTED ON APPLE PLATFORMS.
// This file is written against Apple's documentation for
// FamilyControls (AuthorizationCenter, FamilyActivityPicker,
// FamilyActivitySelection) and ManagedSettings (ManagedSettingsStore,
// ShieldSettings), fetched 2026-11-17; no Apple SDK has compiled it.
// It answers the independent-review finding that AppShieldController
// was UNREACHABLE: this is the UI layer that calls it.
//
// CONSENT MODEL (Apple-required, never bypassed): shielding starts
// only after the device's user taps "Enable app blocking" and approves
// the system Screen Time authorization prompt that
// AuthorizationCenter.requestAuthorization(for: .individual) presents.
// This file never requests authorization on appear, never retries in a
// loop, and never treats a missing answer as approval. A denial is
// shown as "not protected", exactly as the user's standing rule
// requires.
//
// SCOPE (unchanged from AppShieldController's header): on a
// personally-owned device the selection is made of OPAQUE,
// DEVICE-LOCAL tokens chosen in FamilyActivityPicker. The control
// plane's bundle-ID policy cannot select apps here; the supervised
// MDM route (blockedAppBundleIDs / DDM DeniedApps) is where bundle-ID
// enforcement happens. This view therefore presents the two routes
// separately and never claims the server policy is what shields.
import Foundation
import SwiftUI

/// Persists the FamilyActivityPicker selection across app launches.
/// FamilyActivitySelection is Codable; this store only moves Data, so
/// the bytes stay Apple-side and the store logic stays portable and
/// unit-testable (see tools/swift-portable-tests.swift).
struct AppShieldSelectionStore {
    let file: URL

    init?(fileManager: FileManager = .default) {
        guard let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier:
                FilterRuleStore.appGroupIdentifier)
        else { return nil }
        // Same fail-honest rule as FilterRuleStore.appGroupStore: no
        // silent fallback to a private container.
        self.file = container.appendingPathComponent(
            "shield-selection.json")
    }

    func save(_ data: Data) throws {
        try data.write(to: file, options: .atomic)
    }

    func load() -> Data? {
        try? Data(contentsOf: file)
    }

    func clear() {
        try? FileManager.default.removeItem(at: file)
    }
}

#if canImport(FamilyControls) && canImport(ManagedSettings)
import FamilyControls
import ManagedSettings

/// Drives the personally-owned app blocking section: authorization,
/// selection, shield application, removal.
@Observable
final class AppShieldViewModel {
    enum State: String {
        /// AuthorizationCenter has not been asked on this device.
        case needsConsent = "Not enabled"
        /// The system prompt was declined or restricted (Screen Time
        /// parental controls can also deny). NOT protected.
        case notAuthorized = "Screen Time access not granted"
        /// Authorized, no shield chosen yet.
        case readyToChoose = "Choose apps to block"
        /// A selection is stored and applied to the named store.
        case shielding = "App blocking on"
        /// Persistence unavailable (app group missing) - shield NOT
        /// guaranteed to survive relaunch; surfaced, never hidden.
        case persistenceUnavailable = "Shield storage unavailable"
    }

    private(set) var state: State = .needsConsent
    private(set) var note: String = ""
    /// The current picker selection; bound to FamilyActivityPicker.
    var selection = FamilyActivitySelection()

    private let controller = AppShieldController()
    private let selectionStore = AppShieldSelectionStore()

    init() {
        refresh()
    }

    /// Re-read Apple's authorization state and any stored selection.
    /// Called on appear and after every action: the user can change
    /// Screen Time permission in Settings at any time, and the shield
    /// is silently ineffective without .approved.
    func refresh() {
        switch AuthorizationCenter.shared.authorizationStatus {
        case .notDetermined:
            state = .needsConsent
        case .denied:
            state = .notAuthorized
        case .approved:
            guard let store = selectionStore else {
                state = .persistenceUnavailable
                return
            }
            if let data = store.load(),
               let saved = try? JSONDecoder().decode(
                   FamilyActivitySelection.self, from: data),
               !saved.applicationTokens.isEmpty
                   || !saved.categoryTokens.isEmpty
                   || !saved.webDomainTokens.isEmpty {
                selection = saved
                controller.applyShield(selection: saved)
                state = .shielding
                note = "\(saved.applicationTokens.count) apps, "
                    + "\(saved.categoryTokens.count) categories, "
                    + "\(saved.webDomainTokens.count) websites."
            } else {
                state = .readyToChoose
                note = ""
            }
        @unknown default:
            // Honest SDK unknown: an authorization state this build
            // does not know is treated as NOT authorized.
            state = .notAuthorized
        }
    }

    /// The one consent entry point. Apple's system prompt is the
    /// authorization UX; errors/denials surface as notAuthorized.
    func requestAuthorization() async {
        do {
            try await controller.requestAuthorization()
        } catch {
            state = .notAuthorized
            note = "Authorization was not granted (\(error.localizedDescription))."
            return
        }
        refresh()
    }

    /// Persist and apply the picker's current selection. Empty
    /// selection means "block nothing" and is applied as such (nil
    /// shields) - never silently kept as a stale shield.
    func applySelection() {
        guard let store = selectionStore else {
            state = .persistenceUnavailable
            return
        }
        do {
            try store.save(try JSONEncoder().encode(selection))
        } catch {
            state = .persistenceUnavailable
            note = "Could not persist the selection: \(error.localizedDescription)"
            return
        }
        controller.applyShield(selection: selection)
        refresh()
    }

    /// Explicit removal only (matches AppShieldController's lifecycle
    /// rule): clears the named store's shields and deletes the stored
    /// selection. A sync failure elsewhere never calls this.
    func removeBlocking() {
        controller.clearShield()
        selectionStore?.clear()
        selection = FamilyActivitySelection()
        refresh()
    }
}

/// The reachable personally-owned app blocking UI. Embedded as a
/// section in FilterStatusView.
struct AppBlockingSection: View {
    @State private var model = AppShieldViewModel()
    @State private var pickerPresented = false

    var body: some View {
        LabeledContent("This device", value: model.state.rawValue)
        if !model.note.isEmpty {
            Text(model.note).font(.footnote).foregroundStyle(.secondary)
        }
        switch model.state {
        case .needsConsent:
            Text("Blocks chosen apps on THIS iPhone via Screen Time. "
                 + "iOS will ask you to allow it; KosherGuard cannot "
                 + "enable it by itself.")
                .font(.footnote).foregroundStyle(.secondary)
            Button("Enable app blocking") {
                Task { await model.requestAuthorization() }
            }
        case .notAuthorized:
            Text("Screen Time access was not granted, so no apps are "
                 + "blocked. You can grant it in Settings > Screen "
                 + "Time, then return here.")
                .font(.footnote).foregroundStyle(.secondary)
            Button("Check again") { model.refresh() }
        case .readyToChoose, .shielding, .persistenceUnavailable:
            Button(model.state == .shielding
                   ? "Change blocked apps" : "Choose apps to block") {
                pickerPresented = true
            }
            .familyActivityPicker(
                isPresented: $pickerPresented,
                selection: $model.selection)
            .onChange(of: pickerPresented) { _, presented in
                // Apply only when the sheet CLOSES, so a live edit is
                // not half-applied; cancelling with no change re-applies
                // the stored selection harmlessly.
                if !presented { model.applySelection() }
            }
            if model.state == .shielding {
                Button("Remove app blocking", role: .destructive) {
                    model.removeBlocking()
                }
            }
            if model.state == .persistenceUnavailable {
                Text("The shared app-group container is missing "
                     + "(entitlement/provisioning not active), so the "
                     + "selection cannot be stored. Shielding is not "
                     + "guaranteed until this is fixed.")
                    .font(.footnote).foregroundStyle(.red)
            }
        }
    }
}
#else
/// Stub for builds without the FamilyControls/ManagedSettings SDKs:
/// the section stays visible and honest instead of vanishing.
struct AppBlockingSection: View {
    var body: some View {
        LabeledContent("This device", value: "Unavailable in this build")
        Text("App blocking needs the FamilyControls and ManagedSettings "
             + "frameworks and the family-controls entitlement.")
            .font(.footnote).foregroundStyle(.secondary)
    }
}
#endif
