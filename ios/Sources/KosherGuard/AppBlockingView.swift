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
///
/// REMOTE ACTIVATION GATE (Stage 10): when this device is linked to a
/// KosherGuard family account, the mirrored app policy carries a
/// `shield_active` flag the family administrator sets from the
/// dashboard. It gates ONLY whether the device's own locally
/// consented selection is activated:
///   - The server never sees, chooses or widens WHICH apps are
///     shielded. The selection's tokens are opaque and device-local
///     and are never uploaded anywhere.
///   - Gate OFF pauses the shield but keeps the local selection;
///     gate back ON reactivates exactly that selection.
///   - Local removal deletes the selection; the gate cannot recreate
///     it. Local consent and revocation always win.
///   - Gate UNKNOWN (never synced, signed out, or server identity
///     changed) means purely local behavior, exactly as before this
///     feature existed. A failed sync changes nothing: the last
///     mirrored gate keeps applying across restarts (it is stored
///     identity-bound next to the filter snapshot).
/// The gate cannot exceed the selection: there is deliberately no
/// remote path to all-apps or all-except category shielding - that
/// would be broader than the user's explicit local consent and needs
/// a separate local choice in the picker.
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
        /// A selection is stored but the family administrator turned
        /// the shield off remotely. The choice is kept locally and
        /// the device owner can change or remove it anytime.
        case remotePaused = "Turned off by your administrator"
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
        // The approved path, shared by .approved and (iOS 26.4+)
        // .approvedWithDataAccess, which grants everything .approved
        // grants plus access to non-tokenized family activity data.
        func applyApprovedAuthorization() {
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
                let counts = "\(saved.applicationTokens.count) apps, "
                    + "\(saved.categoryTokens.count) categories, "
                    + "\(saved.webDomainTokens.count) websites."
                if currentRemoteGate() == false {
                    // Gate OFF: pause only. The selection file stays;
                    // the administrator cannot see or rebuild it, and
                    // local removal below still wins.
                    controller.clearShield()
                    state = .remotePaused
                    note = counts + " Kept on this iPhone."
                } else {
                    // Gate ON or UNKNOWN: activate the local choice.
                    controller.applyShield(selection: saved)
                    state = .shielding
                    note = counts
                    if currentRemoteGate() == true {
                        note += " Your administrator can pause this "
                            + "remotely."
                    }
                }
            } else {
                state = .readyToChoose
                note = ""
            }
        }
        switch AuthorizationCenter.shared.authorizationStatus {
        case .notDetermined:
            state = .needsConsent
        case .denied:
            state = .notAuthorized
        case .approved:
            applyApprovedAuthorization()
        default:
            // iOS 26.4 added .approvedWithDataAccess. It is
            // availability-annotated (iOS 26.4+), so it cannot be a case
            // pattern on this iOS 17 deployment target; handle it here
            // instead. It grants everything .approved grants, so it
            // takes the approved path. Any other state this build does
            // not know is treated conservatively as NOT authorized.
            if #available(iOS 26.4, *),
               AuthorizationCenter.shared.authorizationStatus
                   == .approvedWithDataAccess {
                applyApprovedAuthorization()
            } else {
                state = .notAuthorized
            }
        }
    }

    /// The one consent entry point. Apple's system prompt is the
    /// authorization UX; errors/denials surface as notAuthorized.
    /// kind selects Apple's two documented forms: .individual (this
    /// device's user self-authorizes with Face ID/Touch ID) or
    /// .child (device signed into a Family Sharing CHILD account; a
    /// parent or guardian must authenticate). .child on a non-child
    /// account fails honestly through the same error path.
    func requestAuthorization(
        for kind: AppShieldController.AuthorizationKind = .individual
    ) async {
        do {
            try await controller.requestAuthorization(for: kind)
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
        // refresh() applies the shield or pauses it per the remote
        // gate - never apply directly here, or a paused device would
        // re-shield the moment the picker closes.
        refresh()
    }

    /// The mirrored policy's remote gate for the CURRENT server
    /// identity, or nil when unknown. Reads only the device-local
    /// mirror written by the pull sync; performs no network access
    /// and never uploads the selection.
    private func currentRemoteGate() -> Bool? {
        let configuration = AppConfiguration.managed()
        guard let fingerprint = FilterSyncController.bootstrap(
            for: configuration, tenantID: nil)?.endpointFingerprint,
            let store = FilterRuleStore.appGroupStore()
        else { return nil }
        return AppBlockingPolicyStore(
            snapshotFile: store.appPolicyMirrorFile)
            .load(endpointFingerprint: fingerprint)?.shieldActive
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
    @Environment(FilterSyncViewModel.self) private var sync

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
            // Family-managed route (Apple .child authorization): for
            // a device signed into a child's Family Sharing account;
            // a parent or guardian must authenticate the request.
            Button("This is my child's device") {
                Task {
                    await model.requestAuthorization(for: .child)
                }
            }
            Text("On a child's device, a parent or guardian confirms "
                 + "with their own authentication.")
                .font(.footnote).foregroundStyle(.secondary)
        case .notAuthorized:
            Text("Screen Time access was not granted, so no apps are "
                 + "blocked. You can grant it in Settings > Screen "
                 + "Time, then return here.")
                .font(.footnote).foregroundStyle(.secondary)
            Button("Check again") { model.refresh() }
        case .remotePaused:
            Text("Your administrator turned app blocking off "
                 + "remotely. Your app choice stays private on this "
                 + "iPhone - they cannot see which apps you picked - "
                 + "and you can change or remove it anytime.")
                .font(.footnote).foregroundStyle(.secondary)
            Button("Change blocked apps") { pickerPresented = true }
                .familyActivityPicker(
                    isPresented: $pickerPresented,
                    selection: $model.selection)
                .onChange(of: pickerPresented) { _, presented in
                    if !presented { model.applySelection() }
                }
            Button("Remove app blocking", role: .destructive) {
                model.removeBlocking()
            }
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
        // Honest remote-control disclosure, always visible: the user
        // must know an administrator CAN toggle this shield remotely
        // before it ever happens.
        Text("If this device is linked to a KosherGuard family "
             + "account, an administrator can turn this blocking on "
             + "or off remotely. They can never see or change which "
             + "apps you picked, and removing your choice here "
             + "always wins.")
            .font(.caption).foregroundStyle(.secondary)
            .onChange(of: sync.appPolicyGeneration) { _, _ in
                // A completed policy mirror may have flipped the
                // remote gate; re-evaluate authorization + gate.
                model.refresh()
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
