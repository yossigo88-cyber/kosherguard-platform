// STATUS: UNCOMPILED, UNSIGNED, UNTESTED ON APPLE PLATFORMS.
// FamilyControls / ManagedSettings symbols are written against
// Apple's documentation (developer.apple.com/documentation/
// familycontrols/authorizationcenter and /managedsettings/
// shieldsettings, read 2026-11-17); no Apple SDK has compiled this
// file. Requires the com.apple.developer.family-controls
// entitlement, which must be added to the App ID by an Apple
// account holder - NOT requested or configured yet.
//
// SCOPE OF THIS MECHANISM (personally-owned devices): the Screen
// Time API shields apps/categories identified by OPAQUE,
// DEVICE-LOCAL tokens (ApplicationToken / ActivityCategoryToken).
// A token is chosen on THIS device through FamilyActivityPicker;
// it cannot be derived from a bundle ID and cannot be transferred
// between devices. Remote policy updates from the control plane
// therefore cannot push "block app X" to a personally-owned device;
// they can only be mirrored for dashboard visibility. The
// bundle-ID policy (AppBlockingPolicy) is enforced through the
// supervised MDM route (com.apple.applicationaccess profile).
// See AppBlockingPolicy.swift for the full capability split.
import Foundation
#if canImport(FamilyControls) && canImport(ManagedSettings)
import FamilyControls
import ManagedSettings

/// Applies and clears the local Screen Time shields for the
/// personally-owned route. Launch-blocking here is REAL blocking of
/// app launches (the shield covers the app), which DNS-level
/// internet denial is not.
final class AppShieldController {

    /// One named store per device policy slot; a named store's
    /// settings persist across app launches and reinstalls.
    private let store = ManagedSettingsStore(
        named: ManagedSettingsStore.Name("kosherguard-app-blocking"))

    /// FamilyControls authorization state. Shield changes without
    /// `.approved` are silently ineffective, so the caller checks
    /// this before claiming anything is blocked.
    var authorizationStatus: AuthorizationStatus {
        AuthorizationCenter.shared.authorizationStatus
    }

    /// Ask the user for Screen Time authorization (individual
    /// device use). Throws on denial/failure - the caller must
    /// surface that shielding is NOT active.
    func requestAuthorization() async throws {
        try await AuthorizationCenter.shared.requestAuthorization(
            for: .individual)
    }

    /// Apply an on-device FamilyActivityPicker selection as the
    /// shield set. The selection is Codable and is persisted by the
    /// caller (app group) so shields survive app relaunch; the
    /// tokens themselves remain valid only on this device.
    func applyShield(selection: FamilyActivitySelection) {
        store.shield.applications = selection.applicationTokens
            .isEmpty ? nil : selection.applicationTokens
        store.shield.applicationCategories =
            selection.categoryTokens.isEmpty
                ? ShieldSettings.ActivityCategoryPolicy.none
                : .specific(selection.categoryTokens, except: [])
        store.shield.webDomains = selection.webDomainTokens
            .isEmpty ? nil : selection.webDomainTokens
    }

    /// Remove every shield this store applied. Used on sign-out and
    /// on guardian disable - never implicitly, only on an explicit
    /// lifecycle event, so a sync failure never silently unblocks.
    func clearShield() {
        store.clearAllSettings()
    }
}
#endif
