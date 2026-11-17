// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation
import Security

/// Keychain storage for scoped device credentials and the session
/// cookie. Closes the "in-memory only" gap: short-lived tokens still
/// need a device-bound home between launches, and the Keychain is the
/// only appropriate one on iOS (UserDefaults and files are not).
///
/// Items are stored kSecClassGenericPassword, this device's current
/// unlock state only (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
/// no iCloud sync, no migration to a new device - a scoped credential
/// belongs to THIS device).
public struct KeychainCredentialStore {
    /// PLACEHOLDER pending the real Apple Developer team ID: the
    /// keychain access group shared by the app and BOTH filter
    /// extensions so the control provider can use the same session /
    /// device credential for its supported rule-maintenance sync.
    /// Must match the keychain-access-groups entitlement in every
    /// target (currently absent from the hand-authored entitlements:
    /// tracked in docs/setup/IOS_BUILD.md). UNVERIFIED.
    public static let sharedAccessGroup =
        "TEAMIDPLACEHOLDER.com.kosherguard.shared"

    /// accessGroup: pass KeychainCredentialStore.sharedAccessGroup in
    /// every production caller (app and extensions); nil keeps the
    /// app's private keychain (tests and pre-team-id development).
    public init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }
    let accessGroup: String?
    let service = "com.kosherguard.credentials"

    private func scoped(_ query: [String: Any]) -> [String: Any] {
        var q = query
        if let accessGroup {
            q[kSecAttrAccessGroup as String] = accessGroup
        }
        return q
    }

    public enum StoreError: Error {
        case saveFailed(OSStatus)
        case readFailed(OSStatus)
        case deleteFailed(OSStatus)
    }

    public func save(key: String, value: String) throws {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        // Replace-any-existing semantics via delete-then-add: simple
        // and atomicity is not required for a cache of a re-mintable
        // credential.
        SecItemDelete(scoped(query) as CFDictionary)
        var attrs = scoped(query)
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] =
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw StoreError.saveFailed(status)
        }
    }

    public func read(key: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(scoped(query) as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess,
              let data = item as? Data else {
            throw StoreError.readFailed(status)
        }
        return String(data: data, encoding: .utf8)
    }

    public func delete(key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let status = SecItemDelete(scoped(query) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound
        else { throw StoreError.deleteFailed(status) }
    }
}

/// Lets FilterSyncController read stored credentials through its
/// portable CredentialReading seam.
extension KeychainCredentialStore: CredentialReading {}

/// Writable vault conformance for the sign-in coordinator's atomic
/// credential bundle (declared here: this file is not part of the
/// portable test target, which uses in-memory fakes instead).
extension KeychainCredentialStore: CredentialVault {}
