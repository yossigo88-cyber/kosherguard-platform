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
    public init() {}
    let service = "com.kosherguard.credentials"

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
        SecItemDelete(query as CFDictionary)
        var attrs = query
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
        let status = SecItemCopyMatching(query as CFDictionary, &item)
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
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound
        else { throw StoreError.deleteFailed(status) }
    }
}
