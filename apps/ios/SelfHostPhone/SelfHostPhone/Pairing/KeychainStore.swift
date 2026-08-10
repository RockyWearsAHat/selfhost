//  KeychainStore.swift
//  SelfHostPhone
//
//  The paired server's credential, kept in the iOS Keychain.
//
//  The token controls every service on the operator's machine, so it never
//  touches UserDefaults or a file: it lives in a generic-password Keychain item
//  accessible only after first unlock, and never migrates to a new device
//  (`ThisDeviceOnly`) — a restored backup on somebody else's phone must not
//  carry control of the server with it.

import Foundation
import Security

/// Everything needed to reach and authenticate against the paired server.
///
/// Hashable so a view can use the whole credential as identity: re-pairing
/// with a different server (or token) rebuilds the dashboard from scratch.
struct ServerCredential: Codable, Hashable {
    /// Human name for the server, shown in the app's title.
    let name: String
    /// Host the admin API is reachable at from this phone.
    let host: String
    /// TCP port of the admin API.
    let port: UInt16
    /// Whether to speak HTTPS.
    let tls: Bool
    /// SHA-256 of the server's DER leaf certificate as 64 lowercase hex
    /// characters, when the connection is pinned.
    let fingerprint: String?
    /// The long-lived bearer token presented as `Authorization: Bearer`.
    let token: String

    /// The base URL every API path is resolved against.
    var baseURL: URL? {
        var components = URLComponents()
        components.scheme = tls ? "https" : "http"
        components.host = host
        components.port = Int(port)
        return components.url
    }
}

/// Why a Keychain operation failed.
enum KeychainError: LocalizedError {
    /// The Keychain refused the operation with an OSStatus.
    case unexpectedStatus(OSStatus)
    /// The stored item exists but is not a decodable credential.
    case corruptItem

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "The Keychain refused: \(message)"
        case .corruptItem:
            return "The stored credential could not be read. Re-pair with the server."
        }
    }
}

/// Reads and writes the single paired-server credential.
///
/// One server per phone is a deliberate simplification: the account name is
/// fixed, and pairing again replaces the previous server.
struct KeychainStore {
    /// The Keychain service namespace for this app's items.
    private static let service = "dev.selfhost.phone"
    /// The account under which the one credential is stored.
    private static let account = "paired-server"

    /// The attributes that identify the credential item.
    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
        ]
    }

    /// Stores the credential, replacing any previously paired server.
    func save(_ credential: ServerCredential) throws {
        let data = try JSONEncoder().encode(credential)
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let update: [String: Any] = [kSecValueData as String: data]
            let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw KeychainError.unexpectedStatus(updateStatus)
            }
            return
        }
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Loads the stored credential, or `nil` when no server is paired.
    ///
    /// Throws only for real failures: an unreadable item is an error the person
    /// should see (and fix by re-pairing), not a silent "not paired".
    func load() throws -> ServerCredential? {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let credential = try? JSONDecoder().decode(ServerCredential.self, from: data)
            else {
                throw KeychainError.corruptItem
            }
            return credential
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Removes the stored credential. Absent is success: the goal is "gone".
    func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}
