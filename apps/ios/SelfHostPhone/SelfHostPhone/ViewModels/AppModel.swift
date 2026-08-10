//  AppModel.swift
//  SelfHostPhone
//
//  The app's root state: whether a server is paired, and the pairing flow.

import Foundation

/// Root observable state: the paired server, or the absence of one.
///
/// Owns the Keychain round-trips so views never touch storage directly, and
/// owns pairing so the "verify before saving" rule lives in exactly one place.
@MainActor
final class AppModel: ObservableObject {
    /// The paired server, or `nil` when the app should show the pairing screen.
    @Published private(set) var credential: ServerCredential?
    /// A storage problem the person should see (a corrupt Keychain item, say).
    @Published private(set) var storageError: String?

    private let store = KeychainStore()

    /// Loads any previously paired server from the Keychain.
    init() {
        do {
            credential = try store.load()
        } catch {
            credential = nil
            storageError = error.localizedDescription
        }
    }

    /// Pairs with the server a scanned or pasted payload describes.
    ///
    /// Order matters, and each step fails with its own message: the
    /// unauthenticated health probe proves the address reaches a daemon (a
    /// mistyped host fails here, before any secret is sent), then the token is
    /// proven against `GET /api/services` *before* anything is saved — so a
    /// stale QR code fails loudly at pairing time instead of producing a saved
    /// credential that never works.
    func pair(with rawPayload: String, deviceName: String) async throws {
        let payload = try PairingPayload.parse(rawPayload)

        let probe = ServerCredential(
            name: payload.name, host: payload.host, port: payload.port,
            tls: payload.tls, fingerprint: payload.fingerprint, token: ""
        )
        guard try await AdminAPIClient(credential: probe).health() else {
            throw APIError.protocolViolation("the address answered, but not as a Self-Host daemon")
        }

        let token: String
        var serverName = payload.name
        switch payload.kind {
        case .admin:
            token = payload.token
        case .pairing:
            let response = try await AdminAPIClient.exchange(payload: payload, deviceName: deviceName)
            token = response.token
            if let offered = response.serverName, !offered.isEmpty {
                serverName = offered
            }
        }

        let candidate = ServerCredential(
            name: serverName,
            host: payload.host,
            port: payload.port,
            tls: payload.tls,
            fingerprint: payload.fingerprint,
            token: token
        )
        _ = try await AdminAPIClient(credential: candidate).services()

        try store.save(candidate)
        storageError = nil
        credential = candidate
    }

    /// Forgets the paired server and returns to the pairing screen.
    ///
    /// Throws if the Keychain refuses the delete: a credential the person asked
    /// to remove but which is still on the phone is worth a loud complaint.
    func unpair() throws {
        try store.delete()
        credential = nil
    }
}
