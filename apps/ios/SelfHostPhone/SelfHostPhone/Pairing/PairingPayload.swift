//  PairingPayload.swift
//  SelfHostPhone
//
//  The payload a pairing QR code (or pasted pairing string) carries.
//
//  The format is a contract with the server side; it is documented in
//  `apps/ios/PAIRING.md`. Two encodings are accepted — a JSON object and a
//  `selfhost-pair://` URL — because a QR code prefers the compact URL while a
//  human pasting over chat prefers readable JSON.

import Foundation

/// What kind of secret the payload carries.
enum PairingTokenKind: String {
    /// The daemon's `data/admin.token` verbatim: a long-lived credential the
    /// app can use directly. Works against today's server with no new endpoints.
    case admin
    /// A short-lived, single-use token to be exchanged for a long-lived one via
    /// `POST /api/pair` (a server endpoint specified in PAIRING.md).
    case pairing
}

/// Why a pairing string could not be understood.
enum PairingParseError: LocalizedError, Equatable {
    /// The text is neither the URL form nor a JSON object.
    case unrecognised
    /// The payload parsed but a required field is missing or empty.
    case missingField(String)
    /// A field parsed but its value is unusable.
    case invalidField(String, reason: String)

    var errorDescription: String? {
        switch self {
        case .unrecognised:
            return "This is not a Self-Host pairing code. Expected a selfhost-pair:// link or a JSON object."
        case .missingField(let field):
            return "The pairing code is missing \"\(field)\"."
        case .invalidField(let field, let reason):
            return "The pairing code's \"\(field)\" is invalid: \(reason)."
        }
    }
}

/// Everything the app needs to reach and authenticate against one server.
struct PairingPayload: Equatable {
    /// The URL scheme the compact form uses.
    static let urlScheme = "selfhost-pair"
    /// The only payload version this app understands.
    static let supportedVersion = 1

    /// Host the admin API is reachable at from the phone (LAN address,
    /// VPN/Tailscale address, or a gateway's hostname).
    let host: String
    /// TCP port of the admin API; the daemon's default is 9191.
    let port: UInt16
    /// The secret, interpreted per `kind`.
    let token: String
    /// How to interpret `token`.
    let kind: PairingTokenKind
    /// A human name for the server, shown in the app. Falls back to the host.
    let name: String
    /// Whether to speak HTTPS. Plain HTTP is for tunnelled/VPN transports only.
    let tls: Bool
    /// SHA-256 of the server's leaf certificate in DER form, as 64 hex
    /// characters. When present (and `tls` is on), the connection is refused
    /// unless the presented certificate matches — trust on first scan.
    let fingerprint: String?

    /// Parses either accepted encoding, trying the URL form first.
    ///
    /// Throws `PairingParseError` describing exactly what was wrong, so the
    /// pairing screen can tell the person what to fix rather than shrugging.
    static func parse(_ raw: String) throws -> PairingPayload {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw PairingParseError.unrecognised }
        if trimmed.lowercased().hasPrefix("\(urlScheme)://") {
            return try parseURL(trimmed)
        }
        if trimmed.hasPrefix("{") {
            return try parseJSON(trimmed)
        }
        throw PairingParseError.unrecognised
    }

    /// Parses the compact form:
    /// `selfhost-pair://v1/?host=…&port=…&token=…&kind=…&name=…&tls=1&fp=…`.
    private static func parseURL(_ text: String) throws -> PairingPayload {
        guard let components = URLComponents(string: text) else {
            throw PairingParseError.unrecognised
        }
        guard components.host == "v\(supportedVersion)" else {
            throw PairingParseError.invalidField(
                "version", reason: "expected v\(supportedVersion), got \"\(components.host ?? "")\""
            )
        }
        var fields: [String: String] = [:]
        for item in components.queryItems ?? [] {
            fields[item.name] = item.value
        }
        return try build(
            host: fields["host"],
            port: fields["port"],
            token: fields["token"],
            kind: fields["kind"],
            name: fields["name"],
            tls: fields["tls"].map { $0 == "1" || $0 == "true" },
            fingerprint: fields["fp"]
        )
    }

    /// Parses the readable form: a JSON object with `"type":"selfhost-pair"`.
    private static func parseJSON(_ text: String) throws -> PairingPayload {
        guard
            let data = text.data(using: .utf8),
            let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw PairingParseError.unrecognised
        }
        guard object["type"] as? String == "selfhost-pair" else {
            throw PairingParseError.unrecognised
        }
        guard let version = object["v"] as? Int, version == supportedVersion else {
            throw PairingParseError.invalidField("v", reason: "expected \(supportedVersion)")
        }
        return try build(
            host: object["host"] as? String,
            port: (object["port"] as? Int).map(String.init),
            token: object["token"] as? String,
            kind: object["tokenKind"] as? String,
            name: object["name"] as? String,
            tls: object["tls"] as? Bool,
            fingerprint: object["fingerprint"] as? String
        )
    }

    /// Validates the raw fields both encodings reduce to, and builds the payload.
    private static func build(
        host: String?,
        port: String?,
        token: String?,
        kind: String?,
        name: String?,
        tls: Bool?,
        fingerprint: String?
    ) throws -> PairingPayload {
        guard let host, !host.isEmpty else { throw PairingParseError.missingField("host") }
        guard let portText = port, !portText.isEmpty else { throw PairingParseError.missingField("port") }
        guard let portNumber = UInt16(portText), portNumber > 0 else {
            throw PairingParseError.invalidField("port", reason: "\"\(portText)\" is not a port number")
        }
        guard let token, !token.isEmpty else { throw PairingParseError.missingField("token") }
        let tokenKind: PairingTokenKind
        switch kind {
        case nil, "":
            tokenKind = .admin
        case let text?:
            guard let parsed = PairingTokenKind(rawValue: text) else {
                throw PairingParseError.invalidField("kind", reason: "expected \"admin\" or \"pairing\"")
            }
            tokenKind = parsed
        }
        let useTLS = tls ?? false
        let normalisedFingerprint = try normaliseFingerprint(fingerprint)
        if normalisedFingerprint != nil && !useTLS {
            throw PairingParseError.invalidField(
                "fingerprint", reason: "a certificate fingerprint is meaningless without tls"
            )
        }
        return PairingPayload(
            host: host,
            port: portNumber,
            token: token,
            kind: tokenKind,
            name: (name?.isEmpty == false ? name! : host),
            tls: useTLS,
            fingerprint: normalisedFingerprint
        )
    }

    /// Lower-cases a fingerprint and strips separators, refusing anything that
    /// is not 64 hex characters — a truncated fingerprint would pin nothing.
    private static func normaliseFingerprint(_ raw: String?) throws -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        let cleaned = raw.lowercased().replacingOccurrences(of: ":", with: "")
        guard cleaned.count == 64, cleaned.allSatisfy(\.isHexDigit) else {
            throw PairingParseError.invalidField(
                "fingerprint", reason: "expected 64 hex characters (SHA-256 of the DER certificate)"
            )
        }
        return cleaned
    }
}
