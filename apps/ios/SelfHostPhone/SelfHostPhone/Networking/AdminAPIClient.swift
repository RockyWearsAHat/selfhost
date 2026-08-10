//  AdminAPIClient.swift
//  SelfHostPhone
//
//  The async HTTP client for the daemon's admin API.
//
//  Paths, methods, auth, and response shapes mirror `crates/admin/src/lib.rs`
//  exactly. Error bodies are `{"error": "…"}` (or `{"problems": […]}` on 422),
//  and both are surfaced verbatim: the daemon's explanations are written for
//  the operator, and this app's job is to deliver them, not rewrite them.

import CryptoKit
import Foundation

/// Why an API call did not produce an answer.
enum APIError: LocalizedError {
    /// The credential's host/port do not form a URL.
    case invalidBaseURL
    /// The network layer failed: unreachable, timed out, TLS refused, and so on.
    case transport(Error)
    /// The reply was not HTTP, or its body was not the JSON the API sends.
    case protocolViolation(String)
    /// The daemon answered, and said no. Carries its own explanation.
    case refused(status: Int, message: String)
    /// A 422: the daemon listed field-level problems with what was sent.
    case validation([APIProblem])

    var errorDescription: String? {
        switch self {
        case .invalidBaseURL:
            return "The stored server address is not usable. Re-pair with the server."
        case .transport(let error):
            return "Cannot reach the server: \(error.localizedDescription)"
        case .protocolViolation(let detail):
            return "Unexpected reply: \(detail)"
        case .refused(let status, let message):
            return "The server refused (\(status)): \(message)"
        case .validation(let problems):
            let listed = problems.map { "\($0.field): \($0.message)" }.joined(separator: "; ")
            return "The server rejected the request: \(listed)"
        }
    }

    /// Whether this means the server is unreachable, as opposed to unhappy.
    ///
    /// Drives the dashboard: a refused command leaves the connection banner
    /// alone, while a dead transport flips the whole screen to "unreachable".
    var isDisconnection: Bool {
        if case .transport = self { return true }
        return false
    }
}

/// Pins the server's TLS certificate to a SHA-256 fingerprint from pairing.
///
/// A self-hosted server's certificate is usually self-signed, so the system
/// trust store would refuse it; the fingerprint scanned at pairing time is the
/// trust anchor instead — the same trust-on-first-use model as SSH host keys.
final class PinnedCertificateDelegate: NSObject, URLSessionDelegate {
    /// The expected SHA-256 of the server's DER leaf certificate.
    private let expectedFingerprint: Data

    /// Builds a delegate from 64 hex characters, or `nil` if they are not hex.
    init?(fingerprintHex: String) {
        guard let data = Data(hexString: fingerprintHex), data.count == 32 else { return nil }
        self.expectedFingerprint = data
    }

    /// Accepts the connection only when the presented leaf matches the pin.
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard
            challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let trust = challenge.protectionSpace.serverTrust,
            let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
            let leaf = chain.first
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let presented = Data(SHA256.hash(data: SecCertificateCopyData(leaf) as Data))
        if presented == expectedFingerprint {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

private extension Data {
    /// Parses lowercase/uppercase hex into bytes; `nil` for non-hex input.
    init?(hexString: String) {
        let characters = Array(hexString)
        guard characters.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(characters.count / 2)
        for index in stride(from: 0, to: characters.count, by: 2) {
            guard let byte = UInt8(String(characters[index...index + 1]), radix: 16) else {
                return nil
            }
            bytes.append(byte)
        }
        self.init(bytes)
    }
}

/// A client for one paired server's admin API.
struct AdminAPIClient {
    /// The server this client talks to.
    let credential: ServerCredential

    private let session: URLSession
    private let decoder = JSONDecoder()

    /// How long a request may take before it fails as a transport error.
    /// Generous compared to loopback, because the phone reaches the server
    /// over a VPN or gateway — the same request over a much longer wire.
    private static let requestTimeout: TimeInterval = 10

    /// Builds a client, wiring in certificate pinning when the credential pins.
    init(credential: ServerCredential) {
        self.credential = credential
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = Self.requestTimeout
        configuration.waitsForConnectivity = false
        let delegate = credential.fingerprint.flatMap(PinnedCertificateDelegate.init(fingerprintHex:))
        self.session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    // MARK: - Endpoints

    /// `GET /api/health` — whether a daemon is listening. Unauthenticated by
    /// design, so it proves reachability without proving the token.
    func health() async throws -> Bool {
        struct Health: Decodable { let ok: Bool }
        let data = try await send("GET", "/api/health", authenticated: false)
        return try decode(Health.self, from: data).ok
    }

    /// `GET /api/services` — every installed service with its current state.
    func services() async throws -> [ServiceStatus] {
        let data = try await send("GET", "/api/services")
        return try decode(ServicesResponse.self, from: data).services
    }

    /// `GET /api/services/{name}` — one service's state and full definition.
    func service(named name: String) async throws -> ServiceDetail {
        let data = try await send("GET", "/api/services/\(escape(name))")
        return try decode(ServiceDetail.self, from: data)
    }

    /// `GET /api/services/{name}/logs?from=N&limit=M` — output after sequence
    /// N, oldest first, with the sequence to ask for next time.
    func logs(for name: String, from: UInt64, limit: Int = 500) async throws -> LogSlice {
        let data = try await send(
            "GET", "/api/services/\(escape(name))/logs",
            query: [URLQueryItem(name: "from", value: String(from)),
                    URLQueryItem(name: "limit", value: String(limit))]
        )
        return try decode(LogSlice.self, from: data)
    }

    /// `POST /api/services/{name}/{start|stop|restart}` — asks for a lifecycle
    /// change. The 202 receipt means accepted, not done; poll for the outcome.
    @discardableResult
    func perform(_ action: ServiceAction, on name: String) async throws -> ActionReceipt {
        let data = try await send("POST", "/api/services/\(escape(name))/\(action.rawValue)")
        return try decode(ActionReceipt.self, from: data)
    }

    // MARK: - Pairing exchange

    /// The answer to a successful `POST /api/pair`.
    struct PairResponse: Decodable {
        /// The long-lived device token to store in the Keychain.
        let token: String
        /// The server's human name, when it offers one.
        let serverName: String?
    }

    /// `POST /api/pair` — exchanges a single-use pairing token for a
    /// long-lived device token.
    ///
    /// This endpoint does not exist on the server yet; its contract is
    /// specified in `apps/ios/PAIRING.md`. The app implements the exchange now
    /// so `tokenKind: "pairing"` QR codes work the moment the server lands it.
    /// Until then, `tokenKind: "admin"` codes work against today's API.
    static func exchange(payload: PairingPayload, deviceName: String) async throws -> PairResponse {
        let probe = ServerCredential(
            name: payload.name, host: payload.host, port: payload.port,
            tls: payload.tls, fingerprint: payload.fingerprint, token: ""
        )
        let client = AdminAPIClient(credential: probe)
        let body: [String: Any] = [
            "pairingToken": payload.token,
            "device": ["name": deviceName, "platform": "ios"],
        ]
        let data = try await client.send(
            "POST", "/api/pair",
            body: try JSONSerialization.data(withJSONObject: body),
            authenticated: false
        )
        return try client.decode(PairResponse.self, from: data)
    }

    // MARK: - Plumbing

    /// Escapes a service name for use as one path segment.
    ///
    /// The daemon restricts names to letters, digits, dot, dash, underscore, so
    /// this is belt-and-braces rather than load-bearing — but a client must not
    /// rely on a server-side rule to keep its own URLs well-formed.
    private func escape(_ segment: String) -> String {
        segment.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? segment
    }

    /// Sends one request and returns the body of a 2xx reply, or throws the
    /// daemon's own explanation for anything else.
    private func send(
        _ method: String,
        _ path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil,
        authenticated: Bool = true
    ) async throws -> Data {
        guard let base = credential.baseURL,
              var components = URLComponents(url: base, resolvingAgainstBaseURL: false)
        else {
            throw APIError.invalidBaseURL
        }
        components.path = path
        if !query.isEmpty {
            components.queryItems = query
        }
        guard let url = components.url else { throw APIError.invalidBaseURL }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if authenticated {
            request.setValue("Bearer \(credential.token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw APIError.transport(error)
        }
        guard let http = response as? HTTPURLResponse else {
            throw APIError.protocolViolation("the reply was not HTTP")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw refusal(status: http.statusCode, body: data)
        }
        return data
    }

    /// Turns a non-2xx body into the most specific error it supports.
    private func refusal(status: Int, body: Data) -> APIError {
        struct ErrorBody: Decodable { let error: String }
        struct ProblemBody: Decodable { let problems: [APIProblem] }
        if let problems = try? decoder.decode(ProblemBody.self, from: body) {
            return .validation(problems.problems)
        }
        if let explained = try? decoder.decode(ErrorBody.self, from: body) {
            return .refused(status: status, message: explained.error)
        }
        return .refused(status: status, message: HTTPURLResponse.localizedString(forStatusCode: status))
    }

    /// Decodes a 2xx body, reporting a shape mismatch as a protocol violation
    /// rather than a crash or a silent nil.
    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try decoder.decode(type, from: data)
        } catch {
            throw APIError.protocolViolation("the body did not match \(type): \(error.localizedDescription)")
        }
    }
}
