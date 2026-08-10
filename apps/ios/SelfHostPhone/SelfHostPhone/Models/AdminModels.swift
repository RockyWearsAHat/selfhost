//  AdminModels.swift
//  SelfHostPhone
//
//  Swift mirrors of the daemon's admin API wire format.
//
//  The shapes here are a contract with `crates/admin` and
//  `crates/supervisor/src/state.rs` (`ServiceStatus::to_json`,
//  `ServiceState::to_json`, `spec_to_json`, `LogSlice::to_json`). They must
//  change only when the Rust side does, and deliberately: a field renamed here
//  silently stops decoding there.

import Foundation

/// When a service starts, as the wire names it (`startMode`).
enum StartMode: String, Decodable {
    /// Started when the daemon starts.
    case automatic
    /// Started only when asked, but supervised once running.
    case manual
    /// Never started; start requests are refused.
    case disabled

    /// A short label for display.
    var label: String {
        switch self {
        case .automatic: return "Automatic"
        case .manual: return "Manual"
        case .disabled: return "Disabled"
        }
    }
}

/// What the daemon does when a service exits, as the wire names it (`restart`).
enum RestartPolicy: String, Decodable {
    /// Leave it stopped however it exited.
    case never
    /// Restart only on a non-zero exit or a signal.
    case onFailure = "on-failure"
    /// Restart on any exit.
    case always

    /// A short label for display.
    var label: String {
        switch self {
        case .never: return "Never"
        case .onFailure: return "On failure"
        case .always: return "Always"
        }
    }
}

/// The lifecycle position of one service, mirroring the Rust `ServiceState`.
///
/// The wire encodes this flat: a `state` discriminant plus state-specific
/// fields alongside it, so decoding reads from the same keyed container as the
/// surrounding status object.
enum ServiceState: Equatable {
    /// Not running, and not trying to.
    case stopped
    /// Configured never to run.
    case disabled
    /// Spawning.
    case starting
    /// Up, with its process id and seconds of uptime.
    case running(pid: UInt32, uptimeSecs: UInt64)
    /// Asked to stop, waiting for it to comply.
    case stopping
    /// Exited and will not be restarted. `code` is absent when killed by a signal.
    case exited(code: Int32?)
    /// Waiting out a backoff delay before the next restart attempt.
    case backoff(retryInSecs: UInt64, attempt: UInt32)
    /// Failed too many times in a row; the supervisor stopped trying.
    case gaveUp(attempts: UInt32, reason: String)
    /// Could not be started at all — a bad path, or no permission.
    case unstartable(reason: String)

    /// Whether a process currently exists for this service.
    var isLive: Bool {
        switch self {
        case .starting, .running, .stopping: return true
        default: return false
        }
    }

    /// Whether this state needs the operator's attention.
    ///
    /// "Stopped" and "gave up" both mean no process, but only one is urgent,
    /// and the dashboard must not render them the same way.
    var needsAttention: Bool {
        switch self {
        case .gaveUp, .unstartable: return true
        default: return false
        }
    }

    /// A short label for a row or badge.
    var label: String {
        switch self {
        case .stopped: return "Stopped"
        case .disabled: return "Disabled"
        case .starting: return "Starting"
        case .running: return "Running"
        case .stopping: return "Stopping"
        case .exited: return "Exited"
        case .backoff: return "Restarting"
        case .gaveUp: return "Gave up"
        case .unstartable: return "Cannot start"
        }
    }

    /// A one-line elaboration on the label, when the state carries detail.
    var detail: String? {
        switch self {
        case .running(let pid, let uptime):
            return "pid \(pid) · up \(Self.formatUptime(uptime))"
        case .exited(let code):
            return code.map { "exit code \($0)" } ?? "killed by a signal"
        case .backoff(let retry, let attempt):
            return "attempt \(attempt), retrying in \(retry)s"
        case .gaveUp(let attempts, let reason):
            return "after \(attempts) attempts: \(reason)"
        case .unstartable(let reason):
            return reason
        case .stopped, .disabled, .starting, .stopping:
            return nil
        }
    }

    /// Renders seconds of uptime as the largest two useful units.
    private static func formatUptime(_ seconds: UInt64) -> String {
        let (d, h, m, s) = (seconds / 86_400, seconds % 86_400 / 3_600, seconds % 3_600 / 60, seconds % 60)
        if d > 0 { return "\(d)d \(h)h" }
        if h > 0 { return "\(h)h \(m)m" }
        if m > 0 { return "\(m)m \(s)s" }
        return "\(s)s"
    }
}

extension ServiceState: Decodable {
    private enum Keys: String, CodingKey {
        case state, pid, uptimeSecs, code, retryInSecs, attempt, attempts, reason
    }

    /// Decodes the flat wire form: `state` plus that state's own fields.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        let tag = try container.decode(String.self, forKey: .state)
        switch tag {
        case "stopped": self = .stopped
        case "disabled": self = .disabled
        case "starting": self = .starting
        case "stopping": self = .stopping
        case "running":
            self = .running(
                pid: try container.decode(UInt32.self, forKey: .pid),
                uptimeSecs: try container.decode(UInt64.self, forKey: .uptimeSecs)
            )
        case "exited":
            self = .exited(code: try container.decodeIfPresent(Int32.self, forKey: .code))
        case "backoff":
            self = .backoff(
                retryInSecs: try container.decode(UInt64.self, forKey: .retryInSecs),
                attempt: try container.decode(UInt32.self, forKey: .attempt)
            )
        case "gave-up":
            self = .gaveUp(
                attempts: try container.decode(UInt32.self, forKey: .attempts),
                reason: try container.decode(String.self, forKey: .reason)
            )
        case "unstartable":
            self = .unstartable(reason: try container.decode(String.self, forKey: .reason))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .state, in: container,
                debugDescription: "unknown service state \"\(tag)\""
            )
        }
    }
}

/// A service and its current state, as `GET /api/services` lists them.
struct ServiceStatus: Decodable, Identifiable, Equatable {
    /// The service's identifier, unique across the catalogue.
    let name: String
    /// The name to display; the daemon falls back to `name`.
    let displayName: String
    /// What the operator wrote about it.
    let description: String
    /// Where it is in its lifecycle.
    let state: ServiceState
    /// How it is configured to start.
    let startMode: StartMode
    /// Total restarts since the daemon started.
    let totalRestarts: UInt64
    /// Sequence number of the newest captured log line.
    let logSeq: UInt64

    var id: String { name }

    private enum Keys: String, CodingKey {
        case name, displayName, description, startMode, totalRestarts, logSeq
    }

    /// Decodes the flat status object; the state reads from the same container.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        name = try container.decode(String.self, forKey: .name)
        displayName = try container.decodeIfPresent(String.self, forKey: .displayName) ?? name
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        startMode = try container.decodeIfPresent(StartMode.self, forKey: .startMode) ?? .manual
        totalRestarts = try container.decodeIfPresent(UInt64.self, forKey: .totalRestarts) ?? 0
        logSeq = try container.decodeIfPresent(UInt64.self, forKey: .logSeq) ?? 0
        state = try ServiceState(from: decoder)
    }
}

/// The envelope `GET /api/services` answers with.
struct ServicesResponse: Decodable {
    /// Every installed service with its current state.
    let services: [ServiceStatus]
}

/// A Git watch attached to a service, as `spec_to_json` writes it.
struct GitWatch: Decodable, Equatable {
    /// The repository being watched.
    let repository: String
    /// The branch whose movement redeploys the service.
    let branch: String
    /// Where the working copy lives, relative to the daemon's data directory.
    let path: String
    /// Seconds between polls.
    let intervalSecs: UInt64
    /// Whether the watch is switched on.
    let enabled: Bool
    /// Whether a moved branch is deployed automatically.
    let autoUpdate: Bool
}

/// A service definition, as `GET /api/services/{name}` describes it.
///
/// Read-only on the phone: the app displays how a service is configured but
/// does not install or edit definitions — that stays with the desktop console.
struct ServiceSpec: Decodable, Equatable {
    /// Identifier, unique across the catalogue.
    let name: String
    /// The executable the daemon runs.
    let program: String
    /// Arguments passed to the program, already split.
    let args: [String]
    /// Extra environment variables set for the process.
    let env: [String: String]
    /// Directory the process runs in, when one is set.
    let cwd: String?
    /// Which machine runs this service, when pinned.
    let node: String?
    /// When the service starts.
    let startMode: StartMode
    /// What the daemon does when it exits.
    let restart: RestartPolicy
    /// Seconds before the first restart attempt.
    let restartDelaySecs: UInt64
    /// Consecutive failed restarts before the supervisor gives up. Zero means never.
    let maxRestarts: UInt32
    /// Seconds to wait for a graceful stop before killing the process.
    let stopTimeoutSecs: UInt64
    /// A command that asks the service to shut down cleanly, when one is named.
    let stopCommand: [String]?
    /// The Git watch that redeploys this service, when it has one.
    let git: GitWatch?
}

/// The answer to `GET /api/services/{name}`: state plus definition.
struct ServiceDetail: Decodable, Equatable {
    /// What the service is doing right now.
    let status: ServiceStatus
    /// How it is configured.
    let spec: ServiceSpec
}

/// Which stream produced a log line.
enum LogStream: String, Decodable {
    case stdout
    case stderr
}

/// One captured line of a service's output.
struct LogLine: Decodable, Identifiable, Equatable {
    /// Monotonic position in this service's output, never reused.
    let seq: UInt64
    /// Which stream produced it.
    let stream: LogStream
    /// The text, with any trailing newline removed.
    let text: String

    var id: UInt64 { seq }
}

/// The answer to `GET /api/services/{name}/logs?from=N`: everything after N.
struct LogSlice: Decodable, Equatable {
    /// Lines in order, oldest first.
    let lines: [LogLine]
    /// Sequence to ask for next time.
    let nextSeq: UInt64
    /// Lines evicted before the reader got to them; non-zero means a gap.
    let missed: UInt64
}

/// A lifecycle command the API accepts via `POST /api/services/{name}/{action}`.
enum ServiceAction: String, CaseIterable {
    case start
    case stop
    case restart

    /// A short label for a button.
    var label: String { rawValue.capitalized }
}

/// The 202 acknowledgement of a lifecycle command.
///
/// The daemon accepts the command; it does not await the outcome. The app
/// polls the status afterwards, which it must do anyway for state changes
/// nobody asked for.
struct ActionReceipt: Decodable {
    /// The action that was accepted.
    let accepted: String
    /// The service it applies to.
    let service: String
}

/// One field-level validation failure, as a 422 lists them.
struct APIProblem: Decodable, Equatable {
    /// Dotted path to the offending field.
    let field: String
    /// What is wrong with it.
    let message: String
}
