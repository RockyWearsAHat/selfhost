//  ServiceDetailViewModel.swift
//  SelfHostPhone
//
//  State behind one service's detail screen: status, spec, and a live log tail.

import Foundation

/// Loads one service's detail and tails its logs incrementally.
///
/// Logs use the API's resume-point protocol: each fetch asks for everything
/// after `nextSeq` from the previous slice, so polling transfers only new
/// lines. A non-zero `missed` means lines were evicted before we fetched them,
/// and that gap is shown rather than papered over.
@MainActor
final class ServiceDetailViewModel: ObservableObject {
    /// The service's current status and definition.
    @Published private(set) var detail: ServiceDetail?
    /// The tail of the service's output, oldest first.
    @Published private(set) var logLines: [LogLine] = []
    /// Lines lost to eviction since the tail began; non-zero means a gap.
    @Published private(set) var missedLines: UInt64 = 0
    /// The last failure worth showing, cleared by the next success.
    @Published private(set) var lastError: String?
    /// Which action is currently in flight, to disable its button.
    @Published private(set) var actionInFlight: ServiceAction?

    /// Seconds between automatic refreshes of status and logs.
    private static let pollInterval: Duration = .seconds(3)
    /// How many log lines the screen keeps; the ring on the phone mirrors the
    /// bounded ring on the daemon.
    private static let keptLines = 1_000

    private let client: AdminAPIClient
    private let serviceName: String
    /// The sequence to ask for next; nil until the first fetch anchors it.
    private var nextSeq: UInt64?

    /// A view model for the named service on the given server.
    init(client: AdminAPIClient, serviceName: String) {
        self.client = client
        self.serviceName = serviceName
    }

    /// Fetches the status/spec and any new log lines, once.
    func refresh() async {
        do {
            detail = try await client.service(named: serviceName)
            try await fetchNewLogs()
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Refreshes forever at the poll interval; cancel the task to stop.
    func poll() async {
        while !Task.isCancelled {
            await refresh()
            do {
                try await Task.sleep(for: Self.pollInterval)
            } catch {
                return // Cancelled while sleeping: the view is gone.
            }
        }
    }

    /// Sends a lifecycle command, then refreshes so the outcome shows promptly.
    func perform(_ action: ServiceAction) async {
        actionInFlight = action
        defer { actionInFlight = nil }
        do {
            try await client.perform(action, on: serviceName)
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
    }

    /// Appends everything after the resume point to the kept tail.
    ///
    /// The first fetch starts a bounded distance back rather than at zero, so
    /// opening a long-running service does not pull its whole history over a
    /// slow link before showing anything.
    private func fetchNewLogs() async throws {
        let from: UInt64
        if let nextSeq {
            from = nextSeq
        } else {
            let latest = detail?.status.logSeq ?? 0
            from = latest > UInt64(Self.keptLines) ? latest - UInt64(Self.keptLines) : 0
        }

        let slice = try await client.logs(for: serviceName, from: from, limit: Self.keptLines)
        nextSeq = slice.nextSeq
        missedLines += slice.missed
        guard !slice.lines.isEmpty else { return }
        logLines.append(contentsOf: slice.lines)
        if logLines.count > Self.keptLines {
            logLines.removeFirst(logLines.count - Self.keptLines)
        }
    }
}
