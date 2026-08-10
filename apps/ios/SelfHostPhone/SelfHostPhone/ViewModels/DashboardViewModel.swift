//  DashboardViewModel.swift
//  SelfHostPhone
//
//  State behind the services dashboard: the list, its freshness, and polling.

import Foundation

/// Loads and periodically refreshes the service list for the dashboard.
///
/// Polling mirrors the desktop console's model: lifecycle commands are
/// acknowledged asynchronously by the daemon, so the only way to learn the
/// outcome — or about state changes nobody asked for — is to keep asking.
@MainActor
final class DashboardViewModel: ObservableObject {
    /// Every installed service, as of the last successful refresh.
    @Published private(set) var services: [ServiceStatus] = []
    /// Whether the server is currently reachable.
    ///
    /// Stale data stays on screen while this is false: a dropped VPN must not
    /// blank the dashboard the operator is looking at.
    @Published private(set) var reachable = true
    /// The last failure worth showing, cleared by the next success.
    @Published private(set) var lastError: String?
    /// Whether the very first load is still in flight, to drive a spinner.
    @Published private(set) var isInitialLoad = true

    /// Seconds between automatic refreshes.
    private static let pollInterval: Duration = .seconds(5)

    /// The server's client, shared with detail screens so navigation does not
    /// rebuild sessions (and re-run TLS pinning setup) per push.
    let client: AdminAPIClient

    /// A view model polling the given server.
    init(client: AdminAPIClient) {
        self.client = client
    }

    /// Fetches the service list once, updating reachability and error state.
    func refresh() async {
        do {
            services = try await client.services()
            reachable = true
            lastError = nil
        } catch let error as APIError {
            reachable = !error.isDisconnection
            lastError = error.localizedDescription
        } catch {
            lastError = error.localizedDescription
        }
        isInitialLoad = false
    }

    /// Refreshes forever at the poll interval; cancel the task to stop.
    ///
    /// Meant to be owned by `.task` on the dashboard view, so polling stops
    /// automatically when the view leaves the screen.
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

    /// Sends a lifecycle command, then refreshes so the change shows promptly.
    func perform(_ action: ServiceAction, on name: String) async {
        do {
            try await client.perform(action, on: name)
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
    }

    /// The services that need attention first, then the rest, both by name.
    ///
    /// A service the supervisor gave up on must not be alphabetically buried
    /// under twelve healthy ones.
    var sortedServices: [ServiceStatus] {
        services.sorted { a, b in
            if a.state.needsAttention != b.state.needsAttention {
                return a.state.needsAttention
            }
            return a.displayName.localizedCaseInsensitiveCompare(b.displayName) == .orderedAscending
        }
    }
}
