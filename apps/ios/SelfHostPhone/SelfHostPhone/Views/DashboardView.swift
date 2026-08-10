//  DashboardView.swift
//  SelfHostPhone
//
//  The server dashboard: every service, its state, and quick actions.

import SwiftUI

/// Lists the paired server's services with live state, polling while visible.
struct DashboardView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var viewModel: DashboardViewModel
    @State private var confirmUnpair = false
    @State private var unpairError: String?

    /// A dashboard for the given paired server.
    init(credential: ServerCredential) {
        _viewModel = StateObject(
            wrappedValue: DashboardViewModel(client: AdminAPIClient(credential: credential))
        )
    }

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.isInitialLoad {
                    ProgressView("Connecting…")
                } else {
                    serviceList
                }
            }
            .navigationTitle(model.credential?.name ?? "Server")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Unpair", systemImage: "qrcode.viewfinder", role: .destructive) {
                        confirmUnpair = true
                    }
                }
            }
            .confirmationDialog(
                "Unpair from this server?",
                isPresented: $confirmUnpair,
                titleVisibility: .visible
            ) {
                Button("Unpair", role: .destructive) {
                    do {
                        try model.unpair()
                    } catch {
                        unpairError = error.localizedDescription
                    }
                }
            } message: {
                Text("The stored credential is removed from this phone. The server is not affected.")
            }
            .alert("Could not unpair", isPresented: .constant(unpairError != nil)) {
                Button("OK") { unpairError = nil }
            } message: {
                Text(unpairError ?? "")
            }
        }
        .task { await viewModel.poll() }
    }

    /// The list body: banners for trouble, then one row per service.
    private var serviceList: some View {
        List {
            if !viewModel.reachable {
                banner(
                    "Server unreachable — showing the last known state.",
                    systemImage: "wifi.slash", tint: .orange
                )
            } else if let error = viewModel.lastError {
                banner(error, systemImage: "exclamationmark.triangle.fill", tint: .red)
            }

            if viewModel.services.isEmpty {
                ContentUnavailableView(
                    "No services installed",
                    systemImage: "server.rack",
                    description: Text("Install services from the desktop console; they appear here.")
                )
            } else {
                ForEach(viewModel.sortedServices) { service in
                    NavigationLink(value: service.name) {
                        ServiceRow(service: service)
                    }
                    .swipeActions(edge: .trailing) {
                        swipeAction(for: service)
                    }
                }
            }
        }
        .navigationDestination(for: String.self) { name in
            ServiceDetailView(client: viewModel.client, serviceName: name)
        }
        .refreshable { await viewModel.refresh() }
    }

    /// The one swipe action that makes sense for the service's current state.
    @ViewBuilder
    private func swipeAction(for service: ServiceStatus) -> some View {
        if service.state.isLive {
            Button("Stop") {
                Task { await viewModel.perform(.stop, on: service.name) }
            }
            .tint(.orange)
        } else if service.startMode != .disabled {
            Button("Start") {
                Task { await viewModel.perform(.start, on: service.name) }
            }
            .tint(.green)
        }
    }

    /// An inline list banner for connection or command trouble.
    private func banner(_ message: String, systemImage: String, tint: Color) -> some View {
        Label(message, systemImage: systemImage)
            .font(.footnote)
            .foregroundStyle(tint)
            .listRowBackground(tint.opacity(0.1))
    }
}

/// One service in the list: name, state badge, and a line of detail.
struct ServiceRow: View {
    /// The service this row renders.
    let service: ServiceStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(service.displayName)
                    .font(.headline)
                Spacer()
                StateBadge(state: service.state)
            }
            if let detail = service.state.detail {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            } else if !service.description.isEmpty {
                Text(service.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
}

/// A coloured capsule naming a service's state.
struct StateBadge: View {
    /// The state being rendered.
    let state: ServiceState

    var body: some View {
        Text(state.label)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    /// Green for live, red for urgent, orange for transitional, grey otherwise.
    private var color: Color {
        switch state {
        case .running: return .green
        case .starting, .stopping, .backoff: return .orange
        case .gaveUp, .unstartable: return .red
        case .stopped, .disabled, .exited: return .secondary
        }
    }
}
