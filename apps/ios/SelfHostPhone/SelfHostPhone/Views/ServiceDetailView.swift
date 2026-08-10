//  ServiceDetailView.swift
//  SelfHostPhone
//
//  One service: its state, its definition, lifecycle controls, and a log tail.

import SwiftUI

/// The detail screen for one service, polling status and logs while visible.
struct ServiceDetailView: View {
    @StateObject private var viewModel: ServiceDetailViewModel
    private let serviceName: String

    /// A detail screen for `serviceName` on the given server.
    init(client: AdminAPIClient, serviceName: String) {
        self.serviceName = serviceName
        _viewModel = StateObject(
            wrappedValue: ServiceDetailViewModel(client: client, serviceName: serviceName)
        )
    }

    var body: some View {
        List {
            if let error = viewModel.lastError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .listRowBackground(Color.red.opacity(0.1))
            }

            if let detail = viewModel.detail {
                statusSection(detail.status)
                actionsSection(detail.status)
                specSection(detail.spec)
                logsSection
            } else {
                ProgressView("Loading…")
            }
        }
        .navigationTitle(viewModel.detail?.status.displayName ?? serviceName)
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await viewModel.refresh() }
        .task { await viewModel.poll() }
    }

    /// Current state, restart count, and any state-specific detail.
    private func statusSection(_ status: ServiceStatus) -> some View {
        Section("Status") {
            LabeledContent("State") { StateBadge(state: status.state) }
            if let detail = status.state.detail {
                LabeledContent("Detail", value: detail)
            }
            LabeledContent("Start mode", value: status.startMode.label)
            LabeledContent("Restarts", value: String(status.totalRestarts))
            if !status.description.isEmpty {
                Text(status.description)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Start / stop / restart, each enabled only when it can mean something.
    private func actionsSection(_ status: ServiceStatus) -> some View {
        Section("Actions") {
            HStack(spacing: 12) {
                actionButton(.start, disabled: status.state.isLive || status.startMode == .disabled)
                actionButton(.stop, disabled: !status.state.isLive)
                actionButton(.restart, disabled: status.startMode == .disabled)
            }
            .buttonStyle(.bordered)
        }
    }

    /// One lifecycle button, showing progress while its command is in flight.
    private func actionButton(_ action: ServiceAction, disabled: Bool) -> some View {
        Button {
            Task { await viewModel.perform(action) }
        } label: {
            if viewModel.actionInFlight == action {
                ProgressView()
            } else {
                Text(action.label).frame(maxWidth: .infinity)
            }
        }
        .disabled(disabled || viewModel.actionInFlight != nil)
    }

    /// How the service is configured, read-only.
    private func specSection(_ spec: ServiceSpec) -> some View {
        Section("Definition") {
            LabeledContent("Program", value: spec.program)
            if !spec.args.isEmpty {
                LabeledContent("Arguments", value: spec.args.joined(separator: " "))
            }
            if let cwd = spec.cwd {
                LabeledContent("Directory", value: cwd)
            }
            if let node = spec.node {
                LabeledContent("Node", value: node)
            }
            LabeledContent("Restart", value: spec.restart.label)
            LabeledContent("Restart delay", value: "\(spec.restartDelaySecs)s")
            LabeledContent(
                "Max restarts",
                value: spec.maxRestarts == 0 ? "Unlimited" : String(spec.maxRestarts)
            )
            LabeledContent("Stop timeout", value: "\(spec.stopTimeoutSecs)s")
            if let git = spec.git {
                LabeledContent("Repository", value: git.repository)
                LabeledContent("Branch", value: git.branch)
                LabeledContent("Auto-deploy", value: git.enabled && git.autoUpdate ? "On" : "Off")
            }
        }
        .font(.footnote)
    }

    /// The live log tail, newest at the bottom, with any gap declared.
    private var logsSection: some View {
        Section("Logs") {
            if viewModel.missedLines > 0 {
                Label(
                    "\(viewModel.missedLines) earlier lines were dropped before they could be fetched.",
                    systemImage: "scissors"
                )
                .font(.caption)
                .foregroundStyle(.orange)
            }
            if viewModel.logLines.isEmpty {
                Text("No output captured yet.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.logLines) { line in
                    Text(line.text)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(line.stream == .stderr ? .red : .primary)
                        .listRowInsets(EdgeInsets(top: 2, leading: 12, bottom: 2, trailing: 12))
                }
            }
        }
    }
}
