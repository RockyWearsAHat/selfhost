//  PairingView.swift
//  SelfHostPhone
//
//  The pairing flow: scan the server's QR code, or paste the pairing string.

import SwiftUI
import UIKit

/// Pairs the phone with a server by QR scan or manual paste.
///
/// Both inputs funnel into the same `AppModel.pair`, so the validation, the
/// token exchange, and the "prove it works before saving" rule are identical
/// regardless of how the payload arrived.
struct PairingView: View {
    /// How the pairing payload is being entered.
    private enum Mode: String, CaseIterable {
        case scan = "Scan"
        case paste = "Paste"
    }

    @EnvironmentObject private var model: AppModel
    @State private var mode: Mode = QRScannerView.isUsable ? .scan : .paste
    @State private var pastedPayload = ""
    @State private var errorMessage: String?
    @State private var isPairing = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Picker("Input", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { Text($0.rawValue) }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)

                switch mode {
                case .scan: scanner
                case .paste: pasteEntry
                }

                if isPairing {
                    ProgressView("Pairing…")
                }
                if let storageError = model.storageError {
                    errorBanner(storageError)
                }
                if let errorMessage {
                    errorBanner(errorMessage)
                }
                Spacer(minLength: 0)
            }
            .navigationTitle("Pair with Server")
        }
    }

    /// The camera scanner, or an explanation of why it is unavailable.
    @ViewBuilder
    private var scanner: some View {
        if QRScannerView.isUsable {
            QRScannerView(
                onScan: { payload in pair(with: payload) },
                onError: { message in errorMessage = message }
            )
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .padding(.horizontal)
            .frame(maxHeight: 420)
            Text("Point the camera at the pairing QR code shown by your server.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            ContentUnavailableView(
                "Camera unavailable",
                systemImage: "camera.fill",
                description: Text("Scanning needs camera access on a device that supports it. Use Paste instead.")
            )
        }
    }

    /// The manual path: paste the same payload the QR code carries.
    private var pasteEntry: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Paste the pairing string — a selfhost-pair:// link or the JSON your server printed.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            TextEditor(text: $pastedPayload)
                .font(.system(.footnote, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .frame(minHeight: 140)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(.quaternary))
            Button("Pair") {
                pair(with: pastedPayload)
            }
            .buttonStyle(.borderedProminent)
            .disabled(pastedPayload.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isPairing)
        }
        .padding(.horizontal)
    }

    /// A dismiss-less error banner; the next attempt replaces it.
    private func errorBanner(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.footnote)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal)
    }

    /// Runs the pairing flow once, serialising attempts.
    private func pair(with payload: String) {
        guard !isPairing else { return }
        isPairing = true
        errorMessage = nil
        Task {
            defer { isPairing = false }
            do {
                try await model.pair(with: payload, deviceName: UIDevice.current.name)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}
