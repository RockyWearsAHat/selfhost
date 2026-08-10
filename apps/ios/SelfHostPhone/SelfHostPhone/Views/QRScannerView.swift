//  QRScannerView.swift
//  SelfHostPhone
//
//  The camera view that reads pairing QR codes, wrapping VisionKit's scanner.

import SwiftUI
import VisionKit

/// A live camera view recognising QR codes and reporting their string payloads.
///
/// Reports every recognised code once via `onScan`; the pairing screen decides
/// what a valid payload is. Reports scanner-start failures via `onError`
/// instead of failing silently — a camera that never starts must say so.
struct QRScannerView: UIViewControllerRepresentable {
    /// Called once per newly recognised QR code, with its string payload.
    let onScan: (String) -> Void
    /// Called when the scanner cannot start (no permission, camera in use).
    let onError: (String) -> Void

    /// Whether this device and its current camera-permission state allow
    /// scanning at all. When false, the pairing screen offers paste-only.
    static var isUsable: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        guard !scanner.isScanning else { return }
        do {
            try scanner.startScanning()
        } catch {
            onError("The camera could not start: \(error.localizedDescription)")
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan)
    }

    /// Receives recognition callbacks and forwards each code exactly once.
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onScan: (String) -> Void
        /// Payloads already reported, so a code held in frame fires once.
        private var seen = Set<String>()

        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            for item in addedItems {
                guard case .barcode(let barcode) = item,
                      let payload = barcode.payloadStringValue,
                      seen.insert(payload).inserted
                else { continue }
                onScan(payload)
            }
        }
    }
}
