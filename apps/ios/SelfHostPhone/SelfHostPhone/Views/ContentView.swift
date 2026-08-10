//  ContentView.swift
//  SelfHostPhone
//
//  Routes between the two lives of the app: pairing, and the dashboard.

import SwiftUI

/// Shows the dashboard when a server is paired, the pairing flow otherwise.
struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let credential = model.credential {
            // Identified by the credential so re-pairing with a different
            // server rebuilds the dashboard (and its client) from scratch
            // instead of polling the old one.
            DashboardView(credential: credential)
                .id(credential)
        } else {
            PairingView()
        }
    }
}
