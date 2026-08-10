//  SelfHostPhoneApp.swift
//  SelfHostPhone
//
//  Entry point: owns the root model and hands it to the view tree.

import SwiftUI

/// The application. One window group, one root model.
@main
struct SelfHostPhoneApp: App {
    /// Root state: created once for the app's lifetime.
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
        }
    }
}
