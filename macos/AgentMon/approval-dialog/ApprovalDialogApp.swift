// macos/AgentMon/approval-dialog/ApprovalDialogApp.swift
import SwiftUI

/// The macOS approvals UI.
///
/// The daemon opens one instance per request, with
/// `open -n -a approval-dialog.app --args agentmon-approval://approve?id=<id>`,
/// when approvals.mode is gui. The dialog fetches the request over the policy
/// socket, shows it, and sends the answer back the same way.
@main
struct ApprovalDialogApp: App {
    @State private var state: DialogState = .loading

    var body: some Scene {
        WindowGroup {
            content
                .onAppear {
                    NSApp.activate(ignoringOtherApps: true)
                    load(ApprovalURL.requestID(fromArguments: ProcessInfo.processInfo.arguments))
                }
                .onOpenURL { url in load(ApprovalURL.requestID(from: url)) }
        }
        .windowResizability(.contentSize)
        .windowStyle(.hiddenTitleBar)
        .commands { CommandGroup(replacing: .newItem) {} }
    }

    @ViewBuilder
    private var content: some View {
        switch state {
        case .loading:
            message(icon: nil, title: "Loading the request...", detail: nil)
        case .showing(let request):
            ApprovalView(request: request) { approved in answer(request, approved: approved) }
        case .sending:
            message(icon: nil, title: "Sending your answer...", detail: nil)
        case .failed(let detail):
            message(icon: "exclamationmark.triangle.fill", title: "The request cannot be answered", detail: detail)
        }
    }

    private func load(_ id: String?) {
        guard let id else {
            state = .failed("The dialog was started without a request ID.")
            return
        }
        state = .loading
        Task.detached {
            let next: DialogState
            do {
                if let request = try ApprovalClient().fetch(id: id) {
                    next = .showing(request)
                } else {
                    next = .failed("This request expired or someone already answered it.")
                }
            } catch {
                next = .failed(error.localizedDescription)
            }
            await MainActor.run { state = next }
        }
    }

    private func answer(_ request: ApprovalRequestData, approved: Bool) {
        state = .sending
        let reason = "\(approved ? "approved" : "denied") in the macOS approval dialog by \(NSUserName())"
        Task.detached {
            do {
                try ApprovalClient().resolve(id: request.id, approved: approved, reason: reason)
                await MainActor.run { NSApp.terminate(nil) }
            } catch {
                await MainActor.run { state = .failed(error.localizedDescription) }
            }
        }
    }

    private func message(icon: String?, title: String, detail: String?) -> some View {
        VStack(spacing: 14) {
            if let icon {
                Image(systemName: icon).font(.system(size: 40)).foregroundColor(.red)
            } else {
                ProgressView()
            }
            Text(title).font(.headline)
            if let detail {
                Text(detail)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                Button("Close") { NSApp.terminate(nil) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(28)
        .frame(width: 380)
    }
}

enum DialogState {
    case loading
    case showing(ApprovalRequestData)
    case sending
    case failed(String)
}
