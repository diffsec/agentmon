// macos/AgentMon/approval-dialog/ApprovalDialogApp.swift
import AppKit
import Combine
import SwiftUI

/// The macOS approvals UI.
///
/// The daemon opens one instance per request, with
/// `open -n -a approval-dialog.app --args agentmon-approval://approve?id=<id>`,
/// when approvals.mode is gui. The dialog fetches the request over the policy
/// socket, shows it, and sends the answer back the same way.
///
/// The window is made in AppKit by DialogAppDelegate, not by a SwiftUI
/// WindowGroup. The daemon launches the dialog from a LaunchAgent, and macOS
/// does not activate an app launched that way. A WindowGroup creates its first
/// window only on activation, so the dialog ran with no window at all until
/// the person clicked its Dock icon.
@main
struct ApprovalDialogApp: App {
    @NSApplicationDelegateAdaptor(DialogAppDelegate.self) private var delegate

    var body: some Scene {
        Settings { EmptyView() }
    }
}

final class DialogAppDelegate: NSObject, NSApplicationDelegate {
    private let model = DialogModel()
    private var window: NSWindow?
    private var receivedURL = false
    private var stateSubscription: AnyCancellable?

    func applicationDidFinishLaunching(_ notification: Notification) {
        showWindow()
        if let id = ApprovalURL.requestID(fromArguments: ProcessInfo.processInfo.arguments) {
            model.load(id)
            return
        }
        // A launch through the URL scheme delivers the URL in
        // application(_:open:), which can arrive after this method returns.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [self] in
            if !receivedURL { model.load(nil) }
        }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let url = urls.first else { return }
        receivedURL = true
        model.load(ApprovalURL.requestID(from: url))
        showWindow()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Put the dialog above every other window, on the current Space.
    ///
    /// A floating window ordered front with orderFrontRegardless is visible
    /// without activation, which a background launch does not get. The window
    /// still takes keyboard focus only when the person clicks it, so typing
    /// into another app cannot answer a request.
    private func showWindow() {
        let window = self.window ?? makeWindow()
        self.window = window
        window.level = .floating
        window.collectionBehavior.insert([.canJoinAllSpaces, .fullScreenAuxiliary])
        window.center()
        window.orderFrontRegardless()
        NSApp.activate()
    }

    private func makeWindow() -> NSWindow {
        // The window is sized explicitly, once per state change, from the
        // content's fitting size. Letting the hosting view drive the window
        // size (sizingOptions .preferredContentSize) crashed the dialog:
        // AppKit threw "needing another Update Constraints in Window pass"
        // while the loading spinner ran.
        let hosting = NSHostingView(rootView: DialogRootView(model: model))
        hosting.sizingOptions = []
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: hosting.fittingSize),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.contentView = hosting
        window.titleVisibility = .hidden
        window.isReleasedWhenClosed = false
        stateSubscription = model.$state
            .receive(on: DispatchQueue.main)
            .sink { [weak window, weak hosting] _ in
                guard let window, let hosting else { return }
                window.setContentSize(hosting.fittingSize)
            }
        return window
    }
}

final class DialogModel: ObservableObject {
    @Published var state: DialogState = .loading

    func load(_ id: String?) {
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
            await MainActor.run { self.state = next }
        }
    }

    func answer(_ request: ApprovalRequestData, approved: Bool) {
        state = .sending
        let reason = "\(approved ? "approved" : "denied") in the macOS approval dialog by \(NSUserName())"
        Task.detached {
            do {
                try ApprovalClient().resolve(id: request.id, approved: approved, reason: reason)
                await MainActor.run { NSApp.terminate(nil) }
            } catch {
                await MainActor.run { self.state = .failed(error.localizedDescription) }
            }
        }
    }
}

struct DialogRootView: View {
    @ObservedObject var model: DialogModel

    var body: some View {
        switch model.state {
        case .loading:
            message(icon: nil, title: "Loading the request...", detail: nil)
        case .showing(let request):
            ApprovalView(request: request) { approved in model.answer(request, approved: approved) }
        case .sending:
            message(icon: nil, title: "Sending your answer...", detail: nil)
        case .failed(let detail):
            message(icon: "exclamationmark.triangle.fill", title: "The request cannot be answered", detail: detail)
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
