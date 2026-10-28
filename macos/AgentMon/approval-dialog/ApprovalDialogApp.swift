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
    /// Measures the content for the window. It is never shown. See makeWindow.
    private lazy var measurer = NSHostingController(rootView: DialogRootView(model: model))

    private func contentSize() -> NSSize {
        measurer.sizeThatFits(in: NSSize(width: 10_000, height: 10_000))
    }

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
        Self.fit(window, to: contentSize())
        window.orderFrontRegardless()
        NSApp.activate()
    }

    /// Size the window to its content and center it on the screen that holds
    /// the pointer.
    ///
    /// NSWindow.center() is not used. It puts a window above the vertical
    /// center on purpose, and AppKit keeps the origin fixed when the content
    /// grows, so the dialog sat high and drifted further as the request
    /// loaded.
    private static func fit(_ window: NSWindow, to contentSize: NSSize) {
        let frameSize = window.frameRect(forContentRect: NSRect(origin: .zero, size: contentSize)).size
        let mouse = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { NSMouseInRect(mouse, $0.frame, false) } ?? NSScreen.main
        guard let visible = screen?.visibleFrame else {
            window.setContentSize(contentSize)
            return
        }
        let origin = NSPoint(x: visible.midX - frameSize.width / 2, y: visible.midY - frameSize.height / 2)
        window.setFrame(NSRect(origin: origin, size: frameSize), display: true)
    }

    private func makeWindow() -> NSWindow {
        // The hosting view does not size the window. With sizingOptions
        // .preferredContentSize the dialog crashed: AppKit threw "needing
        // another Update Constraints in Window pass" while the loading spinner
        // ran. With sizing off, the hosting view's fittingSize is zero, so the
        // content is measured by a separate controller, and the window is
        // sized and centered from that on each state change.
        let hosting = NSHostingView(rootView: DialogRootView(model: model))
        hosting.sizingOptions = []
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: contentSize()),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.contentView = hosting
        window.titleVisibility = .hidden
        window.isReleasedWhenClosed = false
        stateSubscription = model.$state
            .receive(on: DispatchQueue.main)
            .sink { [weak self, weak window] _ in
                // The next pass of the run loop, so that the measuring
                // controller sees the new state.
                DispatchQueue.main.async {
                    guard let self, let window else { return }
                    Self.fit(window, to: self.contentSize())
                }
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
