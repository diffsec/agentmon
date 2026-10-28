// macos/AgentMon/approval-dialog/ApprovalView.swift
import Combine
import SwiftUI

/// Shows one pending approval and asks for an answer.
struct ApprovalView: View {
    let request: ApprovalRequestData
    /// Called once, with true for approve and false for deny.
    let onDecision: (Bool) -> Void

    @State private var now = Date()
    @State private var decided = false
    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var remaining: TimeInterval { max(0, request.expiresAt.timeIntervalSince(now)) }
    private var expired: Bool { remaining <= 0 }
    private var total: TimeInterval { max(1, request.expiresAt.timeIntervalSince(request.createdAt)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            details
            countdown
            buttons
        }
        .padding(24)
        .frame(width: 460)
        .onReceive(tick) { now = $0 }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 36))
                .foregroundColor(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title2.bold())
                Text("An agent is waiting for your answer.")
                    .foregroundColor(.secondary)
            }
        }
    }

    private var details: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                if !request.target.isEmpty {
                    row("Target", request.target, monospaced: true)
                }
                if !request.message.isEmpty {
                    row("Reason", request.message)
                }
                if !request.rule.isEmpty {
                    row("Rule", request.rule, monospaced: true)
                }
                ForEach(request.fields, id: \.key) { field in
                    row(field.key, field.value, monospaced: true)
                }
                if !request.sessionID.isEmpty {
                    row("Session", request.sessionID, monospaced: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var countdown: some View {
        VStack(alignment: .leading, spacing: 6) {
            ProgressView(value: remaining, total: total)
                .tint(remaining <= 15 ? .red : .accentColor)
            Text(expired
                 ? "Expired. The daemon denied this request."
                 : "Denied automatically in \(Int(remaining.rounded(.up))) seconds.")
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }

    private var buttons: some View {
        HStack {
            Spacer()
            // Escape denies. Neither button takes Return, so a reflexive
            // keypress cannot approve anything.
            Button("Deny") { decide(false) }
                .keyboardShortcut(.cancelAction)
                .controlSize(.large)
            Button("Approve") { decide(true) }
                .tint(.green)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
        .disabled(decided || expired)
    }

    private func decide(_ approved: Bool) {
        guard !decided, !expired else { return }
        decided = true
        onDecision(approved)
    }

    private func row(_ label: String, _ value: String, monospaced: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .leading)
            Text(value)
                .font(monospaced ? .system(.body, design: .monospaced) : .body)
                .textSelection(.enabled)
                .lineLimit(4)
                .truncationMode(.middle)
        }
    }

    private var title: String {
        switch request.kind {
        case "command": return "Run a command?"
        case "file": return "Access a file?"
        case "network": return "Open a connection?"
        default: return "Approval needed"
        }
    }

    private var icon: String {
        switch request.kind {
        case "command": return "terminal"
        case "file": return "doc.badge.ellipsis"
        case "network": return "network.badge.shield.half.filled"
        default: return "exclamationmark.shield"
        }
    }
}
