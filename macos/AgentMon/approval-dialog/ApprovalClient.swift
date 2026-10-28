// macos/AgentMon/approval-dialog/ApprovalClient.swift
//
// Everything the dialog does that is not drawing: the request model, the
// socket path, the wire format, the launch URL and the check on the daemon's
// signature. It imports only Foundation and Security, so
// scripts/test-swift-approval-client.sh can compile this file as it ships and
// test it without Xcode.
import Foundation
import Security

/// One pending approval, as the daemon's list_approvals reply describes it.
/// Mirrors policysock.PendingApproval in
/// internal/platform/darwin/policysock/approvals.go.
struct ApprovalRequestData: Equatable {
    let id: String
    let kind: String
    let target: String
    let rule: String
    let message: String
    let sessionID: String
    let createdAt: Date
    let expiresAt: Date
    /// Extra detail rows, sorted by key so the layout does not reorder.
    let fields: [(key: String, value: String)]

    nonisolated static func == (a: ApprovalRequestData, b: ApprovalRequestData) -> Bool {
        a.id == b.id && a.kind == b.kind && a.target == b.target && a.rule == b.rule
            && a.message == b.message && a.sessionID == b.sessionID
            && a.createdAt == b.createdAt && a.expiresAt == b.expiresAt
            && a.fields.map { $0.key + "=" + $0.value } == b.fields.map { $0.key + "=" + $0.value }
    }

    /// Parses one entry of pending_approvals. Returns nil when a field the
    /// dialog cannot work without is missing, because a dialog that shows an
    /// approval without its expiry or ID cannot be answered correctly.
    nonisolated static func from(json: [String: Any]) -> ApprovalRequestData? {
        guard let id = json["id"] as? String, !id.isEmpty,
              let kind = json["kind"] as? String,
              let created = (json["created_at"] as? String).flatMap(parseTime),
              let expires = (json["expires_at"] as? String).flatMap(parseTime)
        else {
            return nil
        }
        let rawFields = json["fields"] as? [String: String] ?? [:]
        return ApprovalRequestData(
            id: id,
            kind: kind,
            target: json["target"] as? String ?? "",
            rule: json["rule"] as? String ?? "",
            message: json["message"] as? String ?? "",
            sessionID: json["session_id"] as? String ?? "",
            createdAt: created,
            expiresAt: expires,
            fields: rawFields.sorted { $0.key < $1.key }.map { (key: $0.key, value: $0.value) }
        )
    }

    /// The daemon sends RFC 3339 timestamps at second precision. Fractional
    /// seconds are accepted too, so a later change on the Go side does not
    /// turn every approval into a parse failure.
    nonisolated static func parseTime(_ s: String) -> Date? {
        let plain = ISO8601DateFormatter()
        if let d = plain.date(from: s) { return d }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: s)
    }
}

/// Where the daemon's policy socket is.
enum ApprovalSocket {
    /// The dialog runs as the logged-in user, the same user as the daemon, so
    /// the socket is under this user's home. The home comes from the password
    /// database rather than $HOME or NSHomeDirectory(), because the daemon
    /// passes an environment the dialog should not have to trust, and a
    /// sandboxed process would get its container instead.
    ///
    /// This must match defaultPolicySocketPath in
    /// internal/config/policysocket_path.go.
    nonisolated static func defaultPath() -> String {
        var home = ""
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            home = String(cString: dir)
        }
        if home.isEmpty {
            home = NSHomeDirectory()
        }
        return (home as NSString).appendingPathComponent("Library/Application Support/agentmon/policy.sock")
    }
}

/// Reads the request ID out of agentmon-approval://approve?id=<id>.
enum ApprovalURL {
    nonisolated static let scheme = "agentmon-approval"

    nonisolated static func requestID(from url: URL) -> String? {
        guard url.scheme == scheme,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let id = components.queryItems?.first(where: { $0.name == "id" })?.value,
              !id.isEmpty
        else {
            return nil
        }
        return id
    }

    /// The daemon passes the URL as a launch argument, because it opens the
    /// app with `open -n -a ... --args <url>`.
    nonisolated static func requestID(fromArguments args: [String]) -> String? {
        for arg in args where arg.hasPrefix(scheme + "://") {
            if let url = URL(string: arg), let id = requestID(from: url) {
                return id
            }
        }
        return nil
    }
}

/// Talks to the daemon over its policy socket.
///
/// The daemon admits this connection only because the process is the signed
/// approval dialog running as the daemon's own user. The same connection is
/// refused anything except listing and resolving approvals.
///
/// Its methods are nonisolated so the app can call them off the main actor:
/// the target builds with MainActor as the default isolation, and a blocking
/// socket read on the main thread freezes the window.
struct ApprovalClient {
    enum ClientError: Error, LocalizedError, Equatable {
        case connectionFailed(String)
        case writeFailed
        case readFailed
        case timeout
        case invalidResponse
        case untrustedServer(String)
        case server(String)

        var errorDescription: String? {
            switch self {
            case .connectionFailed(let path):
                return "Cannot reach the agentmon daemon at \(path). Make sure that it is running."
            case .writeFailed:
                return "The request to the daemon could not be sent."
            case .readFailed:
                return "The daemon closed the connection without an answer."
            case .timeout:
                return "The daemon did not answer within 5 seconds."
            case .invalidResponse:
                return "The daemon sent a reply that the dialog cannot read."
            case .untrustedServer(let path):
                return "The process at \(path) is not the signed agentmon daemon, so the dialog will not trust it."
            case .server(let message):
                return message
            }
        }
    }

    /// The code requirement for the daemon: agentmon's signing identifier and
    /// team. Any process running as this user can bind the socket path while
    /// the daemon is not holding it. Without this check, such a process could
    /// show the person a request of its choosing.
    nonisolated static let daemonRequirement =
        "anchor apple generic and identifier \"dev.diffsec.agentmon\" and certificate leaf[subject.OU] = \"LWSYS6YTUZ\""

    let socketPath: String
    /// The requirement the peer must meet, or nil to skip the check. Only the
    /// test harness passes nil, because its fake daemon is not signed.
    let serverRequirement: String?
    var timeout: TimeInterval = 5

    nonisolated init(socketPath: String = ApprovalSocket.defaultPath(),
                     serverRequirement: String? = ApprovalClient.daemonRequirement) {
        self.socketPath = socketPath
        self.serverRequirement = serverRequirement
    }

    /// All pending approvals.
    nonisolated func list() throws -> [ApprovalRequestData] {
        let reply = try send(["type": "list_approvals"])
        guard let raw = reply["pending_approvals"] as? [[String: Any]] else {
            return []
        }
        return raw.compactMap(ApprovalRequestData.from(json:))
    }

    /// One pending approval, or nil if it expired or someone answered it.
    nonisolated func fetch(id: String) throws -> ApprovalRequestData? {
        try list().first { $0.id == id }
    }

    /// Answers an approval. Returns normally only if the daemon accepted it.
    nonisolated func resolve(id: String, approved: Bool, reason: String) throws {
        let reply = try send([
            "type": "resolve_approval",
            "request_id": id,
            "approved": approved,
            "reason": reason,
        ])
        if reply["success"] as? Bool != true {
            throw ClientError.server(reply["message"] as? String ?? "The daemon did not accept the answer.")
        }
    }

    /// Whether the process at the other end of fd meets the code requirement.
    ///
    /// The peer is identified by its audit token, not its PID, so a process
    /// that exits and leaves its PID to another cannot pass as the daemon.
    nonisolated static func peerSatisfies(fd: Int32, requirement: String) -> Bool {
        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) == 0 else { return false }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) } as CFData
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary, [], &code) == errSecSuccess,
            let code else { return false }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess,
              let req else { return false }
        return SecCodeCheckValidity(code, [], req) == errSecSuccess
    }

    /// Sends one newline-delimited JSON request and reads one reply.
    nonisolated func send(_ request: [String: Any]) throws -> [String: Any] {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ClientError.connectionFailed(socketPath) }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < capacity else { throw ClientError.connectionFailed(socketPath) }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (i, b) in pathBytes.enumerated() { buf[i] = b }
            buf[pathBytes.count] = 0
        }
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { throw ClientError.connectionFailed(socketPath) }
        if let requirement = serverRequirement, !Self.peerSatisfies(fd: fd, requirement: requirement) {
            throw ClientError.untrustedServer(socketPath)
        }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var payload = try JSONSerialization.data(withJSONObject: request)
        payload.append(0x0A)
        var written = 0
        while written < payload.count {
            let n = payload.withUnsafeBytes { write(fd, $0.baseAddress! + written, $0.count - written) }
            if n <= 0 {
                throw (errno == EAGAIN || errno == EWOULDBLOCK) ? ClientError.timeout : ClientError.writeFailed
            }
            written += n
        }

        var reply = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while reply.last != 0x0A {
            let n = read(fd, &buf, buf.count)
            if n < 0 {
                throw (errno == EAGAIN || errno == EWOULDBLOCK) ? ClientError.timeout : ClientError.readFailed
            }
            if n == 0 { break }
            reply.append(contentsOf: buf[0..<n])
            if reply.count > 1 << 20 { throw ClientError.invalidResponse }
        }
        guard !reply.isEmpty else { throw ClientError.readFailed }
        guard let obj = try? JSONSerialization.jsonObject(with: reply) as? [String: Any] else {
            throw ClientError.invalidResponse
        }
        // A refused request comes back with allow false and a message, and no
        // success field. Surface the daemon's words rather than a blank failure.
        if obj["success"] == nil, let message = obj["message"] as? String, !message.isEmpty {
            throw ClientError.server(message)
        }
        return obj
    }
}
