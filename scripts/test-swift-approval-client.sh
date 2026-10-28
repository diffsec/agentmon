#!/usr/bin/env bash
# Test the approval dialog's non-UI code: the request parser, the launch URL,
# the socket path and the wire format.
#
# The Xcode project has no test target. ApprovalClient.swift imports only
# Foundation for exactly this reason, so it is compiled here as it ships, with
# no extraction and no second copy to drift. The SwiftUI files are compiled by
# the xcodebuild step in CI.
#
# The parser runs against internal/platform/darwin/policysock/testdata/
# list_approvals_reply.json, which a Go test marshals from the real response
# types. A JSON tag renamed on either side fails one of the two tests.
set -euo pipefail

cd "$(dirname "$0")/.."
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    if ok { print("ok    \(what)") } else { print("FAIL  \(what)"); failures += 1 }
}

// MARK: golden reply from the Go side

let goldenPath = CommandLine.arguments[1]
let golden = try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: goldenPath))) as! [String: Any]
let raw = golden["pending_approvals"] as! [[String: Any]]
let parsed = raw.compactMap(ApprovalRequestData.from(json:))
check(parsed.count == 1, "golden reply parses one approval")
if let a = parsed.first {
    check(a.id == "approval-1" && a.kind == "command", "id and kind")
    check(a.target == "curl https://example.com" && a.rule == "approve-curl-wget", "target and rule")
    check(a.sessionID == "session-abc", "session id")
    check(a.expiresAt.timeIntervalSince(a.createdAt) == 300, "created_at and expires_at parse, 300s apart")
    check(a.fields.map { $0.key } == ["argv", "cwd"], "fields are sorted by key")
}

// MARK: parser edge cases

check(ApprovalRequestData.from(json: ["kind": "command", "created_at": "2026-10-28T02:00:00Z", "expires_at": "2026-10-28T02:05:00Z"]) == nil,
      "missing id is rejected")
check(ApprovalRequestData.from(json: ["id": "a", "kind": "command", "created_at": "2026-10-28T02:00:00Z"]) == nil,
      "missing expires_at is rejected; the dialog cannot show a countdown without it")
check(ApprovalRequestData.parseTime("2026-10-28T02:00:00.123456789Z") != nil,
      "fractional seconds parse, in case the Go side changes")
check(ApprovalRequestData.parseTime("yesterday") == nil, "garbage time is rejected")

// MARK: launch URL

check(ApprovalURL.requestID(from: URL(string: "agentmon-approval://approve?id=approval-1")!) == "approval-1", "url with id")
check(ApprovalURL.requestID(from: URL(string: "agentmon-approval://approve?id=a%26b%3Dc")!) == "a&b=c", "escaped id round-trips")
check(ApprovalURL.requestID(from: URL(string: "agentmon-approval://approve")!) == nil, "url without id")
check(ApprovalURL.requestID(from: URL(string: "https://approve?id=x")!) == nil, "another scheme is ignored")
check(ApprovalURL.requestID(fromArguments: ["/path/approval-dialog", "-NSDocumentRevisionsDebugMode", "agentmon-approval://approve?id=z"]) == "z",
      "id from launch arguments")
check(ApprovalURL.requestID(fromArguments: ["/path/approval-dialog"]) == nil, "no URL argument")

// MARK: socket path

let path = ApprovalSocket.defaultPath()
let home = String(cString: getpwuid(getuid())!.pointee.pw_dir)
check(path == home + "/Library/Application Support/agentmon/policy.sock",
      "socket path matches defaultPolicySocketPath in Go: \(path)")

// MARK: wire format, against a fake daemon

/// Serves one connection: records the request line and writes `reply`.
func serveOnce(at sockPath: String, reply: String) -> () -> [String: Any]? {
    unlink(sockPath)
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(sockPath.utf8)
    withUnsafeMutableBytes(of: &addr.sun_path) { buf in
        for (i, b) in bytes.enumerated() { buf[i] = b }
        buf[bytes.count] = 0
    }
    _ = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    listen(fd, 1)
    var received: [String: Any]?
    let done = DispatchSemaphore(value: 0)
    Thread {
        let c = accept(fd, nil, nil)
        var line = Data()
        var b = [UInt8](repeating: 0, count: 1)
        while read(c, &b, 1) == 1 {
            if b[0] == 0x0A { break }
            line.append(b[0])
        }
        received = try? JSONSerialization.jsonObject(with: line) as? [String: Any]
        let out = Array((reply + "\n").utf8)
        _ = out.withUnsafeBytes { write(c, $0.baseAddress!, $0.count) }
        close(c)
        close(fd)
        done.signal()
    }.start()
    return {
        done.wait()
        return received
    }
}

let sock = "/tmp/amtest-\(getpid()).sock"
defer { unlink(sock) }
// The fake daemon runs in this process. When the client refuses it and closes
// the connection, its reply write would raise SIGPIPE and end the test.
signal(SIGPIPE, SIG_IGN)
let client = ApprovalClient(socketPath: sock, serverRequirement: nil)

let goldenText = try! String(contentsOfFile: goldenPath, encoding: .utf8).replacingOccurrences(of: "\n", with: "")
var wait = serveOnce(at: sock, reply: goldenText)
let listed = (try? client.list()) ?? []
var req = wait()
check(req?["type"] as? String == "list_approvals", "list sends type list_approvals")
check(listed.count == 1 && listed.first?.id == "approval-1", "list returns the daemon's approvals")

wait = serveOnce(at: sock, reply: #"{"allow":false,"success":true}"#)
do {
    try client.resolve(id: "approval-1", approved: true, reason: "approved by test")
    check(true, "resolve accepts success true")
} catch {
    check(false, "resolve accepts success true (threw \(error))")
}
req = wait()
check(req?["type"] as? String == "resolve_approval", "resolve sends type resolve_approval")
check(req?["request_id"] as? String == "approval-1", "resolve sends request_id")
check(req?["approved"] as? Bool == true, "resolve sends approved true")
check(req?["reason"] as? String == "approved by test", "resolve sends reason")

// A deny must reach the daemon as approved false, not as a missing field
// that a later default could turn into true.
wait = serveOnce(at: sock, reply: #"{"allow":false,"success":true}"#)
try? client.resolve(id: "approval-1", approved: false, reason: "denied by test")
req = wait()
check(req?["approved"] as? Bool == false, "deny sends approved false")

// Go marshals Success with omitempty, so a failed resolve with no message
// arrives as {"allow":false}. resolve must not read that as accepted.
wait = serveOnce(at: sock, reply: #"{"allow":false}"#)
do {
    try client.resolve(id: "approval-1", approved: true, reason: "x")
    check(false, "a reply without success true throws")
} catch {
    check(true, "a reply without success true throws")
}
_ = wait()

wait = serveOnce(at: sock, reply: #"{"allow":false,"message":"no pending approval with that id; it may have expired or been resolved already"}"#)
do {
    try client.resolve(id: "gone", approved: false, reason: "x")
    check(false, "a rejected resolve throws")
} catch let e as ApprovalClient.ClientError {
    check(e == .server("no pending approval with that id; it may have expired or been resolved already"), "a rejected resolve surfaces the daemon's message")
} catch {
    check(false, "a rejected resolve throws ClientError (got \(error))")
}
_ = wait()

// The daemon refuses a peer that is not the signed dialog with allow false
// and a message, and no success field.
wait = serveOnce(at: sock, reply: #"{"allow":false,"message":"approvals are listed and resolved only by the signed approval dialog"}"#)
do {
    _ = try client.list()
    check(false, "a refused list throws")
} catch let e as ApprovalClient.ClientError {
    check(e == .server("approvals are listed and resolved only by the signed approval dialog"), "a refused list surfaces the daemon's message")
} catch {
    check(false, "a refused list throws ClientError (got \(error))")
}
_ = wait()

// With the real requirement, the client refuses a daemon that is not signed
// as agentmon. The fake daemon here is this unsigned test binary, which is
// what a process that took the socket path would be.
wait = serveOnce(at: sock, reply: #"{"allow":true,"pending_approvals":[]}"#)
do {
    _ = try ApprovalClient(socketPath: sock).list()
    check(false, "an unsigned daemon is refused")
} catch let e as ApprovalClient.ClientError {
    check(e == .untrustedServer(sock), "an unsigned daemon is untrustedServer")
} catch {
    check(false, "an unsigned daemon throws ClientError (got \(error))")
}
_ = wait()

unlink(sock)
do {
    _ = try ApprovalClient(socketPath: sock, serverRequirement: nil).list()
    check(false, "no daemon throws")
} catch let e as ApprovalClient.ClientError {
    check(e == .connectionFailed(sock), "no daemon is connectionFailed")
} catch {
    check(false, "no daemon throws ClientError (got \(error))")
}

print(failures == 0 ? "\nALL PASS" : "\n\(failures) FAILURES")
exit(failures == 0 ? 0 : 1)
SWIFT

# The same isolation the app target builds with: MainActor by default, so the
# nonisolated annotations in ApprovalClient.swift are exercised as they ship.
swiftc -swift-version 5 -default-isolation MainActor \
  -o "$WORK/test" \
  macos/AgentMon/approval-dialog/ApprovalClient.swift "$WORK/main.swift"
"$WORK/test" internal/platform/darwin/policysock/testdata/list_approvals_reply.json
