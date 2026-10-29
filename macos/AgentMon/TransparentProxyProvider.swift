// macos/SysExt/TransparentProxyProvider.swift
import Foundation
import Network
import NetworkExtension
import os.log

private let proxyLog = OSLog(subsystem: "dev.diffsec.agentmon.SysExt", category: "TransparentProxy")

/// Sends each outbound TCP flow from a session process through the daemon.
///
/// The content filter can only allow or drop a flow. The daemon's gateway
/// applies the whole Go network policy instead: first-match rules, approvals,
/// redirects and events, as the Linux transparent gateway does. Every client
/// keeps working, including one that ignores HTTPS_PROXY, such as ssh.
///
/// A flow from any other process is returned to the system untouched. So is
/// a flow from the daemon, because the daemon's own upstream connections must
/// not loop back into the gateway.
///
/// It needs macOS 15 for the nw_endpoint flow APIs. The extension target
/// still builds for macOS 14, but the app that installs it needs 15.6.
@available(macOS 15.0, *)
class TransparentProxyProvider: NETransparentProxyProvider {

    /// Whether the proxy is running. FilterDataProvider leaves the TCP flows
    /// of a session to the proxy only while this is true.
    private static let runningLock = NSLock()
    private static var _isRunning = false
    static var isRunning: Bool {
        runningLock.lock()
        defer { runningLock.unlock() }
        return _isRunning
    }
    private static func setRunning(_ running: Bool) {
        runningLock.lock()
        _isRunning = running
        runningLock.unlock()
    }

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // Every outbound TCP flow, except loopback. A flow to the session's
        // HTTP proxy on loopback already goes to the daemon.
        settings.includedNetworkRules = [
            NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0,
                          localNetworkEndpoint: nil, localPrefix: 0,
                          protocol: .TCP, direction: .outbound)
        ]
        settings.excludedNetworkRules = [
            NENetworkRule(remoteNetworkEndpoint: NWEndpoint.hostPort(host: "127.0.0.0", port: 0), remotePrefix: 8,
                          localNetworkEndpoint: nil, localPrefix: 0,
                          protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetworkEndpoint: NWEndpoint.hostPort(host: "::1", port: 0), remotePrefix: 128,
                          localNetworkEndpoint: nil, localPrefix: 0,
                          protocol: .TCP, direction: .outbound),
        ]
        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                NSLog("TransparentProxyProvider: failed to apply network settings: \(error)")
            } else {
                Self.setRunning(true)
                // The proof that session TCP flows now go to the daemon.
                NSLog("TransparentProxyProvider: startProxy -- session TCP flows now go through the daemon")
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Self.setRunning(false)
        NSLog("TransparentProxyProvider: stopProxy (reason \(reason.rawValue)) -- the content filter decides session TCP flows")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow,
              let tokenData = flow.metaData.sourceAppAuditToken,
              tokenData.count == MemoryLayout<audit_token_t>.size else {
            return false
        }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { tokenData.copyBytes(to: $0) }

        // The daemon dials the upstream of every flow. Its own flows go out
        // directly.
        if PolicySocketClient.shared.isValidatedServer(token) {
            return false
        }
        let pid = audit_token_to_pid(token)
        guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
            return false
        }
        // From here the flow belongs to a session. The content filter allowed
        // it because the proxy runs, so a flow that the proxy cannot forward
        // is refused, not returned to the system.
        guard case let .hostPort(host, port) = tcpFlow.remoteFlowEndpoint else {
            FlowRelay.refuse(tcpFlow)
            return true
        }

        let hostString: String
        switch host {
        case .name(let name, _):
            hostString = name
        case .ipv4(let address):
            hostString = "\(address)"
        case .ipv6(let address):
            hostString = "\(address)"
        @unknown default:
            FlowRelay.refuse(tcpFlow)
            return true
        }

        FlowRelay.start(flow: tcpFlow, request: [
            "type": "flow_open",
            "session_id": sessionID,
            "pid": Int(pid),
            "host": hostString,
            "port": Int(port.rawValue),
            "domain": flow.remoteHostname ?? "",
        ])
        return true
    }
}

/// Copies one flow's bytes between the app and the daemon.
///
/// The connection to the daemon is the policy socket. The relay sends one
/// flow_open request and waits for one response line. If the daemon allows
/// the flow, the relay opens the app's flow and the connection then carries
/// the flow's bytes. If the daemon refuses it, the app's connection fails.
///
/// The daemon writes the response only after its upstream connection is open,
/// so the app's connect() returns when the destination is reachable, or after
/// an approval when the policy asks for one.
@available(macOS 15.0, *)
final class FlowRelay {
    private let flow: NEAppProxyTCPFlow
    private let fd: Int32
    private let queue = DispatchQueue(label: "dev.diffsec.agentmon.flowrelay")
    private let writeQueue = DispatchQueue(label: "dev.diffsec.agentmon.flowrelay.write")
    private var readSource: DispatchSourceRead?
    private var sourceSuspended = false

    /// Bytes read before the response line was complete.
    private var pending = Data()
    private var answered = false
    private var daemonDone = false
    private var appDone = false
    private var closed = false

    /// Requests and responses of more than this are not policy socket
    /// traffic.
    private static let maxResponse = 64 * 1024

    private init(flow: NEAppProxyTCPFlow, fd: Int32) {
        self.flow = flow
        self.fd = fd
    }

    static func start(flow: NEAppProxyTCPFlow, request: [String: Any]) {
        DispatchQueue.global(qos: .userInitiated).async {
            guard let fd = PolicySocketClient.shared.openFlowConnection() else {
                os_log(.error, log: proxyLog, "no connection to the daemon -- refused a session flow")
                refuse(flow)
                return
            }
            // No newline after the request: the daemon reads one JSON value,
            // and a newline would reach the upstream as a flow byte.
            guard let data = try? JSONSerialization.data(withJSONObject: request),
                  writeAll(fd: fd, data: data) else {
                close(fd)
                refuse(flow)
                return
            }
            FlowRelay(flow: flow, fd: fd).run()
        }
    }

    static func refuse(_ flow: NEAppProxyTCPFlow) {
        let error = NSError(domain: NEAppProxyErrorDomain, code: NEAppProxyFlowError.refused.rawValue)
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }

    @discardableResult
    private static func writeAll(fd: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { buffer -> Bool in
            guard let base = buffer.baseAddress else { return true }
            var offset = 0
            while offset < buffer.count {
                let n = write(fd, base + offset, buffer.count - offset)
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
    }

    private func run() {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [self] in readFromDaemon() }
        source.setCancelHandler { [fd] in close(fd) }
        readSource = source
        // The relay keeps itself alive through the source's handlers until
        // finish() cancels the source.
        source.resume()
    }

    // MARK: - Daemon to app

    private func readFromDaemon() {
        var buffer = [UInt8](repeating: 0, count: 65536)
        let n = read(fd, &buffer, buffer.count)
        if n < 0 {
            if errno == EAGAIN || errno == EINTR { return }
            finish()
            return
        }
        if n == 0 {
            daemonDone = true
            if !answered {
                Self.refuse(flow)
                finish()
                return
            }
            flow.closeWriteWithError(nil)
            stopReading()
            finishIfDone()
            return
        }
        let data = Data(buffer[0..<n])
        if answered {
            deliverToApp(data)
            return
        }

        pending.append(data)
        guard let newline = pending.firstIndex(of: 0x0A) else {
            if pending.count > Self.maxResponse { Self.refuse(flow); finish() }
            return
        }
        let line = pending[pending.startIndex..<newline]
        let rest = pending[(newline + 1)...]
        pending = Data()
        answered = true

        let response = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any]
        guard response?["allow"] as? Bool == true else {
            os_log(.info, log: proxyLog, "daemon refused a session flow: %{public}s",
                   (response?["message"] as? String) ?? "no reason")
            Self.refuse(flow)
            finish()
            return
        }

        suspendReading()
        flow.open(withLocalFlowEndpoint: nil) { [self] error in
            queue.async { [self] in
                if let error = error {
                    os_log(.error, log: proxyLog, "could not open a session flow: %{public}s", "\(error)")
                    finish()
                    return
                }
                readFromApp()
                if rest.isEmpty {
                    resumeReading()
                } else {
                    deliverToApp(Data(rest))
                }
            }
        }
    }

    /// Writes to the app, and reads more from the daemon only once the app
    /// took this data, so a slow app slows the daemon rather than filling
    /// memory.
    private func deliverToApp(_ data: Data) {
        suspendReading()
        flow.write(data) { [self] error in
            queue.async { [self] in
                if error != nil {
                    finish()
                    return
                }
                resumeReading()
            }
        }
    }

    // MARK: - App to daemon

    private func readFromApp() {
        flow.readData { [self] data, error in
            if error != nil {
                queue.async { [self] in finish() }
                return
            }
            guard let data = data, !data.isEmpty else {
                // The app closed its write side.
                queue.async { [self] in
                    appDone = true
                    shutdown(fd, SHUT_WR)
                    finishIfDone()
                }
                return
            }
            writeQueue.async { [self] in
                let ok = Self.writeAll(fd: fd, data: data)
                queue.async { [self] in
                    if ok && !closed {
                        readFromApp()
                    } else {
                        finish()
                    }
                }
            }
        }
    }

    // MARK: - Teardown

    private func suspendReading() {
        guard let source = readSource, !sourceSuspended else { return }
        source.suspend()
        sourceSuspended = true
    }

    private func resumeReading() {
        guard let source = readSource, sourceSuspended, !closed else { return }
        source.resume()
        sourceSuspended = false
    }

    /// Stops reading from the daemon after its end of the stream. The fd
    /// stays open, because the app can still be writing.
    private func stopReading() {
        suspendReading()
    }

    private func finishIfDone() {
        if daemonDone && appDone { finish() }
    }

    private func finish() {
        guard !closed else { return }
        closed = true
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        if let source = readSource {
            // A suspended source must be resumed before it can be cancelled
            // and released.
            if sourceSuspended {
                source.resume()
                sourceSuspended = false
            }
            source.cancel()
            readSource = nil
        } else {
            close(fd)
        }
    }
}
