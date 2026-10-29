// macos/SysExt/FilterDataProvider.swift
import NetworkExtension
import Foundation

class FilterDataProvider: NEFilterDataProvider {

    // MARK: - Blocking Configuration

    // Whether the filter drops a flow that an approve rule matches comes from
    // the session's snapshot (network_enforcement, derived in
    // policysock/handler.go), so two sessions can differ.

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // This line is the proof that the content filter is actually running.
        // macOS calls startFilter only once an NEFilterManager configuration
        // exists and is enabled; before that the provider is registered but
        // never instantiated, and network rules are unenforced with nothing in
        // any log to say so. `log show --predicate 'process == "..."'` finding
        // this message is the check that distinguishes the two states.
        NSLog("FilterDataProvider: startFilter -- content filter is now active")
        _ = ProcessHierarchy.shared
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        NSLog("FilterDataProvider: stopFilter (reason \(reason.rawValue)) -- network rules are no longer enforced")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Get remote endpoint - use remoteFlowEndpoint for modern API, fallback to deprecated
        let ip: String
        let port: Int

        if #available(macOS 15.0, *) {
            guard let endpoint = socketFlow.remoteFlowEndpoint else {
                return .allow()
            }
            switch endpoint {
            case .hostPort(let host, let p):
                ip = "\(host)"
                port = Int(p.rawValue)
            default:
                return .allow()
            }
        } else {
            // Fallback to deprecated API for older macOS
            guard let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
                return .allow()
            }
            ip = remoteEndpoint.hostname
            port = Int(remoteEndpoint.port) ?? 0
        }

        // Extract process info using audit token
        guard let auditTokenData = socketFlow.sourceAppAuditToken else {
            NSLog("FilterDataProvider: No audit token for flow to \(ip):\(port)")
            return .allow()
        }

        // Convert Data to audit_token_t
        var auditToken = audit_token_t()
        guard auditTokenData.count == MemoryLayout<audit_token_t>.size else {
            NSLog("FilterDataProvider: Invalid audit token size for flow to \(ip):\(port)")
            return .allow()
        }
        _ = withUnsafeMutableBytes(of: &auditToken) { dest in
            auditTokenData.copyBytes(to: dest)
        }

        let pid = audit_token_to_pid(auditToken)

        // The daemon's own connections are never an agent's. The daemon
        // registers itself as the root of every `agentmon exec` session
        // (registerSessionRoot in internal/api/session_root.go), so without
        // this check its proxy's upstream dial looks like a session process
        // bypassing the proxy and is dropped. The match is on the audit token
        // of the server that passed validateServer, PID and PID version both,
        // so a reused PID or another copy of the agentmon binary does not
        // match.
        if PolicySocketClient.shared.isValidatedServer(auditToken) {
            return .allow()
        }

        // Session scoping: auto-allow if PID is not in any active session.
        // This runs before any per-process work. Every flow on the machine
        // passes through here, and a code signature lookup on each one made
        // all network connections slow.
        guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
            return .allow()
        }

        // While the transparent proxy runs, it sends this session's outbound
        // TCP flows to the daemon, which applies the full network policy.
        // A loopback flow is not captured, so the filter still decides it.
        if #available(macOS 15.0, *), TransparentProxyProvider.isRunning,
           socketFlow.socketType == SOCK_STREAM, socketFlow.direction == .outbound,
           !Self.isLoopback(ip) {
            return .allow()
        }

        // Extract domain from flow if available (SNI/hostname)
        let hostname = socketFlow.remoteHostname

        // Cache fast-path: check network rules.
        //
        // hostname and ip are passed separately: domain rules match the
        // hostname, CIDR rules match the address, and collapsing them to
        // `hostname ?? ip` discarded the address whenever SNI was available.
        let (cacheDecision, _) = SessionPolicyCache.shared.evaluateNetwork(
            host: hostname, ip: ip, port: port, pid: pid)

        switch cacheDecision {
        case .allow:
            return .allow()
        case .deny:
            return .drop()
        case .fallthrough_:
            // Enforcement mode is a property of the session's policy. A
            // missing cache means the snapshot has not arrived yet, and audit
            // matches what a PID with no known policy gets elsewhere.
            let blockingEnabled = SessionPolicyCache.shared.cacheForSession(sessionID)?.networkBlocking ?? false
            // An approve rule. The filter cannot hold a flow while a person
            // decides, so it denies the flow when the policy enforces and
            // allows it in audit mode. Through the transparent proxy, the
            // daemon asks for approval instead. This used to send a
            // pnacl_check to the daemon, which nothing answered: the daemon
            // has no PNACL handler, so every check came back allow.
            NSLog("FilterDataProvider: approve rule for \(hostname ?? ip):\(port) from pid \(pid) -- \(blockingEnabled ? "denied" : "allowed in audit mode")")
            return blockingEnabled ? .drop() : .allow()
        }
    }

    /// Whether an address is loopback, which the transparent proxy excludes.
    static func isLoopback(_ ip: String) -> Bool {
        ip.hasPrefix("127.") || ip == "::1" || ip == "localhost"
    }

    // MARK: - Data Handlers

    override func handleInboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        return .allow()
    }

    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        return .allow()
    }
}
