// macos/SysExt/DNSProxyProvider.swift
import NetworkExtension
import Network
import os.log

/// DNS filtering provider.
///
/// **This provider is registered but deliberately not installed.** Nothing
/// creates an NEDNSProxyManager configuration, so macOS never starts it, and
/// DNS rules are unenforced on macOS. That is a known gap, not an oversight,
/// and it is not safe to close by installing a configuration as-is:
///
///  1. There is no upstream resolver here. `shouldForward` reacts to a query
///     that policy does not block by calling `flow.writeDatagrams` -- which
///     writes *back to the querying app*, not out to a DNS server. So an
///     allowed query would be answered with a copy of itself. No NWConnection
///     or NWUDPSession exists anywhere in this file to send it upstream.
///  2. `BuildPolicySnapshot` emits no DNS rules at all (see the "the current
///     policy model does not have separate DNS rules" comment in
///     policysock/handler.go), so `evaluateDNS` always returns nil and every
///     query takes the broken path above.
///  3. An NEDNSProxyManager configuration is machine-wide. Unlike the content
///     filter, which the provider scopes to session PIDs, a DNS proxy sees
///     every lookup on the Mac. `evaluateDNS` is itself unscoped -- it takes no
///     PID and unions the rules of all sessions.
///
/// Together those mean installing this today would break name resolution for
/// the entire machine, not just for a sandboxed session. Closing the gap needs
/// an upstream resolver, DNS rules in the snapshot, and PID scoping -- in that
/// order.
class DNSProxyProvider: NEDNSProxyProvider {
    // SPIKE (SECENG-308): this build answers one question. Does the audit
    // token of a DNS proxy flow name the process that looked the name up, or
    // mDNSResponder? The provider forwards every UDP query to the server
    // that the query was sent to, and logs the source of each one. It
    // enforces nothing. Do not merge this provider.
    private let spikeLog = OSLog(subsystem: "dev.diffsec.agentmon", category: "dns-spike")

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        os_log(.default, log: spikeLog, "dns-spike: started")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let source = describeSource(flow.metaData)
        guard let udpFlow = flow as? NEAppProxyUDPFlow else {
            // A TCP query is rare. Returning false leaves it to the system.
            os_log(.default, log: spikeLog, "dns-spike: tcp flow not handled %{public}@", source)
            return false
        }
        udpFlow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log(.error, log: self.spikeLog, "dns-spike: open failed %{public}@", String(describing: error))
                return
            }
            self.relay(udpFlow, source: source)
        }
        return true
    }

    /// The PID, its session, and the signing identifier behind a flow.
    private func describeSource(_ meta: NEFlowMetaData) -> String {
        var pid: pid_t = -1
        if let data = meta.sourceAppAuditToken, data.count == MemoryLayout<audit_token_t>.size {
            var token = audit_token_t()
            _ = withUnsafeMutableBytes(of: &token) { data.copyBytes(to: $0) }
            pid = audit_token_to_pid(token)
        }
        let session = pid > 0 ? (SessionPolicyCache.shared.sessionForPID(pid) ?? "none") : "none"
        var path = [CChar](repeating: 0, count: 4096)
        let name = pid > 0 && proc_pidpath(pid, &path, UInt32(path.count)) > 0 ? String(cString: path) : "?"
        return "pid=\(pid) path=\(name) session=\(session) signing=\(meta.sourceAppSigningIdentifier)"
    }

    private func relay(_ flow: NEAppProxyUDPFlow, source: String) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }
            guard let datagrams = datagrams, let endpoints = endpoints, error == nil, !datagrams.isEmpty else {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }
            for (datagram, endpoint) in zip(datagrams, endpoints) {
                let domain = self.parseDNSQueryDomain(datagram) ?? "?"
                os_log(.default, log: self.spikeLog, "dns-spike: query %{public}@ %{public}@", domain, source)
                guard let host = endpoint as? NWHostEndpoint, let port = Network.NWEndpoint.Port(host.port) else { continue }
                self.forward(datagram, host: host.hostname, port: port) { reply in
                    flow.writeDatagrams([reply], sentBy: [endpoint]) { _ in }
                }
            }
            self.relay(flow, source: source)
        }
    }

    /// Send one query to its server and pass the first reply back.
    private func forward(_ query: Data, host: String, port: Network.NWEndpoint.Port, reply: @escaping (Data) -> Void) {
        let conn = NWConnection(host: Network.NWEndpoint.Host(host), port: port, using: .udp)
        conn.stateUpdateHandler = { state in
            if case .failed = state { conn.cancel() }
        }
        conn.start(queue: .global())
        conn.send(content: query, completion: .contentProcessed { _ in })
        conn.receiveMessage { data, _, _, _ in
            if let data = data { reply(data) }
            conn.cancel()
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) { conn.cancel() }
    }

    /// Returns an NXDOMAIN response if the query should be blocked, nil otherwise.
    private func processQuery(_ datagram: Data) -> Data? {
        guard let domain = parseDNSQueryDomain(datagram),
              let action = SessionPolicyCache.shared.evaluateDNS(domain: domain) else {
            return nil
        }
        if action == "nxdomain" {
            return synthesizeNXDOMAIN(datagram)
        }
        return nil
    }

    /// Returns true if the datagram should be forwarded (not blocked by policy).
    private func shouldForward(_ datagram: Data) -> Bool {
        guard let domain = parseDNSQueryDomain(datagram),
              let _ = SessionPolicyCache.shared.evaluateDNS(domain: domain) else {
            return true  // No policy match — forward
        }
        return false  // Policy matched (deny/nxdomain) — don't forward
    }

    // MARK: - DNS Wire Format Helpers

    /// Parse domain name from DNS query wire format.
    /// DNS header is 12 bytes, then QNAME as length-prefixed labels.
    private func parseDNSQueryDomain(_ datagram: Data) -> String? {
        guard datagram.count > 12 else { return nil }

        var offset = 12  // Skip DNS header
        var labels: [String] = []

        while offset < datagram.count {
            let length = Int(datagram[offset])
            if length == 0 { break }  // Root label = end
            if length & 0xC0 == 0xC0 { return nil }  // Pointer compression — bail
            guard length <= 63 else { return nil }  // RFC 1035: max label length
            offset += 1
            guard offset + length <= datagram.count else { return nil }
            let label = datagram[offset..<offset+length]
            guard let str = String(bytes: label, encoding: .ascii) else { return nil }
            labels.append(str)
            offset += length
        }

        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    /// Synthesize a DNS NXDOMAIN response from a query datagram.
    private func synthesizeNXDOMAIN(_ query: Data) -> Data? {
        guard query.count >= 12 else { return nil }
        var response = query
        // Set QR bit (response) and RCODE=3 (NXDOMAIN)
        // Byte 2: QR=1 (0x80) | Opcode (keep) | AA=0 | TC=0 | RD (keep)
        response[2] = (query[2] & 0x79) | 0x80  // Set QR, preserve Opcode and RD
        // Byte 3: RA=1 (0x80) | Z=0 | RCODE=3 (0x03)
        response[3] = 0x83
        // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        response[6] = 0; response[7] = 0
        response[8] = 0; response[9] = 0
        response[10] = 0; response[11] = 0
        // Truncate to header + question only
        var offset = 12
        while offset < response.count {
            let length = Int(response[offset])
            if length == 0 { offset += 1; break }
            offset += 1 + length
        }
        guard offset + 4 <= response.count else { return nil }
        offset += 4  // QTYPE (2) + QCLASS (2)
        return response.prefix(offset)
    }
}
