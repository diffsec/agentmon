// macos/SysExt/DNSProxyProvider.swift
import NetworkExtension
import Network

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
    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        // Refuse to start rather than silently mangling the machine's DNS.
        //
        // This costs nothing today: no configuration exists, so this method is
        // never called. It matters the moment someone installs one -- returning
        // an error surfaces as a failed proxy, whereas succeeding would answer
        // every DNS query on the Mac with a copy of the query. Delete this
        // guard only together with the three fixes named above.
        NSLog("DNSProxyProvider: refusing to start -- no upstream resolver and no DNS rules in the snapshot; DNS policy is unenforced on macOS")
        completionHandler(NSError(
            domain: "dev.diffsec.agentmon",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey:
                "AgentMon DNS proxy is not implemented: it has no upstream resolver, so starting it would break DNS resolution machine-wide."]))
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // DNS flows come through here
        if let udpFlow = flow as? NEAppProxyUDPFlow {
            handleDNSFlow(udpFlow)
            return true
        }
        return false
    }

    private func handleDNSFlow(_ flow: NEAppProxyUDPFlow) {
        if #available(macOS 15.0, *) {
            flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
                if let error = error {
                    NSLog("DNS flow open error: \(error)")
                    return
                }
                self?.readAndProcessDNS(flow)
            }
        } else {
            flow.open(withLocalEndpoint: nil) { [weak self] error in
                if let error = error {
                    NSLog("DNS flow open error: \(error)")
                    return
                }
                self?.readAndProcessDNS(flow)
            }
        }
    }

    private func readAndProcessDNS(_ flow: NEAppProxyUDPFlow) {
        if #available(macOS 15.0, *) {
            readAndProcessDNSModern(flow)
        } else {
            readAndProcessDNSLegacy(flow)
        }
    }

    @available(macOS 15.0, *)
    private func readAndProcessDNSModern(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] tuples, error in
            guard let self = self else { return }

            guard let tuples = tuples, error == nil else {
                if let error = error { NSLog("DNS read error: \(error)") }
                return
            }

            for (datagram, endpoint) in tuples {
                if let response = self.processQuery(datagram) {
                    flow.writeDatagrams([(response, endpoint)]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                } else if self.shouldForward(datagram) {
                    flow.writeDatagrams([(datagram, endpoint)]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                }
            }

            self.readAndProcessDNSModern(flow)
        }
    }

    private func readAndProcessDNSLegacy(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams(completionHandler: { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            guard let datagrams = datagrams, let endpoints = endpoints, error == nil else {
                if let error = error { NSLog("DNS read error: \(error)") }
                return
            }

            for (datagram, endpoint) in zip(datagrams, endpoints) {
                if let response = self.processQuery(datagram) {
                    flow.writeDatagrams([response], sentBy: [endpoint]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                } else if self.shouldForward(datagram) {
                    flow.writeDatagrams([datagram], sentBy: [endpoint]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                }
            }

            self.readAndProcessDNSLegacy(flow)
        })
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
