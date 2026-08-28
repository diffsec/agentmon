import Foundation
// notify.h is its own top-level Clang module on macOS (see
// $(xcrun --show-sdk-path)/usr/include/notify.modulemap), so it is NOT
// re-exported by Foundation or Darwin and must be imported by name.
// Without this, notify_register_dispatch is "cannot find in scope".
import notify

/// Darwin notification name posted by Go server when policy changes.
private let policyUpdatedNotification = "dev.diffsec.agentmon.policy-updated"
private let sessionRegisteredNotification = "dev.diffsec.agentmon.session-registered"

// MARK: - Rule Types

struct FileRule {
    let pattern: String
    let operations: Set<String>  // "read", "write", "create", "delete", "rename"
    let action: String           // "allow" or "deny"
}

struct NetworkRule {
    let pattern: String
    let ports: Set<Int>
    let proto: String?
    let action: String
}

struct DNSRule {
    let pattern: String
    let action: String  // "allow", "deny", "nxdomain"
}

struct ExecRule {
    let pattern: String   // glob pattern for executable path
    let action: String    // "allow", "deny", "redirect"
}

struct DirectAllowEntry {
    let host: String  // IP, hostname, or "*"
    let port: Int     // 0 = any port
}

struct PolicyDefaults {
    let file: String     // "allow" or "deny"
    let network: String
    let dns: String
    let exec: String     // "allow" or "deny"
}

// MARK: - Per-Session Cache Entry

class SessionCache {
    let sessionID: String
    let rootPID: pid_t
    var version: UInt64
    var sessionPIDs: Set<pid_t>
    var fileRules: [FileRule]
    var networkRules: [NetworkRule]
    var dnsRules: [DNSRule]
    var execRules: [ExecRule]
    var defaults: PolicyDefaults
    var proxyAddr: String?
    var directAllow: [DirectAllowEntry] = []

    /// Whether the content filter should consult the daemon for flows this
    /// cache cannot decide, instead of allowing and reporting them. Sent by the
    /// daemon in the snapshot; see networkEnforcement in policysock/handler.go.
    var networkEnforcement: String = "audit"

    /// What a blocking-mode timeout or socket failure does. Only consulted when
    /// networkEnforcement is "block".
    var networkFailOpen: Bool = true

    /// True when the daemon asked for enforcement rather than observation.
    var networkBlocking: Bool { networkEnforcement == "block" }

    init(sessionID: String, rootPID: pid_t, version: UInt64,
         fileRules: [FileRule], networkRules: [NetworkRule],
         dnsRules: [DNSRule], execRules: [ExecRule],
         defaults: PolicyDefaults,
         proxyAddr: String? = nil, directAllow: [DirectAllowEntry] = [],
         networkEnforcement: String = "audit", networkFailOpen: Bool = true) {
        self.sessionID = sessionID
        self.rootPID = rootPID
        self.version = version
        self.sessionPIDs = [rootPID]
        self.fileRules = fileRules
        self.networkRules = networkRules
        self.dnsRules = dnsRules
        self.execRules = execRules
        self.defaults = defaults
        self.proxyAddr = proxyAddr
        self.directAllow = directAllow
        self.networkEnforcement = networkEnforcement
        self.networkFailOpen = networkFailOpen
    }
}

// MARK: - Policy Cache Manager

class SessionPolicyCache {
    static let shared = SessionPolicyCache()

    private var sessions: [String: SessionCache] = [:]  // sessionID -> cache
    private var pidToSession: [pid_t: String] = [:]      // fast PID -> sessionID lookup
    private var execDepths: [pid_t: Int] = [:]
    private let queue = DispatchQueue(label: "dev.diffsec.agentmon.policycache",
                                       attributes: .concurrent)

    /// Lock-free flag for the hot path. Updated under barrier writes.
    /// Avoids queue.sync for the most common check (no sessions = allow all).
    private var _hasActiveSessions: Int32 = 0

    private init() {
        startListeningForNotifications()
    }

    // MARK: - Session Lifecycle

    func registerSession(sessionID: String, rootPID: pid_t, snapshot: SessionCache) {
        queue.async(flags: .barrier) {
            self.sessions[sessionID] = snapshot
            self.pidToSession[rootPID] = sessionID
            OSAtomicCompareAndSwap32(0, 1, &self._hasActiveSessions)
        }
    }

    func unregisterSession(sessionID: String) {
        queue.async(flags: .barrier) {
            guard let cache = self.sessions[sessionID] else { return }
            for pid in cache.sessionPIDs {
                self.pidToSession.removeValue(forKey: pid)
                self.execDepths.removeValue(forKey: pid)
            }
            self.sessions.removeValue(forKey: sessionID)
            if self.sessions.isEmpty {
                OSAtomicCompareAndSwap32(1, 0, &self._hasActiveSessions)
            }
        }
    }

    var hasActiveSessions: Bool {
        _hasActiveSessions != 0
    }

    // MARK: - PID Tracking (called from NOTIFY_FORK/EXIT)

    func addPID(_ childPID: pid_t, parentPID: pid_t) {
        queue.async(flags: .barrier) {
            guard let sessionID = self.pidToSession[parentPID],
                  let cache = self.sessions[sessionID] else { return }
            cache.sessionPIDs.insert(childPID)
            self.pidToSession[childPID] = sessionID
        }
    }

    func removePID(_ pid: pid_t) {
        queue.async(flags: .barrier) {
            if let sessionID = self.pidToSession.removeValue(forKey: pid) {
                self.sessions[sessionID]?.sessionPIDs.remove(pid)
            }
            self.execDepths.removeValue(forKey: pid)
        }
    }

    // MARK: - Session Membership

    /// Returns the sessionID for a PID, or nil if not in any session.
    /// Resolve a PID to its session, walking up the process tree if it is not
    /// mapped directly.
    ///
    /// The direct map is populated by addPID from ESF FORK events, which only
    /// works if the parent was ALREADY in a session when the fork happened.
    /// Under `agentmon wrap` it is not: the daemon registers the wrap caller as
    /// the session root and posts the notification, but the agent has usually
    /// been forked by the time the extension fetches the snapshot. That fork
    /// event is dropped, the agent is never attributed, and every descendant of
    /// it inherits the same blindness -- so a wrapped session enforced nothing
    /// at all, which is the entire point of wrapping.
    ///
    /// `agentmon exec` did not show this because the daemon explicitly
    /// registers both its own PID and the command's PID, so it never depends on
    /// catching the fork.
    ///
    /// The walk uses ProcessHierarchy, which falls back to sysctl for processes
    /// it never saw fork, so it works for PIDs that predate the snapshot. Only
    /// positive results are cached: "not in a session" must stay re-checkable,
    /// because a session can be registered after the first lookup.
    func sessionForPID(_ pid: pid_t) -> String? {
        if let sid = queue.sync(execute: { pidToSession[pid] }) {
            return sid
        }

        // Nothing is tracked at all -- skip the sysctl walk entirely. This is
        // the common case on an idle machine and it is on the ESF AUTH hot path.
        guard _hasActiveSessions != 0 else { return nil }

        for ancestor in ProcessHierarchy.shared.getAncestors(pid: pid) {
            guard let sid = queue.sync(execute: { pidToSession[ancestor] }) else {
                continue
            }
            queue.async(flags: .barrier) {
                // Re-check under the barrier: another thread may have mapped it.
                guard self.pidToSession[pid] == nil,
                      let cache = self.sessions[sid] else { return }
                cache.sessionPIDs.insert(pid)
                self.pidToSession[pid] = sid
            }
            return sid
        }
        return nil
    }

    /// Returns the SessionCache for a PID, or nil if not in any session.
    func cacheForPID(_ pid: pid_t) -> SessionCache? {
        queue.sync {
            guard let sid = pidToSession[pid] else { return nil }
            return sessions[sid]
        }
    }

    /// Returns the SessionCache for a session ID, or nil if not found.
    func cacheForSession(_ sessionID: String) -> SessionCache? {
        queue.sync { sessions[sessionID] }
    }

    // MARK: - Exec Depth

    func recordExecDepth(pid: pid_t, parentPID: pid_t) -> Int {
        return queue.sync(flags: .barrier) {
            let parentDepth = execDepths[parentPID] ?? 0
            let depth = parentDepth + 1
            execDepths[pid] = depth
            return depth
        }
    }

    // MARK: - File Policy Evaluation

    enum CacheDecision {
        case allow
        case deny
        case fallthrough_  // No match, use default or XPC
    }

    func evaluateFile(path: String, operation: String, pid: pid_t) -> (CacheDecision, String?) {
        // Resolve through sessionForPID, NOT by reading pidToSession directly.
        // Only sessionForPID walks the process tree, and a process the
        // extension never saw fork is absent from that map -- which is every
        // direct child of the daemon, because agentmon's own binaries are muted
        // and their FORK events are therefore never delivered.
        //
        // Measured: `agentmon exec -- cat secret.txt` read a file its policy
        // denied, while the same read one level deeper (a script run by sh) was
        // refused, and a network deny on that same direct child WAS enforced --
        // because FilterDataProvider happens to call sessionForPID first and
        // this did not. Depending on the caller to have resolved is what left a
        // whole class of process silently unpoliced for file access.
        guard let sid = sessionForPID(pid) else {
            return (.allow, nil)
        }
        return queue.sync {
            guard let cache = sessions[sid] else {
                return (.allow, nil)  // session ended between resolve and read
            }

            // Check deny rules first
            for rule in cache.fileRules where rule.action == "deny" {
                if rule.operations.contains(operation) && globMatch(pattern: rule.pattern, path: path) {
                    return (.deny, sid)
                }
            }

            // Rules requiring server-side logic -> deny locally
            for rule in cache.fileRules where rule.action != "deny" {
                if rule.operations.contains(operation) && globMatch(pattern: rule.pattern, path: path) {
                    if rule.action == "approve" || rule.action == "redirect" || rule.action == "soft_delete" {
                        return (.deny, sid)
                    }
                    if rule.action == "allow" {
                        return (.allow, sid)
                    }
                }
            }

            // Apply default
            if cache.defaults.file == "deny" {
                return (.deny, sid)
            }
            return (.allow, sid)
        }
    }

    // MARK: - Network Policy Evaluation

    /// Evaluate a connection against the session's network rules.
    ///
    /// `host` and `ip` are separate on purpose. BuildPolicySnapshot flattens
    /// both `domains:` and `cidrs:` into the same pattern list, so a rule is
    /// matched either as a glob against the hostname or as a prefix against the
    /// address, and only one of those is meaningful for any given rule. The
    /// caller used to collapse them to `hostname ?? ip` and glob-match the
    /// result, which threw the address away whenever SNI was available and
    /// could never match a CIDR in any case -- `globMatch("10.0.0.0/8", ...)`
    /// is false for every input. A `cidrs:` deny was silently inert, and
    /// silently is the operative word: evaluateNetwork returns .allow rather
    /// than .fallthrough_ when nothing matches, so the daemon was never asked
    /// for a second opinion.
    func evaluateNetwork(host: String?, ip: String, port: Int, pid: pid_t) -> (CacheDecision, String?) {
        // Resolve through sessionForPID for the same reason as evaluateFile.
        // This path happened to work because its caller resolves first, but
        // relying on that is exactly how the file path came to be unenforced.
        guard let sid = sessionForPID(pid) else {
            return (.allow, nil)
        }
        return queue.sync {
            guard let cache = sessions[sid] else {
                return (.allow, nil)
            }

            func matches(_ rule: NetworkRule) -> Bool {
                guard rule.ports.isEmpty || rule.ports.contains(port) else { return false }
                if rule.pattern.contains("/") {
                    return cidrMatch(pattern: rule.pattern, ip: ip)
                }
                // A domain rule is tried against the hostname when there is
                // one, and against the address otherwise, which is what
                // patterns like "*" rely on.
                return globMatch(pattern: rule.pattern, path: host ?? ip)
            }

            for rule in cache.networkRules where rule.action == "deny" {
                if matches(rule) {
                    return (.deny, sid)
                }
            }

            for rule in cache.networkRules where rule.action != "deny" {
                if matches(rule) {
                    if rule.action == "approve" {
                        return (.fallthrough_, sid)
                    }
                    if rule.action == "allow" {
                        return (.allow, sid)
                    }
                }
            }

            if cache.defaults.network == "deny" {
                return (.deny, sid)
            }
            return (.allow, sid)
        }
    }

    /// Match an address against a CIDR block, for both IPv4 and IPv6.
    ///
    /// Parsing is delegated to inet_pton rather than done by hand: it settles
    /// IPv4-in-IPv6, zero compression and shorthand forms that a string
    /// comparison gets wrong. A pattern whose address or prefix length does not
    /// parse matches NOTHING -- returning true on a malformed rule would turn a
    /// typo into a machine-wide deny, and returning true on a malformed rule in
    /// an allow list would turn one into a hole.
    private func cidrMatch(pattern: String, ip: String) -> Bool {
        let parts = pattern.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefixLen = Int(parts[1]), prefixLen >= 0 else { return false }
        let network = String(parts[0])

        // IPv4
        var netV4 = in_addr()
        var ipV4 = in_addr()
        if inet_pton(AF_INET, network, &netV4) == 1 {
            guard prefixLen <= 32, inet_pton(AF_INET, ip, &ipV4) == 1 else { return false }
            if prefixLen == 0 { return true }
            // s_addr is network byte order; shifting in host order would
            // compare the wrong end of the address on a little-endian machine.
            let mask = UInt32.max << (32 - UInt32(prefixLen))
            return (UInt32(bigEndian: netV4.s_addr) & mask)
                == (UInt32(bigEndian: ipV4.s_addr) & mask)
        }

        // IPv6
        var netV6 = in6_addr()
        var ipV6 = in6_addr()
        guard inet_pton(AF_INET6, network, &netV6) == 1,
              prefixLen <= 128,
              inet_pton(AF_INET6, ip, &ipV6) == 1 else { return false }

        return withUnsafeBytes(of: &netV6) { netBytes in
            withUnsafeBytes(of: &ipV6) { ipBytes in
                var remaining = prefixLen
                var i = 0
                while remaining >= 8 {
                    if netBytes[i] != ipBytes[i] { return false }
                    remaining -= 8
                    i += 1
                }
                if remaining == 0 { return true }
                let mask = UInt8(0xFF) << UInt8(8 - remaining)
                return (netBytes[i] & mask) == (ipBytes[i] & mask)
            }
        }
    }

    // Exec policy is NOT evaluated here.
    //
    // There used to be an evaluateExec that scanned execRules and, finding
    // none, fell through to allow -- so every exec in every wrapped session was
    // permitted. BuildPolicySnapshot emits no exec rules and never sets
    // defaults.exec, so that could not have worked. ESFClient.handleAuthExec now
    // asks the daemon (exec_check -> PolicyAdapter.CheckExec), which is
    // authoritative and can do the things a local matcher cannot: argument
    // filtering, command_overrides, process contexts, ancestry.
    //
    // execRules below is still parsed, because it is part of the snapshot
    // schema and a daemon may populate it, but nothing consumes it. Do not
    // reintroduce a local exec fast path without also making the snapshot carry
    // rules faithful enough to decide on: a local matcher that answers "allow"
    // where the engine would say "deny" is a silent fail-open.

    // MARK: - DNS Policy Evaluation (union of all sessions)

    func evaluateDNS(domain: String) -> String? {
        return queue.sync {
            if sessions.isEmpty { return nil }  // No sessions = passthrough

            // Check deny rules first (stricter than nxdomain — drops entirely)
            for (_, cache) in sessions {
                for rule in cache.dnsRules where rule.action == "deny" {
                    if globMatch(pattern: rule.pattern, path: domain) {
                        return "deny"
                    }
                }
            }

            // Then check nxdomain rules
            for (_, cache) in sessions {
                for rule in cache.dnsRules where rule.action == "nxdomain" {
                    if globMatch(pattern: rule.pattern, path: domain) {
                        return "nxdomain"
                    }
                }
            }

            // Strictest default wins
            for (_, cache) in sessions {
                if cache.defaults.dns == "deny" {
                    return "deny"
                }
            }

            return nil  // All defaults allow = passthrough
        }
    }

    // MARK: - Cache Update

    func updateSession(_ sessionID: String, snapshot: SessionCache) {
        queue.async(flags: .barrier) {
            guard let existing = self.sessions[sessionID] else { return }
            if snapshot.version <= existing.version { return }
            // Preserve sessionPIDs — they're maintained by fork/exit, not snapshot
            snapshot.sessionPIDs = existing.sessionPIDs
            self.sessions[sessionID] = snapshot
        }
    }

    func versionForSession(_ sessionID: String) -> UInt64 {
        queue.sync { sessions[sessionID]?.version ?? 0 }
    }

    func allSessionIDs() -> [String] {
        queue.sync { Array(sessions.keys) }
    }

    // MARK: - Darwin Notification Listener

    /// Queue the notification handlers run on. Serial, so two notifications
    /// arriving together cannot race each other into the cache.
    private let notifyQueue = DispatchQueue(label: "dev.diffsec.agentmon.notify")

    /// Registration tokens, kept so the registrations are not cancelled. The
    /// cache is a process-lifetime singleton, so these are never released.
    private var notifyTokens: [Int32] = []

    /// Subscribe to the Go daemon's Darwin notifications.
    ///
    /// This uses notify_register_dispatch, NOT CFNotificationCenterAddObserver.
    /// The difference is the whole reason this code exists.
    ///
    /// CFNotificationCenterGetDarwinNotifyCenter delivers through a run-loop
    /// source, and the extension's main thread ends in dispatchMain(), which
    /// services the main *dispatch queue* and never runs a CFRunLoop. So the
    /// observers registered here were never called, at all. Two visible
    /// consequences, both measured on hardware on 2026-08-27:
    ///
    ///   - The extension never learned that a session had been registered, so
    ///     SessionPolicyCache mapped no PID to a session, and ESFClient's AUTH
    ///     handlers allowed everything. After a daemon restart, `agentmon wrap`
    ///     and `agentmon exec` sessions alike enforced NOTHING -- no file, exec
    ///     or network policy -- with nothing reporting it.
    ///   - PolicySocketClient.onServerNotification, the only thing that
    ///     re-establishes the event stream after the daemon restarts, was never
    ///     reached. Three previous attempts to fix that reconnect failed
    ///     because they addressed the socket rather than the delivery
    ///     mechanism: the reconnect logic was correct and simply never ran.
    ///
    /// notify_register_dispatch delivers on a dispatch queue and needs no run
    /// loop, so it works under dispatchMain().
    private func startListeningForNotifications() {
        register(policyUpdatedNotification) { [weak self] in
            self?.handlePolicyUpdateNotification()
        }
        register(sessionRegisteredNotification) { [weak self] in
            self?.handleSessionRegisteredNotification()
        }
    }

    private func register(_ name: String, handler: @escaping () -> Void) {
        var token: Int32 = 0
        let status = notify_register_dispatch(name, &token, notifyQueue) { _ in
            handler()
        }
        guard status == UInt32(NOTIFY_STATUS_OK) else {
            // Loud, because a silent failure here is indistinguishable from a
            // daemon that never posts: the extension simply enforces nothing.
            NSLog("SessionPolicyCache: FAILED to subscribe to \(name) (notify status \(status)) -- sessions will not be seen and policy will not be enforced")
            return
        }
        notifyTokens.append(token)
        NSLog("SessionPolicyCache: subscribed to \(name)")
    }

    private func handlePolicyUpdateNotification() {
        PolicySocketClient.shared.onServerNotification()

        let sessionIDs = allSessionIDs()
        for sessionID in sessionIDs {
            NotificationCenter.default.post(
                name: .policyCacheNeedsRefresh,
                object: nil,
                userInfo: ["session_id": sessionID]
            )
        }
    }

    private func handleSessionRegisteredNotification() {
        PolicySocketClient.shared.onServerNotification()

        // session_id "" asks for the most recently registered session.
        fetchSnapshot(sessionID: "") { [weak self] response in
            guard let self = self, let response = response else { return }

            // Darwin notifications coalesce. Two sessions registering close
            // together can produce one delivery, and the fetch above only
            // returns the latest -- so the other would never be fetched, would
            // hold no policy, and would enforce nothing for its whole life. The
            // daemon sends the full list precisely so that cannot happen.
            guard let active = response["active_sessions"] as? [String] else { return }
            let known = Set(self.allSessionIDs())
            for sessionID in active where !known.contains(sessionID) {
                self.fetchSnapshot(sessionID: sessionID, completion: nil)
            }
        }
    }

    /// Fetch one session's snapshot and install it. Passing "" asks the daemon
    /// for the most recently registered session.
    private func fetchSnapshot(sessionID: String,
                               completion: (([String: Any]?) -> Void)?) {
        PolicySocketClient.shared.request([
            "type": "fetch_policy_snapshot",
            "session_id": sessionID,
            "version": 0
        ]) { response in
            defer { completion?(response) }

            guard let response = response,
                  let resolvedID = response["session_id"] as? String,
                  !resolvedID.isEmpty else { return }
            guard let rootPID = response["root_pid"] as? Int32 ?? (response["root_pid"] as? Int).map({ Int32($0) }) else { return }
            guard let snapshot = SessionCache.from(json: response, sessionID: resolvedID, rootPID: rootPID) else {
                NSLog("SessionPolicyCache: failed to parse snapshot for session \(resolvedID)")
                return
            }
            SessionPolicyCache.shared.registerSession(
                sessionID: resolvedID, rootPID: rootPID, snapshot: snapshot)
            NSLog("SessionPolicyCache: registered session \(resolvedID) from notification")
        }
    }

    // MARK: - Glob Matching

    /// Simple glob matcher supporting * (single segment) and ** (recursive).
    /// Matches the Go policy engine's glob semantics.
    private func globMatch(pattern: String, path: String) -> Bool {
        // Use fnmatch for simple cases, handling ** manually
        if pattern.contains("**") {
            // Convert ** to regex-style matching
            let regexPattern = "^" + NSRegularExpression.escapedPattern(for: pattern)
                .replacingOccurrences(of: "\\*\\*", with: ".*")
                .replacingOccurrences(of: "\\*", with: "[^/]*")
            + "$"
            return (try? NSRegularExpression(pattern: regexPattern))?.firstMatch(
                in: path, range: NSRange(path.startIndex..., in: path)
            ) != nil
        }
        // Simple glob: use fnmatch
        return fnmatch(pattern, path, FNM_PATHNAME) == 0
    }
}

// MARK: - Snapshot Parsing

extension SessionCache {
    static func from(json: [String: Any], sessionID: String, rootPID: pid_t) -> SessionCache? {
        guard let version = json["version"] as? UInt64 ?? (json["version"] as? Int).map({ UInt64($0) }) else {
            return nil
        }

        var fileRules: [FileRule] = []
        if let rules = json["file_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let ops = r["operations"] as? [String],
                      let action = r["action"] as? String else { continue }
                fileRules.append(FileRule(pattern: pattern, operations: Set(ops), action: action))
            }
        }

        var networkRules: [NetworkRule] = []
        if let rules = json["network_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let action = r["action"] as? String else { continue }
                let ports = (r["ports"] as? [Int]).map { Set($0) } ?? Set<Int>()
                let proto = r["protocol"] as? String
                networkRules.append(NetworkRule(pattern: pattern, ports: ports, proto: proto, action: action))
            }
        }

        var dnsRules: [DNSRule] = []
        if let rules = json["dns_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let action = r["action"] as? String else { continue }
                dnsRules.append(DNSRule(pattern: pattern, action: action))
            }
        }

        var execRules: [ExecRule] = []
        if let rules = json["exec_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let action = r["action"] as? String else { continue }
                execRules.append(ExecRule(pattern: pattern, action: action))
            }
        }

        let defs = json["defaults"] as? [String: String] ?? [:]
        let defaults = PolicyDefaults(
            file: defs["file"] ?? "allow",
            network: defs["network"] ?? "allow",
            dns: defs["dns"] ?? "allow",
            exec: defs["exec"] ?? "allow"
        )

        var proxyAddr: String? = nil
        if let pa = json["proxy_addr"] as? String, !pa.isEmpty {
            proxyAddr = pa
        }

        var directAllow: [DirectAllowEntry] = []
        if let directAllowArr = json["direct_allow"] as? [[String: Any]] {
            directAllow = directAllowArr.compactMap { entry in
                guard let host = entry["host"] as? String else { return nil }
                let port = entry["port"] as? Int ?? 0
                return DirectAllowEntry(host: host, port: port)
            }
        }

        // A snapshot from a daemon that predates these fields carries neither.
        // Defaulting to audit keeps that daemon's behaviour exactly as it was
        // rather than silently switching it into a blocking mode it was never
        // built to answer for; explicit deny rules still drop, because
        // evaluateNetwork decides those without consulting either flag.
        let enforcement = json["network_enforcement"] as? String ?? "audit"
        let failOpen = json["network_fail_open"] as? Bool ?? true

        let cache = SessionCache(
            sessionID: sessionID, rootPID: rootPID, version: version,
            fileRules: fileRules, networkRules: networkRules,
            dnsRules: dnsRules, execRules: execRules, defaults: defaults,
            proxyAddr: proxyAddr, directAllow: directAllow,
            networkEnforcement: enforcement, networkFailOpen: failOpen
        )
        return cache
    }
}

// MARK: - Notification Name

extension Notification.Name {
    static let policyCacheNeedsRefresh = Notification.Name("dev.diffsec.agentmon.policyCacheNeedsRefresh")
}
