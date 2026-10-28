// macos/SysExt/ESFClient.swift
import Foundation
import EndpointSecurity
import os.log

private let esLog = OSLog(subsystem: "dev.diffsec.agentmon.SysExt", category: "ESF")

/// Handles Endpoint Security Framework events.
class ESFClient {
    /// Singleton reference set before subscribe() in main.swift.
    /// NOTIFY handlers use this; AUTH handlers do NOT depend on it.
    static var shared: ESFClient?

    /// The ES client pointer. Set once in create(), never cleared except in stop()/deinit.
    private var client: OpaquePointer?

    /// Observer token for policy cache refresh notifications
    private var notificationObserver: NSObjectProtocol?

    /// Cache of PID -> audit_token_t for muting
    private var auditTokenCache: [pid_t: audit_token_t] = [:]
    private let cacheQueue = DispatchQueue(label: "dev.diffsec.agentmon.audittokencache")

    private init(client: OpaquePointer) {
        self.client = client

        // Listen for Darwin notification-triggered cache refresh
        notificationObserver = NotificationCenter.default.addObserver(
            forName: .policyCacheNeedsRefresh,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let sessionID = notification.userInfo?["session_id"] as? String else { return }
            self?.refreshCacheForSession(sessionID)
        }
    }

    deinit {
        if let observer = notificationObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        stop()
    }

    /// Factory: creates ES client but does NOT subscribe. Call subscribe() separately.
    static func create() -> ESFClient? {
        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { client, event in
            handleESEvent(client: client, event: event)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient = newClient else {
            NSLog("Failed to create ES client: \(result.rawValue)")
            return nil
        }
        return ESFClient(client: newClient)
    }

    /// The events the extension handles while any session exists.
    private static var enforcedEvents: [es_event_type_t] {
        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_UIPC_BIND,
            ES_EVENT_TYPE_AUTH_UIPC_CONNECT,
            ES_EVENT_TYPE_AUTH_LINK,
            ES_EVENT_TYPE_AUTH_CLONE,
            ES_EVENT_TYPE_AUTH_COPYFILE,
            ES_EVENT_TYPE_AUTH_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]
        // SETATTRLIST tracks chmod and chown (macOS 26+).
        if #available(macOS 26.0, *) {
            events.append(ES_EVENT_TYPE_NOTIFY_SETATTRLIST)
        }
        return events
    }

    private let subscriptionQueue = DispatchQueue(label: "dev.diffsec.agentmon.esf-subscription")
    private var subscribed = false

    /// Prepare the client. Events are not subscribed here.
    ///
    /// The extension subscribes only while a session exists. A subscription to
    /// AUTH_OPEN makes the kernel hold every file open on the machine until the
    /// extension answers, however fast the answer is. Measured on a signed
    /// install with no session open: 1000 runs of /bin/cat took 4.5 s
    /// subscribed and 4.0 s with the extension off, and the extension used 8%
    /// CPU. See enableEnforcement and disableEnforcementIfIdle.
    func subscribe() -> Bool {
        guard client != nil else { return false }
        NSLog("ESF client ready; events are subscribed while a session exists")
        return true
    }

    /// Subscribe to the enforced events. Returns once the subscription is in
    /// place, so a caller that is about to fetch a session's policy knows the
    /// extension already sees that session's processes.
    func enableEnforcement() {
        subscriptionQueue.sync {
            guard !subscribed, let client = client else { return }
            let events = Self.enforcedEvents
            let result = es_subscribe(client, events, UInt32(events.count))
            guard result == ES_RETURN_SUCCESS else {
                NSLog("ESFClient: FAILED to subscribe (\(result.rawValue)) -- sessions are not enforced")
                return
            }
            subscribed = true
            // Exits were not seen while unsubscribed, so earlier "outside
            // every session" answers may name reused PIDs.
            SessionPolicyCache.shared.invalidateOutsideSessions()
            NSLog("ESFClient: subscribed, a session is active")
        }
    }

    /// Unsubscribe when no session exists and no snapshot fetch is in flight.
    /// The check runs on the subscription queue, after any pending subscribe,
    /// so a session that registers meanwhile keeps the subscription.
    func disableEnforcementIfIdle() {
        subscriptionQueue.async {
            guard self.subscribed, let client = self.client,
                  !SessionPolicyCache.shared.hasActiveSessions,
                  !SessionPolicyCache.shared.hasPendingFetches else { return }
            let result = es_unsubscribe_all(client)
            guard result == ES_RETURN_SUCCESS else {
                NSLog("ESFClient: failed to unsubscribe (\(result.rawValue))")
                return
            }
            self.subscribed = false
            NSLog("ESFClient: unsubscribed, no session is active")
        }
    }

    // agentmon's own binaries are not muted by path. Muting every process
    // under AgentMon.app/Contents/MacOS let an agent escape all file checks by
    // running one of those binaries, because a muted process reports nothing,
    // its forks included. Only the daemon is muted, by its audit token, once
    // PolicySocketClient.validateServer has checked its signature. That still
    // stops the recursion the path mute was for: the daemon's own execs, such
    // as the codesign it runs to check each policy socket peer, are not
    // reported back to it.

    func stop() {
        if let client = client {
            es_delete_client(client)
            self.client = nil
        }
    }

    // MARK: - Process Muting (Recursion Guard)

    /// Mute a path so ES events are not delivered for processes at that path.
    ///
    /// Nothing calls this today: the wrap-initialization XPC path it was
    /// written for no longer exists, and muteOwnBinaries now covers the bundle
    /// layout automatically. It is kept as the hook for muting a binary
    /// outside the bundle, and corrected to the instigating-program mute type
    /// -- ES_MUTE_PATH_TYPE_TARGET_LITERAL matches syscall arguments, so as
    /// written it did the opposite of what its name says.
    @available(macOS 12.0, *)
    func mutePath(_ path: String) {
        guard let client = client else { return }
        let result = es_mute_path(client, path, ES_MUTE_PATH_TYPE_LITERAL)
        if result != ES_RETURN_SUCCESS {
            NSLog("ESFClient: failed to mute path \(path): \(result.rawValue)")
        } else {
            NSLog("ESFClient: muted path \(path)")
        }
    }

    /// Mute a process and all its descendants so ES events are not delivered for them.
    /// Used for recursion prevention -- agentmon-spawned commands must not be re-intercepted.
    func muteProcess(auditToken: audit_token_t) {
        guard let client = client else { return }
        var token = auditToken
        let result = es_mute_process(client, &token)
        if result != ES_RETURN_SUCCESS {
            NSLog("ESFClient: failed to mute process: \(result.rawValue)")
        } else {
            // Muted processes won't emit ES_EVENT_TYPE_NOTIFY_EXIT, so clean up
            // the audit token cache now to prevent stale entries and unbounded growth.
            let pid = audit_token_to_pid(token)
            cacheQueue.sync {
                _ = auditTokenCache.removeValue(forKey: pid)
            }
        }
    }

    /// Mute a process by PID. Looks up the audit_token from the fork event cache.
    /// Called from the Go side via XPC when the server spawns a command.
    func muteProcessByPID(_ pid: pid_t) {
        let token: audit_token_t? = cacheQueue.sync {
            return auditTokenCache[pid]
        }
        guard let token = token else {
            NSLog("ESFClient: cannot mute PID \(pid): no cached audit token")
            return
        }
        muteProcess(auditToken: token)
    }

    // MARK: - Session Management

    /// Refresh the policy cache for a session after a Darwin notification
    private func refreshCacheForSession(_ sessionID: String) {
        let currentVersion = SessionPolicyCache.shared.versionForSession(sessionID)
        PolicySocketClient.shared.request([
            "type": "fetch_policy_snapshot",
            "session_id": sessionID,
            "version": currentVersion
        ]) { response in
            guard let response = response else { return }
            guard let version = response["version"] as? UInt64 ?? (response["version"] as? Int).map({ UInt64($0) }),
                  version > 0 else { return }
            guard let rootPID = response["root_pid"] as? Int32 ?? (response["root_pid"] as? Int).map({ Int32($0) }) else { return }
            guard let snapshot = SessionCache.from(json: response, sessionID: sessionID, rootPID: rootPID) else {
                NSLog("ESFClient: failed to parse policy snapshot for session \(sessionID)")
                return
            }
            SessionPolicyCache.shared.updateSession(sessionID, snapshot: snapshot)
            NSLog("ESFClient: updated cache for session \(sessionID) to version \(version)")
        }
    }

    // MARK: - NOTIFY Handlers

    fileprivate func handleNotifyFork(_ message: es_message_t, pid: pid_t) {
        // Fast-path: skip all work if no active sessions
        guard SessionPolicyCache.shared.hasActiveSessions else { return }

        // Only track forks from processes in active sessions
        guard SessionPolicyCache.shared.sessionForPID(pid) != nil else { return }

        let childToken = message.event.fork.child.pointee.audit_token
        let childPid = audit_token_to_pid(childToken)

        // Cache audit token for muting
        cacheQueue.sync {
            auditTokenCache[childPid] = childToken
        }

        ProcessHierarchy.shared.recordFork(parentPID: pid, childPID: childPid)
        SessionPolicyCache.shared.addPID(childPid, parentPID: pid)

        PolicySocketClient.shared.sendEvent([
            "type": "file_event",
            "event_type": "process_fork",
            "pid": Int(pid),
            "child_pid": Int(childPid),
            "session_id": SessionPolicyCache.shared.sessionForPID(pid) ?? "",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ])
    }

    fileprivate func handleNotifyExit(_ message: es_message_t, pid: pid_t) {
        // Every exit, in a session or not: the PID can now be reused.
        defer { SessionPolicyCache.shared.forgetExitedPID(pid) }

        // Fast-path: skip all work if no active sessions
        guard SessionPolicyCache.shared.hasActiveSessions else { return }

        // Only clean up PIDs that are in active sessions
        guard SessionPolicyCache.shared.sessionForPID(pid) != nil else { return }

        // Clean up audit token cache
        cacheQueue.sync {
            _ = auditTokenCache.removeValue(forKey: pid)
        }

        PolicySocketClient.shared.sendEvent([
            "type": "file_event",
            "event_type": "process_exit",
            "pid": Int(pid),
            "session_id": SessionPolicyCache.shared.sessionForPID(pid) ?? "",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ])

        SessionPolicyCache.shared.removePID(pid)

        // Clean up hierarchy tracking and invalidate process info cache
        ProcessHierarchy.shared.recordExit(pid: pid)
        ProcessIdentifier.invalidate(pid: pid)
    }

    fileprivate func handleNotifyClose(_ message: es_message_t, pid: pid_t) {
        guard message.event.close.modified else { return }
        guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else { return }

        let path = String(cString: message.event.close.target.pointee.path.data)

        sendFileEvent(
            eventType: "file_write",
            path: path,
            operation: "close_modified",
            pid: pid,
            sessionID: sessionID,
            decision: "observed",
            rule: nil
        )
    }

    @available(macOS 26.0, *)
    fileprivate func handleNotifySetattr(_ message: es_message_t, pid: pid_t) {
        let sessionID = SessionPolicyCache.shared.sessionForPID(pid)
        guard let sessionID = sessionID else { return }

        let path = String(cString: message.event.setattrlist.target.pointee.path.data)
        let attr = message.event.setattrlist.attrlist

        if attr.commonattr & attrgroup_t(ATTR_CMN_OWNERID) != 0 ||
           attr.commonattr & attrgroup_t(ATTR_CMN_GRPID) != 0 {
            sendFileEvent(eventType: "file_chown", path: path, operation: "chown",
                          pid: pid, sessionID: sessionID, decision: "observed", rule: nil)
        }

        if attr.commonattr & attrgroup_t(ATTR_CMN_ACCESSMASK) != 0 {
            sendFileEvent(eventType: "file_chmod", path: path, operation: "chmod",
                          pid: pid, sessionID: sessionID, decision: "observed", rule: nil)
        }
    }
}

// MARK: - Free Function Helpers

/// Build and send a file event dict via the persistent event stream.
/// This is a free function (not a method on ESFClient) so AUTH handlers can call it.
private func sendFileEvent(
    eventType: String,
    path: String,
    operation: String,
    pid: pid_t,
    sessionID: String?,
    decision: String,
    rule: String?,
    action: String? = nil,
    extraFields: [String: Any]? = nil
) {
    var dict: [String: Any] = [
        "type": "file_event",
        "event_type": eventType,
        "path": path,
        "operation": operation,
        "pid": Int(pid),
        "session_id": sessionID ?? "",
        "decision": decision,
        "rule": rule ?? "",
        "timestamp": ISO8601DateFormatter().string(from: Date())
    ]
    if let action = action {
        dict["action"] = action
    }
    if let extra = extraFields {
        for (k, v) in extra {
            dict[k] = v
        }
    }
    PolicySocketClient.shared.sendEvent(dict)
}

// MARK: - Free Function Event Handlers (AUTH)

/// Free function -- no instance state needed for AUTH responses.
/// AUTH handlers use the `client` pointer from the callback (always valid).
/// NOTIFY handlers delegate to ESFClient.shared (best-effort).
private func handleESEvent(client: OpaquePointer, event: UnsafePointer<es_message_t>) {
    let message = event.pointee
    let eventType = message.event_type.rawValue
    let pid = audit_token_to_pid(message.process.pointee.audit_token)

    os_log(.debug, log: esLog, "handleESEvent: type=%{public}d pid=%{public}d", eventType, pid)

    // With no session registered, nothing is enforced, so every AUTH event
    // is allowed at once. This runs before any other work: the extension
    // receives every file open on the machine, and a path copy plus two locks
    // per event, which the daemon-fork check below costs, made every process
    // start measurably slower.
    if !SessionPolicyCache.shared.hasActiveSessions {
        if message.action_type == ES_ACTION_TYPE_AUTH {
            if message.event_type == ES_EVENT_TYPE_AUTH_OPEN {
                es_respond_flags_result(client, event, 0x7FFFFFFF, false)
            } else {
                es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            }
        }
        return
    }

    // The daemon and its forks are not agents. See
    // PolicySocketClient.isDaemonOrFork.
    let process = message.process.pointee
    if PolicySocketClient.shared.isDaemonOrFork(
        token: process.audit_token, parentToken: process.parent_audit_token,
        executablePath: String(cString: process.executable.pointee.path.data)) {
        if message.action_type == ES_ACTION_TYPE_AUTH {
            if message.event_type == ES_EVENT_TYPE_AUTH_OPEN {
                es_respond_flags_result(client, event, 0x7FFFFFFF, false)
            } else {
                es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            }
        }
        return
    }

    switch message.event_type {
    // AUTH events -- MUST always respond via es_respond_auth_result
    case ES_EVENT_TYPE_AUTH_OPEN:
        handleAuthOpen(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_CREATE:
        handleAuthCreate(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_UNLINK:
        handleAuthUnlink(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_RENAME:
        handleAuthRename(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_EXEC:
        handleAuthExec(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_UIPC_BIND:
        handleAuthUIPCBind(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
        handleAuthUIPCConnect(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_LINK:
        handleAuthCopySource(client: client, event: event, pid: pid,
                             source: event.pointee.event.link.source)
    case ES_EVENT_TYPE_AUTH_CLONE:
        handleAuthCopySource(client: client, event: event, pid: pid,
                             source: event.pointee.event.clone.source)
    case ES_EVENT_TYPE_AUTH_COPYFILE:
        handleAuthCopySource(client: client, event: event, pid: pid,
                             source: event.pointee.event.copyfile.source)
    case ES_EVENT_TYPE_AUTH_SIGNAL:
        handleAuthSignal(client: client, event: event, pid: pid)

    // NOTIFY events -- best effort, no response needed
    case ES_EVENT_TYPE_NOTIFY_FORK:
        ESFClient.shared?.handleNotifyFork(message, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        ESFClient.shared?.handleNotifyExit(message, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        ESFClient.shared?.handleNotifyClose(message, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
        if #available(macOS 26.0, *) {
            ESFClient.shared?.handleNotifySetattr(message, pid: pid)
        }
    default:
        // Safety: respond to any unexpected AUTH event to prevent deadline kill
        if event.pointee.action_type == ES_ACTION_TYPE_AUTH {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            os_log(.error, log: esLog, "UNHANDLED AUTH event type=%{public}d pid=%{public}d — allowed as safety fallback", eventType, pid)
        }
    }
}

private func handleAuthOpen(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    // AUTH_OPEN requires es_respond_flags_result, NOT es_respond_auth_result.
    // Using the wrong function returns ES_RESPOND_RESULT_ERR_EVENT_TYPE and
    // leaves the event unanswered, causing the deadline kill.
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_flags_result(client, event, 0x7FFFFFFF, false)
        return
    }

    let path = String(cString: event.pointee.event.open.file.pointee.path.data)

    // Determine operation from open flags
    let fflag = event.pointee.event.open.fflag
    let operation: String
    if (Int32(fflag) & FWRITE) != 0 {
        operation = "write"
    } else {
        operation = "read"
    }

    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: operation, pid: pid)

    if decision == .deny {
        es_respond_flags_result(client, event, 0, false)
    } else {
        es_respond_flags_result(client, event, 0x7FFFFFFF, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_open",
            path: path,
            operation: operation,
            pid: pid,
            sessionID: sessionID,
            decision: decision == .deny ? "deny" : "allow",
            rule: nil
        )
    }
}

private func handleAuthCreate(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let create = event.pointee.event.create
    let path: String
    if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        path = String(cString: create.destination.existing_file.pointee.path.data)
    } else {
        let dir = String(cString: create.destination.new_path.dir.pointee.path.data)
        let filename = String(cString: create.destination.new_path.filename.data)
        path = dir + "/" + filename
    }

    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: "create", pid: pid)
    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_create",
            path: path,
            operation: "create",
            pid: pid,
            sessionID: sessionID,
            decision: decision == .deny ? "deny" : "allow",
            rule: nil
        )
    }
}

private func handleAuthUnlink(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let path = String(cString: event.pointee.event.unlink.target.pointee.path.data)
    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: "delete", pid: pid)

    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_delete",
            path: path,
            operation: "delete",
            pid: pid,
            sessionID: sessionID,
            decision: decision == .deny ? "deny" : "allow",
            rule: nil
        )
    }
}

private func handleAuthRename(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let sourcePath = String(cString: event.pointee.event.rename.source.pointee.path.data)
    let rename = event.pointee.event.rename
    let destPath: String
    if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        destPath = String(cString: rename.destination.existing_file.pointee.path.data)
    } else {
        let dir = String(cString: rename.destination.new_path.dir.pointee.path.data)
        let filename = String(cString: rename.destination.new_path.filename.data)
        destPath = dir + "/" + filename
    }

    let (srcDecision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: sourcePath, operation: "rename", pid: pid)
    let (dstDecision, _) = SessionPolicyCache.shared.evaluateFile(path: destPath, operation: "create", pid: pid)

    let denied = srcDecision == .deny || dstDecision == .deny
    if denied {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_rename",
            path: sourcePath,
            operation: "rename",
            pid: pid,
            sessionID: sessionID,
            decision: denied ? "deny" : "allow",
            rule: nil,
            extraFields: ["path2": destPath]
        )
    }
}

/// Refuse a session process that binds a unix socket in the daemon's
/// directory. A process that binds the policy socket path answers every
/// policy question the extension asks.
private func handleAuthUIPCBind(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard SessionPolicyCache.shared.hasActiveSessions,
          let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let bind = event.pointee.event.uipc_bind
    let dir = String(cString: bind.dir.pointee.path.data)
    let path = dir + "/" + String(cString: bind.filename.data)
    let denied = SessionPolicyCache.touchesControlDirectory(
        path: path, operation: "create", controlDir: PolicySocketClient.shared.controlDirectory)

    es_respond_auth_result(client, event, denied ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)
    if denied {
        sendFileEvent(eventType: "file_create", path: path, operation: "create", pid: pid,
                      sessionID: sessionID, decision: "deny", rule: "protect-agentmon-control-directory")
    }
}

/// Refuse a session process, other than the session's root, a connection to
/// a unix socket in the daemon's directory. Those sockets are the daemon's
/// unix-socket API and the policy socket. Through the API, an agent could
/// create a session with a policy of its choosing.
private func handleAuthUIPCConnect(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard SessionPolicyCache.shared.hasActiveSessions,
          let sessionID = SessionPolicyCache.shared.sessionForPID(pid),
          SessionPolicyCache.shared.cacheForSession(sessionID)?.rootPID != pid else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let path = String(cString: event.pointee.event.uipc_connect.file.pointee.path.data)
    let dir = PolicySocketClient.shared.controlDirectory
    let denied = !dir.isEmpty && path.hasPrefix(dir + "/")
    es_respond_auth_result(client, event, denied ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)
    if denied {
        os_log(.error, log: esLog,
               "denied connect to %{public}s from session pid %{public}d", path, pid)
    }
}

/// Refuse a session process a hard link, clone or copyfile whose source is in
/// the daemon's directory. Each of them reaches the file's content without an
/// open, so without this a session process could copy the local API key out
/// of the directory and read the copy. The session's root is exempt, as it is
/// for reads in evaluateFile.
private func handleAuthCopySource(client: OpaquePointer, event: UnsafePointer<es_message_t>,
                                  pid: pid_t, source: UnsafeMutablePointer<es_file_t>) {
    guard SessionPolicyCache.shared.hasActiveSessions,
          let sessionID = SessionPolicyCache.shared.sessionForPID(pid),
          SessionPolicyCache.shared.cacheForSession(sessionID)?.rootPID != pid else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let path = String(cString: source.pointee.path.data)
    let denied = SessionPolicyCache.touchesControlDirectory(
        path: path, operation: "read", controlDir: PolicySocketClient.shared.controlDirectory)
    es_respond_auth_result(client, event, denied ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)
    if denied {
        os_log(.error, log: esLog,
               "denied a copy of %{public}s from session pid %{public}d", path, pid)
    }
}

/// Refuse a session process that signals the daemon. An agent that kills the
/// daemon could bind the policy socket before launchd restarts it.
private func handleAuthSignal(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    let target = event.pointee.event.signal.target.pointee.audit_token
    guard SessionPolicyCache.shared.hasActiveSessions,
          PolicySocketClient.shared.isValidatedServer(target),
          SessionPolicyCache.shared.sessionForPID(pid) != nil else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    os_log(.error, log: esLog,
           "denied signal %{public}d from session pid %{public}d to the agentmon daemon",
           event.pointee.event.signal.sig, pid)
    es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
}

/// How long to wait for the daemon's exec verdict before failing closed.
///
/// Comfortably inside the ES deadline for AUTH_EXEC, and enormous next to the
/// observed round trip, which is a single unix-socket request on the same
/// machine.
private let execDecisionTimeout: TimeInterval = 2.0

/// Queue for the fail-closed watchdog below. Concurrent: each exec's watchdog
/// is independent and must not be delayed by another's.
private let execWatchdogQueue = DispatchQueue(
    label: "dev.diffsec.agentmon.execwatchdog", attributes: .concurrent)

/// Answers one AUTH message exactly once, from whichever of several racing
/// callers gets there first.
///
/// AUTH_EXEC is answered out of order: the ES handler returns immediately and
/// the verdict is delivered later, from the socket completion or from the
/// watchdog. That requires retaining the message, and it makes a double
/// response possible, so the two are serialised here. Releasing exactly once,
/// after responding, is the other half of the contract.
private final class AuthResponder {
    private let lock = NSLock()
    private var answered = false
    private let client: OpaquePointer
    private let message: UnsafePointer<es_message_t>

    init(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        self.client = client
        self.message = message
        es_retain_message(message)
    }

    /// Returns true if this call was the one that answered.
    @discardableResult
    func respond(_ result: es_auth_result_t) -> Bool {
        lock.lock()
        if answered {
            lock.unlock()
            return false
        }
        answered = true
        lock.unlock()

        es_respond_auth_result(client, message, result, false)
        es_release_message(message)
        return true
    }
}

private func handleAuthExec(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    // Check session membership before string extraction
    guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let execPtr = UnsafeRawPointer(event)
        .advanced(by: MemoryLayout.offset(of: \es_message_t.event)!)
        .assumingMemoryBound(to: es_event_exec_t.self)
    let execPath = String(cString: execPtr.pointee.target.pointee.executable.pointee.path.data)

    // No session process may run the daemon's executable, whatever the
    // policy says. The agentmon CLI controls the daemon, and a session
    // process whose parent is the daemon would otherwise turn into something
    // isDaemonOrFork accepts as a daemon fork.
    if execPath == PolicySocketClient.shared.daemonExecutablePath {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        os_log(.error, log: esLog,
               "denied exec of the agentmon daemon binary by session pid %{public}d", pid)
        return
    }
    let parentPID = event.pointee.process.pointee.ppid

    // Everything the daemon needs is extracted here, while the message is
    // certainly valid, rather than inside the async completion.
    let argc = es_exec_arg_count(execPtr)
    var args: [String] = []
    args.reserveCapacity(Int(argc))
    for i in 0..<argc {
        let arg = es_exec_arg(execPtr, i)
        let len = Int(arg.length)
        if len > 0, let data = arg.data {
            args.append(String(bytes: UnsafeRawBufferPointer(start: data, count: len),
                               encoding: .utf8) ?? String(cString: data))
        } else {
            args.append("")
        }
    }
    var ttyPath: String? = nil
    if let ttyFile = event.pointee.process.pointee.tty {
        ttyPath = String(cString: ttyFile.pointee.path.data)
    }
    let cwdPath = String(cString: execPtr.pointee.cwd.pointee.path.data)

    // Ask the daemon rather than deciding from the local cache.
    //
    // The cache cannot answer this. BuildPolicySnapshot emits no exec rules and
    // never sets defaults.exec, so SessionPolicyCache.evaluateExec found nothing
    // to match and fell through to "allow" -- every exec in every wrapped
    // session was permitted, which is precisely what `agentmon wrap` exists to
    // prevent. Projecting command_rules into the snapshot would mean
    // re-implementing the policy engine here, and it would be lossy: no
    // argument filtering, no command_overrides, no process contexts, no
    // ancestry. A local matcher that answers "allow" where the engine says
    // "deny" is a silent fail-open. The daemon is authoritative, the Go side of
    // this check already exists (RequestTypeExecCheck -> PolicyAdapter.CheckExec)
    // and had no caller, and exec is rare enough to afford a round trip.
    //
    // The response is delivered out of order so this handler returns at once. A
    // synchronous wait here would block ES message delivery for the whole
    // client, so one hung daemon would stall AUTH_OPEN too and cascade into
    // deadline kills -- losing all enforcement rather than one exec.
    let responder = AuthResponder(client: client, message: event)

    // Fail closed if no verdict arrives. Allowing on timeout would mean a slow
    // or dead daemon silently turns command policy off.
    execWatchdogQueue.asyncAfter(deadline: .now() + execDecisionTimeout) {
        if responder.respond(ES_AUTH_RESULT_DENY) {
            os_log(.error, log: esLog,
                   "exec check timed out for pid %{public}d -- denied (fail closed)", pid)
        }
    }

    PolicySocketClient.shared.request([
        "type": "exec_check",
        "path": execPath,
        "args": args,
        "pid": Int(pid),
        "parent_pid": Int(parentPID),
        "session_id": sessionID,
        "tty_path": ttyPath ?? "",
        "cwd_path": cwdPath
    ]) { response in
        switch response?["action"] as? String {
        case "continue":
            responder.respond(ES_AUTH_RESULT_ALLOW)

        case "redirect":
            // Deny the exec, then have the server spawn the stub in its place.
            responder.respond(ES_AUTH_RESULT_DENY)
            PolicySocketClient.shared.send([
                "type": "exec_redirect_notify",
                "path": execPath,
                "args": args,
                "pid": Int(pid),
                "parent_pid": Int(parentPID),
                "session_id": sessionID,
                "tty_path": ttyPath ?? "",
                "cwd_path": cwdPath
            ])

        case "deny":
            responder.respond(ES_AUTH_RESULT_DENY)

        default:
            // A nil response is a socket failure; an unrecognised action is
            // protocol drift. Neither is evidence that the exec is permitted.
            if responder.respond(ES_AUTH_RESULT_DENY) {
                os_log(.error, log: esLog,
                       "exec check for pid %{public}d got no usable verdict -- denied (fail closed)", pid)
            }
        }
    }

    // Track exec depth for recursion monitoring (best-effort, after response)
    let _ = SessionPolicyCache.shared.recordExecDepth(pid: pid, parentPID: parentPID)
}
