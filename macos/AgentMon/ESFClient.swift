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

    /// Subscribe to ES events. Must be called AFTER ESFClient.shared is set.
    func subscribe() -> Bool {
        guard let client = client else { return false }

        let authEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_EXEC
        ]
        let notifyEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]
        let allEvents = authEvents + notifyEvents
        let subscribeResult = es_subscribe(client, allEvents, UInt32(allEvents.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            NSLog("Failed to subscribe: \(subscribeResult.rawValue)")
            return false
        }
        NSLog("ESF client subscribed successfully")

        // Subscribe to SETATTRLIST events for chmod/chown tracking (macOS 26+)
        if #available(macOS 26.0, *) {
            let setAttrEvents: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_SETATTRLIST]
            es_subscribe(client, setAttrEvents, UInt32(setAttrEvents.count))
        }

        muteOwnBinaries(client: client)
        return true
    }

    /// Stop ES delivering events caused by agentmon's own binaries.
    ///
    /// Without this the enforcement machinery polices itself: agentmon-stub and
    /// agentmon-macwrap run as children of the agent, so they are inside the
    /// tracked session, and their own reads and execs are evaluated against the
    /// session's policy. A policy that denies what the wrapper needs breaks the
    /// wrapper rather than the agent.
    ///
    /// This replaces two hardcoded paths that could not have worked, for two
    /// separate reasons:
    ///
    ///   - They were /usr/local/bin/agentmon and /usr/local/bin/agentmon-stub.
    ///     The binaries install to AgentMon.app/Contents/MacOS, and muting
    ///     happens after symlink resolution, so even the Homebrew cask's
    ///     symlinks resolve elsewhere. Neither path exists on a real install.
    ///
    ///   - They used ES_MUTE_PATH_TYPE_TARGET_LITERAL, which matches the
    ///     *arguments to syscalls*, not the process making them. It would have
    ///     muted events about someone opening the agentmon binary -- the
    ///     opposite of a recursion guard. ES_MUTE_PATH_TYPE_PREFIX is the
    ///     instigating-program form.
    private func muteOwnBinaries(client: OpaquePointer) {
        guard let dir = Self.helperBinaryDirectory() else {
            NSLog("ESFClient: could not locate the app bundle; agentmon's own binaries are NOT muted and will be policed by session policy")
            return
        }
        let result = es_mute_path(client, dir, ES_MUTE_PATH_TYPE_PREFIX)
        if result == ES_RETURN_SUCCESS {
            NSLog("ESFClient: muted agentmon binaries under \(dir)")
        } else {
            NSLog("ESFClient: failed to mute \(dir): \(result.rawValue)")
        }
    }

    /// The directory holding agentmon's executables, resolved from wherever
    /// this extension is actually installed rather than assumed.
    ///
    /// The system extension lives at
    ///   AgentMon.app/Contents/Library/SystemExtensions/<id>.systemextension
    /// so the app bundle is found by walking up to the enclosing .app. The path
    /// is resolved because ES matches after symlink resolution.
    static func helperBinaryDirectory() -> String? {
        var url = Bundle.main.bundleURL.resolvingSymlinksInPath()
        for _ in 0..<8 {
            if url.pathExtension == "app" {
                return url.appendingPathComponent("Contents/MacOS").path
            }
            let parent = url.deletingLastPathComponent()
            if parent.path == url.path { break }
            url = parent
        }
        // Not inside an app bundle -- a development build run directly. Mute
        // the extension executable's own directory, which is where a locally
        // built agentmon sits next to it.
        return Bundle.main.executableURL?
            .resolvingSymlinksInPath()
            .deletingLastPathComponent()
            .path
    }

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
