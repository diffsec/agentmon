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
        [
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
            // A task control or read port lets its holder read the target's
            // memory, and the control port also lets it write the memory and
            // start threads. pid_suspend stops a process. A session process
            // must not do any of this to a process outside its session.
            ES_EVENT_TYPE_AUTH_GET_TASK,
            ES_EVENT_TYPE_AUTH_GET_TASK_READ,
            ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
            // Each of these changes a file without an open for writing, so
            // AUTH_OPEN never sees them. On build 1669, truncate() and chmod()
            // on a file outside the workspace succeeded in an agent-default
            // session, where a write to the same file was refused.
            ES_EVENT_TYPE_AUTH_TRUNCATE,
            ES_EVENT_TYPE_AUTH_SETMODE,
            ES_EVENT_TYPE_AUTH_SETOWNER,
            ES_EVENT_TYPE_AUTH_SETFLAGS,
            ES_EVENT_TYPE_AUTH_SETACL,
            ES_EVENT_TYPE_AUTH_SETEXTATTR,
            ES_EVENT_TYPE_AUTH_DELETEEXTATTR,
            ES_EVENT_TYPE_AUTH_SETATTRLIST,
            ES_EVENT_TYPE_AUTH_UTIMES,
            ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]
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
            "timestamp": eventTimestampFormatter.string(from: Date())
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
            "timestamp": eventTimestampFormatter.string(from: Date())
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
}

// MARK: - Free Function Helpers

/// Build and send a file event dict via the persistent event stream.
/// This is a free function (not a method on ESFClient) so AUTH handlers can call it.
/// One formatter for every event timestamp. Creating an ISO8601DateFormatter
/// is expensive, and it used to happen once per event, which in a session is
/// once per file open. ISO8601DateFormatter is safe to use from several
/// threads.
private let eventTimestampFormatter = ISO8601DateFormatter()

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
        "timestamp": eventTimestampFormatter.string(from: Date())
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

/// The path of an ES file.
private func path(of file: UnsafeMutablePointer<es_file_t>) -> String {
    String(cString: file.pointee.path.data)
}

/// The text of an ES string token. A token is not always NUL-terminated, so
/// it is read by its length.
private func string(_ token: es_string_token_t) -> String {
    guard token.length > 0, let data = token.data else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: data, count: token.length), as: UTF8.self)
}

/// The policy operation names for ES file events. They are the names that
/// the Go engine uses (see isReadOperation in internal/policy/engine.go), so
/// a rule that names an operation matches on macOS as it does on Linux.
enum FileOperation {
    /// AUTH_CREATE reports open with O_CREAT, mkdir and symlink. The type
    /// bits of the new object's mode tell them apart.
    static func forCreate(mode: mode_t) -> String {
        switch mode & S_IFMT {
        case S_IFDIR: return "mkdir"
        case S_IFLNK: return "symlink"
        default: return "create"
        }
    }

    /// AUTH_UNLINK reports both unlink and rmdir.
    static func forUnlink(mode: mode_t) -> String {
        mode & S_IFMT == S_IFDIR ? "rmdir" : "delete"
    }

    /// The operations that one setattrlist call performs. Owner and group
    /// changes are chown. Mode, flag and ACL changes are chmod. Every other
    /// attribute, such as the times or the Finder information, is a write.
    static func forSetattrlist(_ attrs: attrlist) -> [String] {
        let owner = attrgroup_t(ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_UUID | ATTR_CMN_GRPUUID)
        let mode = attrgroup_t(ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS | ATTR_CMN_EXTENDED_SECURITY)
        var ops: [String] = []
        if attrs.commonattr & owner != 0 { ops.append("chown") }
        if attrs.commonattr & mode != 0 { ops.append("chmod") }
        if attrs.commonattr & ~(owner | mode) != 0 || attrs.volattr != 0 || attrs.dirattr != 0
            || attrs.fileattr != 0 || attrs.forkattr != 0 {
            ops.append("write")
        }
        return ops.isEmpty ? ["write"] : ops
    }

    /// The daemon's event type for an operation.
    static func eventType(for operation: String) -> String {
        switch operation {
        case "mkdir": return "dir_create"
        case "rmdir": return "dir_delete"
        case "delete": return "file_delete"
        case "chmod": return "file_chmod"
        case "chown": return "file_chown"
        case "create", "link", "symlink": return "file_create"
        default: return "file_write"
        }
    }
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
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            let link = e.link
            let target = path(of: link.target_dir) + "/" + string(link.target_filename)
            return [(path(of: link.source), "read"), (target, "link")]
        }
    case ES_EVENT_TYPE_AUTH_CLONE:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            let clone = e.clone
            let target = path(of: clone.target_dir) + "/" + string(clone.target_name)
            return [(path(of: clone.source), "read"), (target, "create")]
        }
    case ES_EVENT_TYPE_AUTH_COPYFILE:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            let copy = e.copyfile
            let target = copy.target_file.map { path(of: $0) }
                ?? path(of: copy.target_dir) + "/" + string(copy.target_name)
            return [(path(of: copy.source), "read"), (target, copy.target_file == nil ? "create" : "write")]
        }
    case ES_EVENT_TYPE_AUTH_SIGNAL:
        handleAuthSignal(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_GET_TASK:
        handleAuthProcessAccess(client: client, event: event, pid: pid,
                                target: event.pointee.event.get_task.target, operation: "get_task")
    case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
        handleAuthProcessAccess(client: client, event: event, pid: pid,
                                target: event.pointee.event.get_task_read.target, operation: "get_task_read")
    case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
        let e = event.pointee.event.proc_suspend_resume
        handleAuthProcessAccess(client: client, event: event, pid: pid, target: e.target,
                                operation: processSuspendResumeOperation(e.type))
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.truncate.target), "write")]
        }
    case ES_EVENT_TYPE_AUTH_SETMODE:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.setmode.target), "chmod")]
        }
    case ES_EVENT_TYPE_AUTH_SETOWNER:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.setowner.target), "chown")]
        }
    case ES_EVENT_TYPE_AUTH_SETFLAGS:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.setflags.target), "chmod")]
        }
    case ES_EVENT_TYPE_AUTH_SETACL:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.setacl.target), "chmod")]
        }
    case ES_EVENT_TYPE_AUTH_SETEXTATTR:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.setextattr.target), "write")]
        }
    case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.deleteextattr.target), "write")]
        }
    case ES_EVENT_TYPE_AUTH_SETATTRLIST:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            let target = path(of: e.setattrlist.target)
            return FileOperation.forSetattrlist(e.setattrlist.attrlist).map { (target, $0) }
        }
    case ES_EVENT_TYPE_AUTH_UTIMES:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.utimes.target), "write")]
        }
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
        handleAuthFileChange(client: client, event: event, pid: pid) { e in
            [(path(of: e.exchangedata.file1), "write"), (path(of: e.exchangedata.file2), "write")]
        }

    // NOTIFY events -- best effort, no response needed
    case ES_EVENT_TYPE_NOTIFY_FORK:
        ESFClient.shared?.handleNotifyFork(message, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        ESFClient.shared?.handleNotifyExit(message, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        ESFClient.shared?.handleNotifyClose(message, pid: pid)
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
    let operation: String
    if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        path = String(cString: create.destination.existing_file.pointee.path.data)
        operation = "create"
    } else {
        let dir = String(cString: create.destination.new_path.dir.pointee.path.data)
        path = dir + "/" + string(create.destination.new_path.filename)
        operation = FileOperation.forCreate(mode: create.destination.new_path.mode)
    }

    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: operation, pid: pid)
    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: FileOperation.eventType(for: operation),
            path: path,
            operation: operation,
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

    let target = event.pointee.event.unlink.target.pointee
    let path = String(cString: target.path.data)
    let operation = FileOperation.forUnlink(mode: target.stat.st_mode)
    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: operation, pid: pid)

    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: FileOperation.eventType(for: operation),
            path: path,
            operation: operation,
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
        destPath = dir + "/" + string(rename.destination.new_path.filename)
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

/// Check a unix socket bind by a session process.
///
/// A bind in the daemon's directory is refused whatever the policy says. A
/// process that binds the policy socket path answers every policy question
/// the extension asks. Any other bind is checked against the session's
/// unix_socket_rules.
private func handleAuthUIPCBind(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard SessionPolicyCache.shared.hasActiveSessions,
          let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let bind = event.pointee.event.uipc_bind
    let dir = String(cString: bind.dir.pointee.path.data)
    let path = dir + "/" + string(bind.filename)
    if SessionPolicyCache.touchesControlDirectory(
        path: path, operation: "create", controlDir: PolicySocketClient.shared.controlDirectory) {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        sendFileEvent(eventType: "file_create", path: path, operation: "create", pid: pid,
                      sessionID: sessionID, decision: "deny", rule: "protect-agentmon-control-directory")
        return
    }
    let (decision, rule) = SessionPolicyCache.shared.evaluateUnixSocket(
        sessionID: sessionID, path: path, operation: "bind")
    es_respond_auth_result(client, event, decision == .deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)
    if decision == .deny {
        sendUnixSocketEvent(path: path, operation: "bind", pid: pid, sessionID: sessionID, rule: rule)
    }
}

/// Report a unix socket operation that the policy denied, with the event
/// type that the Linux unix socket monitor uses.
private func sendUnixSocketEvent(path: String, operation: String, pid: pid_t, sessionID: String, rule: String?) {
    sendFileEvent(eventType: "unix_socket_op", path: path, operation: operation, pid: pid,
                  sessionID: sessionID, decision: "deny", rule: rule)
}

/// Check a unix socket connect by a session process.
///
/// A connect to a socket in the daemon's directory is decided first, whatever
/// the policy says. Those sockets are the daemon's unix-socket API and the
/// policy socket. Through the API, an agent could create a session with a
/// policy of its choosing. So only the session's root can connect, because
/// for `agentmon wrap` the root is the CLI that talks to the daemon. Any
/// other connect is checked against the session's unix_socket_rules.
private func handleAuthUIPCConnect(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard SessionPolicyCache.shared.hasActiveSessions,
          let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let path = String(cString: event.pointee.event.uipc_connect.file.pointee.path.data)
    let dir = PolicySocketClient.shared.controlDirectory
    if !dir.isEmpty && path.hasPrefix(dir + "/") {
        let isRoot = SessionPolicyCache.shared.cacheForSession(sessionID)?.rootPID == pid
        es_respond_auth_result(client, event, isRoot ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
        if !isRoot {
            os_log(.error, log: esLog,
                   "denied connect to %{public}s from session pid %{public}d", path, pid)
        }
        return
    }
    let (decision, rule) = SessionPolicyCache.shared.evaluateUnixSocket(
        sessionID: sessionID, path: path, operation: "connect")
    es_respond_auth_result(client, event, decision == .deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)
    if decision == .deny {
        sendUnixSocketEvent(path: path, operation: "connect", pid: pid, sessionID: sessionID, rule: rule)
    }
}

/// Check a file change that AUTH_OPEN does not see against the session
/// policy, and answer the event.
///
/// `accesses` lists each path the change touches with its policy operation.
/// The change is refused if any access is denied. A hard link, clone or
/// copyfile reaches a file's content without an open, so each of them checks
/// `read` on the source as well as the operation on the new name. Without
/// that, clonefile() copied ~/.ssh/known_hosts into the workspace on build
/// 1669, and the copy was readable.
///
/// The access list is built only for a session process. These events fire
/// for every process on the machine while a session exists, and most of them
/// come from processes outside every session.
private func handleAuthFileChange(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t,
                                  accesses: (es_events_t) -> [(path: String, operation: String)]) {
    guard SessionPolicyCache.shared.sessionForPID(pid) != nil else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let checks = accesses(event.pointee.event)
    var sessionID: String?
    var denied: (path: String, operation: String)?
    for check in checks {
        let (decision, sid) = SessionPolicyCache.shared.evaluateFile(
            path: check.path, operation: check.operation, pid: pid)
        sessionID = sessionID ?? sid
        if decision == .deny {
            denied = check
            break
        }
    }
    es_respond_auth_result(client, event, denied == nil ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)

    guard let sessionID = sessionID, let last = checks.last else { return }
    // The event names the file that changes. For a link, clone or copy,
    // path2 names the source.
    var extra: [String: Any]? = nil
    if checks.count > 1 {
        extra = ["path2": checks[0].path]
    }
    sendFileEvent(
        eventType: FileOperation.eventType(for: last.operation),
        path: last.path,
        operation: last.operation,
        pid: pid,
        sessionID: sessionID,
        decision: denied == nil ? "allow" : "deny",
        rule: nil,
        extraFields: extra
    )
}

/// Check a signal from a session process.
///
/// A signal to the daemon is refused whatever the policy says. An agent that
/// kills the daemon could bind the policy socket before launchd restarts it.
/// Any other signal is checked against the session's signal_rules.
private func handleAuthSignal(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard SessionPolicyCache.shared.hasActiveSessions,
          let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let sig = event.pointee.event.signal.sig
    let target = event.pointee.event.signal.target.pointee
    if PolicySocketClient.shared.isValidatedServer(target.audit_token) {
        os_log(.error, log: esLog,
               "denied signal %{public}d from session pid %{public}d to the agentmon daemon", sig, pid)
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        return
    }

    let source = event.pointee.process.pointee
    let targetPID = audit_token_to_pid(target.audit_token)
    let targetPath = String(cString: target.executable.pointee.path.data)
    let result = SessionPolicyCache.shared.evaluateSignal(
        sessionID: sessionID, signal: sig, sourcePID: pid, sourcePPID: source.ppid,
        targetPID: targetPID, targetPPID: target.ppid,
        targetCmd: (targetPath as NSString).lastPathComponent,
        sameUser: audit_token_to_euid(source.audit_token) == audit_token_to_euid(target.audit_token))
    es_respond_auth_result(client, event, result.allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)

    // Report what the policy refused or asked to audit, with the event types
    // and fields that the Linux signal handler uses.
    guard !result.allowed || result.action == "audit" else { return }
    sendFileEvent(
        eventType: result.allowed ? "signal_sent" : "signal_blocked",
        path: targetPath,
        operation: "signal",
        pid: pid,
        sessionID: sessionID,
        decision: result.allowed ? "audit" : "deny",
        rule: result.rule,
        extraFields: ["fields": [
            "source_pid": Int(pid),
            "target_pid": Int(targetPID),
            "signal": Int(sig),
        ] as [String: Any]]
    )
}

/// The operation name that a process_access event reports for a
/// pid_suspend, pid_resume or pid_shutdown_sockets call.
private func processSuspendResumeOperation(_ type: es_proc_suspend_resume_type_t) -> String {
    switch type {
    case ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND: return "suspend"
    case ES_PROC_SUSPEND_RESUME_TYPE_RESUME: return "resume"
    case ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS: return "shutdown_sockets"
    default: return "suspend_resume"
    }
}

/// Check a task port request or a suspend, resume or socket shutdown from a
/// session process.
///
/// No policy rule type covers these calls. A session process can do them to
/// itself and to the processes of its own session. Every other target is
/// denied, because the port gives full access to the target's memory.
///
/// macOS already refuses these calls to a process of another user, and to a
/// platform binary, unless the caller is root. So the deny matters mostly for
/// a session process that runs as root.
private func handleAuthProcessAccess(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t,
                                     target: UnsafeMutablePointer<es_process_t>?, operation: String) {
    guard SessionPolicyCache.shared.hasActiveSessions,
          let sessionID = SessionPolicyCache.shared.sessionForPID(pid),
          let target = target?.pointee else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let targetPID = audit_token_to_pid(target.audit_token)
    let allowed = SessionPolicyCache.processAccessAllowed(
        sourcePID: pid, targetPID: targetPID,
        sourceSession: sessionID, targetSession: SessionPolicyCache.shared.sessionForPID(targetPID))
    // No caching: the target can join or leave the session later.
    es_respond_auth_result(client, event, allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
    guard !allowed else { return }

    let targetPath = String(cString: target.executable.pointee.path.data)
    os_log(.info, log: esLog,
           "denied %{public}@ from session pid %{public}d to pid %{public}d (%{public}@) outside the session",
           operation, pid, targetPID, targetPath)
    sendFileEvent(
        eventType: "process_access_blocked",
        path: targetPath,
        operation: operation,
        pid: pid,
        sessionID: sessionID,
        decision: "deny",
        rule: "deny-outside-process-access",
        extraFields: ["fields": [
            "source_pid": Int(pid),
            "target_pid": Int(targetPID),
        ] as [String: Any]]
    )
}

/// Record an exec that the daemon's policy denied, as the Linux execve
/// handler does. Without it, a denied exec under `agentmon wrap` left no
/// trace: the process died, and no event said why (SECENG-311).
private func sendExecDeniedEvent(path: String, args: [String], pid: pid_t, parentPID: pid_t,
                                 sessionID: String, rule: String?, message: String?) {
    var fields: [String: Any] = ["argv": args, "parent_pid": Int(parentPID)]
    if let message = message, !message.isEmpty {
        fields["message"] = message
    }
    sendFileEvent(
        eventType: "execve",
        path: path,
        operation: "exec",
        pid: pid,
        sessionID: sessionID,
        decision: "deny",
        rule: rule,
        action: "blocked",
        extraFields: ["fields": fields]
    )
}

/// The shortest wait for the daemon's exec verdict before failing closed.
///
/// Enormous next to the observed round trip, which is a single unix-socket
/// request on the same machine. A package install needs longer, because the
/// daemon resolves it and asks the package providers. See execWaitTime.
private let execDecisionTimeout: TimeInterval = 2.0

/// The longest wait for the daemon's exec verdict.
private let execDecisionMaxWait: TimeInterval = 30.0

/// Time kept free before the ES deadline. The extension must answer before
/// it, or ES ends the extension's client.
private let execDeadlineMargin: TimeInterval = 1.0

/// Words that start a package install in the package managers that the
/// daemon checks: npm, pnpm, yarn, pip, uv and poetry.
private let packageInstallWords: Set<String> = ["install", "i", "add", "ci", "sync"]

/// Whether an exec can be a package install, from its arguments. A false
/// answer for a real install is safe: the daemon then has 1.5 s, and an
/// unfinished check denies the exec.
private func execMayBePackageInstall(_ args: [String]) -> Bool {
    args.dropFirst().contains { packageInstallWords.contains($0) }
}

/// How long to wait for the daemon's exec verdict: until execDeadlineMargin
/// before the message's ES deadline, but no longer than execDecisionMaxWait.
/// When the deadline leaves less than execDecisionTimeout, the wait ends
/// 0.2 s before the deadline.
private func execWaitTime(_ message: UnsafePointer<es_message_t>) -> TimeInterval {
    var timebase = mach_timebase_info_data_t()
    mach_timebase_info(&timebase)
    let now = mach_absolute_time()
    let deadline = message.pointee.deadline
    guard deadline > now, timebase.denom != 0 else { return execDecisionTimeout }
    let ticks = Double(deadline - now)
    let remaining = ticks * Double(timebase.numer) / Double(timebase.denom) / 1e9
    let wait = min(remaining - execDeadlineMargin, execDecisionMaxWait)
    if wait >= execDecisionTimeout {
        return wait
    }
    return max(min(execDecisionTimeout, remaining - 0.2), 0.1)
}

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
    // For a script, ES reports the interpreter as the target. The daemon
    // needs the script to see `pip3 install x` as a package install.
    var scriptPath = ""
    if event.pointee.version >= 2, let script = execPtr.pointee.script {
        scriptPath = String(cString: script.pointee.path.data)
    }
    // An exec that can be a package install may need seconds: the daemon
    // resolves the install and asks the package providers. Only such an
    // exec waits longer, on a connection of its own. Every other exec keeps
    // the 2 s limit. If this test misses an install, the daemon has 1.5 s
    // for the check, and an unfinished check denies the exec.
    let mayInstall = execMayBePackageInstall(args)
    let waitTime = mayInstall ? execWaitTime(event) : execDecisionTimeout

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
    execWatchdogQueue.asyncAfter(deadline: .now() + waitTime) {
        if responder.respond(ES_AUTH_RESULT_DENY) {
            os_log(.error, log: esLog,
                   "exec check timed out for pid %{public}d -- denied (fail closed)", pid)
        }
    }

    let execRequest: [String: Any] = [
        "type": "exec_check",
        "path": execPath,
        "args": args,
        "pid": Int(pid),
        "parent_pid": Int(parentPID),
        "session_id": sessionID,
        "tty_path": ttyPath ?? "",
        "cwd_path": cwdPath,
        "script": scriptPath,
        "deadline_ms": Int(waitTime * 1000)
    ]
    let onVerdict: ([String: Any]?) -> Void = { response in
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
            if responder.respond(ES_AUTH_RESULT_DENY) {
                sendExecDeniedEvent(path: execPath, args: args, pid: pid, parentPID: parentPID,
                                    sessionID: sessionID, rule: response?["rule"] as? String,
                                    message: response?["message"] as? String)
            }

        default:
            // A nil response is a socket failure; an unrecognised action is
            // protocol drift. Neither is evidence that the exec is permitted.
            if responder.respond(ES_AUTH_RESULT_DENY) {
                os_log(.error, log: esLog,
                       "exec check for pid %{public}d got no usable verdict -- denied (fail closed)", pid)
            }
        }
    }
    if mayInstall {
        PolicySocketClient.shared.requestOnce(execRequest, timeout: waitTime, completion: onVerdict)
    } else {
        PolicySocketClient.shared.request(execRequest, completion: onVerdict)
    }

    // Track exec depth for recursion monitoring (best-effort, after response)
    let _ = SessionPolicyCache.shared.recordExecDepth(pid: pid, parentPID: parentPID)
}
