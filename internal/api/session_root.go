package api

import (
	"log/slog"
	"os"
	"time"
)

// interceptionReadyTimeout bounds how long a command waits for the system
// extension to pick up its session's policy.
//
// Generous against the observed round trip -- a notify_post plus one
// unix-socket request, tens of milliseconds -- so a loaded machine does not
// give up on a session that was going to work. It is paid at most once per
// session: SessionTracker.AwaitSnapshot returns immediately for a session it
// has already delivered or already given up on.
const interceptionReadyTimeout = 3 * time.Second

// registerSessionRoot registers the server as the session root with the system
// extension and waits for the extension to hold the session's policy.
//
// This runs BEFORE the command is started, and the ordering is the whole point.
// Registration only posts a Darwin notification; the extension then fetches the
// snapshot asynchronously, and until it lands SessionPolicyCache maps none of
// the session's PIDs, so ESFClient's AUTH handlers allow everything. Doing this
// after cmd.Start let the first command of a fresh session win that race and
// run completely unenforced -- reproducible by creating a session and
// immediately reading a file the policy denies: the first attempt succeeded and
// the second was refused.
//
// The server PID is the root because every command is spawned as its child, so
// the extension can attribute the whole tree from FORK events.
//
// A timeout does NOT fail the command. Unlike `agentmon wrap`, whose entire
// contract is interception, `agentmon exec` is expected to run on hosts with no
// system extension at all -- every Linux host, and any Mac where it is not
// installed. Refusing there would break the normal case to close a gap that
// only exists on macOS. The gap is logged instead, once per session, and
// command policy is still enforced by the pre-spawn policy check either way.
func registerSessionRoot(extra *extraProcConfig, sessionID string) {
	if extra == nil || extra.sessionTracker == nil || sessionID == "" {
		return
	}

	// ppid 0 marks this as a session root rather than a tracked child.
	extra.sessionTracker.RegisterProcess(sessionID, int32(os.Getpid()), 0)
	notifySessionRegistered()

	if extra.sessionTracker.AwaitSnapshot(sessionID, interceptionReadyTimeout) {
		return
	}
	slog.Warn("system extension did not pick up this session's policy; file and network rules are unenforced for it",
		"session_id", sessionID,
		"waited", interceptionReadyTimeout)
}
