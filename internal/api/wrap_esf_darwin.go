//go:build darwin

package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/diffsec/agentmon/internal/platform/darwin"
	"github.com/diffsec/agentmon/pkg/types"
)

// platformWrapInit completes wrap-init on macOS.
//
// There is no per-process wrapper to hand back. Interception is done by the
// system extension, which polices a process if SessionPolicyCache can map its
// PID to a session. That map is seeded from the root_pid in the policy
// snapshot and extended down the process tree by NOTIFY_FORK, so the whole
// job here is to register the caller's PID as the session root: the agent is
// launched as its child, and every descendant follows.
//
// Until now this returned 400 "wrap is only supported on Linux", so
// `agentmon wrap` on macOS could not work at all -- before Phase 2 it fell
// through to launching the agent with no interception whatsoever.
//
// Registration is refused unless the extension is verifiably running. A
// session registered against a dead extension is worse than a failure: the
// server reports the agent as wrapped, the audit log shows a wrapped session,
// and nothing is enforced. `agentmon wrap` turns this error into a non-zero
// exit unless the operator passes --allow-unenforced.
func platformWrapInit(a *App, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	if a.sessionTracker == nil {
		return types.WrapInitResponse{}, http.StatusServiceUnavailable,
			fmt.Errorf("wrap: the policy socket server is not running, so no session can be registered with the system extension")
	}
	if req.CallerPID <= 0 {
		return types.WrapInitResponse{}, http.StatusBadRequest,
			fmt.Errorf("wrap: caller_pid is required on macOS (got %d); it becomes the session root the extension attributes processes to", req.CallerPID)
	}

	// Same probe `agentmon detect` reports from, so the two cannot disagree
	// about whether macOS is enforcing.
	//
	// Running is not merely "launchd says the process exists": see
	// CheckSysExtLiveness, which rejects a process whose pid changes between
	// samples. That is what a crash-looping extension looks like -- one denied
	// Full Disk Access fails es_new_client, retries three times, exits 1, and
	// is respawned -- and launchd reports it as "running" for part of every
	// cycle.
	live := darwin.CheckSysExtLiveness()
	if !live.Running {
		return types.WrapInitResponse{}, http.StatusServiceUnavailable,
			fmt.Errorf("wrap: the agentmon system extension is not enforcing, so nothing would constrain this session (%s)", live.Detail)
	}

	// ppid 0 marks this as a session root rather than a tracked child.
	a.sessionTracker.RegisterProcess(sessionID, int32(req.CallerPID), 0)

	// Registering with the tracker only makes the session answerable; it does
	// not tell the extension the session exists. The extension learns that from
	// this Darwin notification, which makes it fetch a policy snapshot -- and
	// until it holds one, SessionPolicyCache maps no PID to a session and
	// ESFClient's AUTH handlers allow everything.
	//
	// This is a parity fix, not a measured one. exec.go and exec_stream.go have
	// always posted it after RegisterProcess; wrap-init never did. It could not
	// be demonstrated end to end on hardware, because the extension only
	// receives these notifications while its connection to the daemon is fresh
	// -- after a daemon restart it reconnects to nothing, and both wrap and
	// exec sessions then enforce nothing at all. That is a separate, known
	// defect; this line is what wrap needs once it is fixed.
	notifySessionRegistered()

	// Wait for the extension to actually hold the policy before letting the
	// agent start.
	//
	// Posting the notification is not enforcement. The extension fetches the
	// snapshot asynchronously, and until it lands SessionPolicyCache maps none
	// of this session's PIDs, so ESFClient's AUTH handlers allow everything.
	// Measured on hardware: a wrapped agent's first second ran completely
	// unenforced -- a `whoami` the policy denies succeeded, and so did a read of
	// a denied file, while a curl a few hundred milliseconds later was blocked
	// correctly. An agent's first actions are exactly the ones worth policing.
	if !a.sessionTracker.AwaitSnapshot(sessionID, interceptionReadyTimeout) {
		// Undo the registration. A refused wrap-init must leave nothing behind:
		// the server is telling the caller this session is not wrapped, and a
		// session root left registered would have the extension attributing
		// processes to a session the server considers unwrapped.
		a.sessionTracker.EndSession(sessionID)
		return types.WrapInitResponse{}, http.StatusServiceUnavailable,
			fmt.Errorf("wrap: the system extension did not pick up this session's policy within %s, so the agent would start unconstrained", interceptionReadyTimeout)
	}

	slog.Info("registered wrap session root with the system extension",
		"session_id", sessionID,
		"root_pid", req.CallerPID)

	// Empty WrapperBinary tells platformSetupWrap to exec the agent directly.
	return types.WrapInitResponse{}, http.StatusOK, nil
}
