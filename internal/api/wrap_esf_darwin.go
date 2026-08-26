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
	live := darwin.CheckSysExtLiveness()
	if !live.Running {
		return types.WrapInitResponse{}, http.StatusServiceUnavailable,
			fmt.Errorf("wrap: the agentmon system extension is not running, so nothing would enforce policy on this session (%s)", live.Detail)
	}

	// ppid 0 marks this as a session root rather than a tracked child.
	a.sessionTracker.RegisterProcess(sessionID, int32(req.CallerPID), 0)
	slog.Info("registered wrap session root with the system extension",
		"session_id", sessionID,
		"root_pid", req.CallerPID)

	// Empty WrapperBinary tells platformSetupWrap to exec the agent directly.
	return types.WrapInitResponse{}, http.StatusOK, nil
}
