//go:build darwin

package api

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/platform/darwin"
	"github.com/diffsec/agentmon/pkg/types"
)

type recordingTracker struct {
	mu         sync.Mutex
	registered []struct {
		sessionID string
		pid, ppid int32
	}
	ended []string
}

func (r *recordingTracker) RegisterProcess(sessionID string, pid, ppid int32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registered = append(r.registered, struct {
		sessionID string
		pid, ppid int32
	}{sessionID, pid, ppid})
}

func (r *recordingTracker) EndSession(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = append(r.ended, sessionID)
}

// TestPlatformWrapInit_RefusesWithoutPolicySocket covers the case where the
// policy socket server never started: there is nothing to register a session
// with, so wrap must fail rather than report success and run the agent
// unwatched.
func TestPlatformWrapInit_RefusesWithoutPolicySocket(t *testing.T) {
	a := &App{}
	_, code, err := platformWrapInit(a, "sess-1", types.WrapInitRequest{CallerPID: 4242})
	if err == nil {
		t.Fatal("wrap-init succeeded with no session tracker; the agent would run with nothing enforcing policy")
	}
	if code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", code, http.StatusServiceUnavailable)
	}
}

// TestPlatformWrapInit_RequiresCallerPID: the PID is the session root the
// extension attributes every descendant to. Registering 0 would make the
// session unreachable, and the failure would look like "policy does nothing".
func TestPlatformWrapInit_RequiresCallerPID(t *testing.T) {
	tr := &recordingTracker{}
	a := &App{}
	a.SetSessionTracker(tr)

	for _, pid := range []int{0, -1} {
		_, code, err := platformWrapInit(a, "sess-1", types.WrapInitRequest{CallerPID: pid})
		if err == nil {
			t.Fatalf("wrap-init accepted caller_pid=%d", pid)
		}
		if code != http.StatusBadRequest {
			t.Errorf("caller_pid=%d: status = %d, want %d", pid, code, http.StatusBadRequest)
		}
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.registered) != 0 {
		t.Errorf("a rejected request still registered %d process(es)", len(tr.registered))
	}
}

// TestPlatformWrapInit_RefusesWhenExtensionNotRunning is the fail-closed case.
// It asserts on outcome rather than stubbing the probe: CI runners have no
// approved system extension, so CheckSysExtLiveness reports not-running and
// the request must be refused. On a developer machine with the extension
// live, the request must instead succeed and register the root PID. Both
// outcomes are correct; what must never happen is a success without a
// running extension.
func TestPlatformWrapInit_RefusesWhenExtensionNotRunning(t *testing.T) {
	tr := &recordingTracker{}
	a := &App{}
	a.SetSessionTracker(tr)

	_, code, err := platformWrapInit(a, "sess-1", types.WrapInitRequest{CallerPID: 4242})

	tr.mu.Lock()
	registered := len(tr.registered)
	tr.mu.Unlock()

	if err != nil {
		if code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", code, http.StatusServiceUnavailable)
		}
		// Match the requirement, not one phrasing of it. There is more than
		// one reason enforcement can be unavailable -- the extension is not
		// running, or it is running but not connected to the policy socket --
		// and pinning a single sentence made this test fail when the second
		// case was added rather than when anything actually regressed.
		if !strings.Contains(err.Error(), "wrap: ") {
			t.Errorf("error should explain why enforcement is unavailable, got: %v", err)
		}
		if registered != 0 {
			t.Error("a refused wrap-init registered a session root anyway; the extension would attribute processes to a session the server considers unwrapped")
		}
		return
	}

	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
	if registered != 1 {
		t.Fatalf("registered %d process(es), want 1", registered)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	got := tr.registered[0]
	if got.sessionID != "sess-1" || got.pid != 4242 || got.ppid != 0 {
		t.Errorf("registered %+v, want {sess-1 4242 0}", got)
	}
}

// TestPlatformWrapInit_ReturnsNoWrapperBinary: on macOS the agent is exec'd
// directly and the extension polices it. A non-empty WrapperBinary would send
// the CLI looking for a per-process wrapper that does not exist on this
// platform.
func TestPlatformWrapInit_ReturnsNoWrapperBinary(t *testing.T) {
	tr := &recordingTracker{}
	a := &App{}
	a.SetSessionTracker(tr)

	resp, _, err := platformWrapInit(a, "sess-1", types.WrapInitRequest{CallerPID: 4242})
	if err != nil {
		t.Skipf("no running system extension on this machine: %v", err)
	}
	if resp.WrapperBinary != "" {
		t.Errorf("WrapperBinary = %q, want empty", resp.WrapperBinary)
	}
}

// TestPlatformWrapInit_AcceptsWhenConnected checks the success path: a
// running extension means wrap proceeds and registers the caller PID as the
// session root. Without this, the refusal tests above could be satisfied by a
// gate that refuses unconditionally.
func TestPlatformWrapInit_AcceptsWhenConnected(t *testing.T) {
	live := darwin.CheckSysExtLiveness()
	if !live.Running {
		t.Skip("no running system extension on this machine")
	}
	darwin.SetExtensionPresenceProbe(func() (bool, time.Time) { return true, time.Now() })
	t.Cleanup(func() { darwin.SetExtensionPresenceProbe(nil) })

	tr := &recordingTracker{}
	a := &App{}
	a.SetSessionTracker(tr)

	_, code, err := platformWrapInit(a, "sess-1", types.WrapInitRequest{CallerPID: 4242})
	if err != nil {
		t.Fatalf("wrap-init refused a connected, running extension: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.registered) != 1 {
		t.Fatalf("registered %d process(es), want 1", len(tr.registered))
	}
}
