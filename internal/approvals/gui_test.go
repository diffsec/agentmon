package approvals

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGUIMode_LaunchesTheDialogAndWaitsForAnAnswer(t *testing.T) {
	m := New("gui", 5*time.Second, nil)
	launched := make(chan Request, 1)
	m.SetLauncher(func(_ context.Context, req Request) error {
		launched <- req
		return nil
	})

	done := make(chan Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(context.Background(), Request{SessionID: "s1", Kind: "command", Target: "curl"})
		done <- res
	}()

	var req Request
	select {
	case req = <-launched:
	case <-time.After(2 * time.Second):
		t.Fatal("the dialog was never launched")
	}
	if req.ID == "" || req.Target != "curl" {
		t.Fatalf("launcher got %+v", req)
	}
	// The dialog answers out of band, through Resolve.
	if !m.Resolve(req.ID, true, "approved in the macOS approval dialog by ben") {
		t.Fatal("Resolve did not find the pending request")
	}
	select {
	case res := <-done:
		if !res.Approved || !strings.Contains(res.Reason, "approval dialog") {
			t.Fatalf("resolution = %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RequestApproval did not return after Resolve")
	}
}

// TestGUIMode_LaunchFailureDeniesAtOnce: a dialog that cannot be shown must
// not hold the agent for the whole timeout and then report "approval timeout",
// which reads as a person who saw it and did not answer.
func TestGUIMode_LaunchFailureDeniesAtOnce(t *testing.T) {
	m := New("gui", time.Hour, nil)
	m.SetLauncher(func(context.Context, Request) error { return errors.New("open: no such app") })

	start := time.Now()
	res, err := m.RequestApproval(context.Background(), Request{SessionID: "s1", Kind: "command"})
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if res.Approved {
		t.Fatal("a request nobody could see was approved")
	}
	if !strings.Contains(res.Reason, "could not be shown") || !strings.Contains(res.Reason, "no such app") {
		t.Errorf("reason = %q", res.Reason)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v; a launch failure must deny at once", time.Since(start))
	}
}

func TestGUIMode_NoLauncherDeniesAtOnce(t *testing.T) {
	m := New("gui", time.Hour, nil)
	res, err := m.RequestApproval(context.Background(), Request{SessionID: "s1", Kind: "command"})
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if res.Approved || !strings.Contains(res.Reason, "no dialog launcher") {
		t.Fatalf("resolution = %+v", res)
	}
}

func TestGUIMode_LaunchedRequestIsListed(t *testing.T) {
	m := New("gui", 5*time.Second, nil)
	listed := make(chan []Request, 1)
	m.SetLauncher(func(_ context.Context, req Request) error {
		// The dialog lists pending requests to find its own, so the request
		// must already be pending when the launcher runs.
		listed <- m.ListPending()
		go m.Resolve(req.ID, false, "denied")
		return nil
	})
	if _, err := m.RequestApproval(context.Background(), Request{SessionID: "s1", Kind: "file"}); err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if got := <-listed; len(got) != 1 {
		t.Fatalf("pending at launch = %d, want 1", len(got))
	}
}

func TestOtherModesNeverCallTheLauncher(t *testing.T) {
	m := New("api", 50*time.Millisecond, nil)
	called := false
	m.SetLauncher(func(context.Context, Request) error { called = true; return nil })
	_, _ = m.RequestApproval(context.Background(), Request{SessionID: "s1", Kind: "command"})
	if called {
		t.Fatal("api mode launched the dialog")
	}
}
