package approvals

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// grantManager is a gui-mode manager with grants on. Its launcher sends each
// request that it shows to the returned channel.
func grantManager(t *testing.T, timeout, ttl time.Duration) (*Manager, chan Request) {
	t.Helper()
	m := New("gui", timeout, nil)
	launched := make(chan Request, 16)
	m.SetLauncher(func(_ context.Context, req Request) error {
		launched <- req
		return nil
	})
	m.SetGrantTTL(ttl)
	return m, launched
}

func fileReq(path, op string) Request {
	return Request{SessionID: "s1", Kind: "file", Target: path, Fields: map[string]any{"operation": op}}
}

func waitLaunch(t *testing.T, launched chan Request) Request {
	t.Helper()
	select {
	case req := <-launched:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("the dialog was never launched")
		return Request{}
	}
}

func noLaunch(t *testing.T, launched chan Request) {
	t.Helper()
	select {
	case req := <-launched:
		t.Fatalf("an extra dialog opened for %+v", req)
	case <-time.After(100 * time.Millisecond):
	}
}

// Four flows to one host opened four dialogs. Identical requests now share
// one dialog and its answer.
func TestGrants_IdenticalRequestsShareOneDialog(t *testing.T) {
	m, launched := grantManager(t, 5*time.Second, time.Minute)

	var wg sync.WaitGroup
	var approved atomic.Int32
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := m.RequestApproval(context.Background(), Request{SessionID: "s1", Kind: "network", Target: "example.com:443"})
			if err == nil && res.Approved {
				approved.Add(1)
			}
		}()
	}
	req := waitLaunch(t, launched)
	noLaunch(t, launched)
	m.Resolve(req.ID, true, "approved")
	wg.Wait()
	if got := approved.Load(); got != 4 {
		t.Fatalf("%d of 4 requests were approved", got)
	}
}

func TestGrants_AnswerIsReusedForTheGrantPeriod(t *testing.T) {
	m, launched := grantManager(t, 5*time.Second, time.Minute)
	var changes atomic.Int32
	m.OnGrantChange(func(sessionID string) {
		if sessionID == "s1" {
			changes.Add(1)
		}
	})

	m.Ask(fileReq("/w/a.txt", "write"))
	req := waitLaunch(t, launched)
	m.Resolve(req.ID, true, "approved")

	deadline := time.Now().Add(2 * time.Second)
	for !m.Granted("s1", "file", "/w/a.txt", "write") {
		if time.Now().After(deadline) {
			t.Fatal("no grant after the approval")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if changes.Load() != 1 {
		t.Fatalf("OnGrantChange ran %d times, want 1", changes.Load())
	}

	res, err := m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write"))
	if err != nil || !res.Approved {
		t.Fatalf("second request = %+v, %v; want the reused approval", res, err)
	}
	noLaunch(t, launched)

	grants := m.Grants("s1")
	if len(grants) != 1 || grants[0].Target != "/w/a.txt" || grants[0].Operation != "write" {
		t.Fatalf("Grants = %+v", grants)
	}
	if len(m.Grants("s2")) != 0 {
		t.Fatal("another session sees the grant")
	}
}

// A grant covers only the exact target and operation.
func TestGrants_OtherOperationAsksAgain(t *testing.T) {
	m, launched := grantManager(t, 5*time.Second, time.Minute)
	go func() { _, _ = m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write")) }()
	m.Resolve(waitLaunch(t, launched).ID, true, "approved")

	go func() { _, _ = m.RequestApproval(context.Background(), fileReq("/w/a.txt", "delete")) }()
	req := waitLaunch(t, launched)
	if req.Fields["operation"] != "delete" {
		t.Fatalf("dialog for %+v", req)
	}
	if m.Granted("s1", "file", "/w/a.txt", "delete") {
		t.Fatal("delete is granted before anyone answered")
	}
	m.Resolve(req.ID, false, "denied")
}

// A denial is reused too, so the agent's retries do not reopen the dialog.
func TestGrants_DenialIsReusedButNotGranted(t *testing.T) {
	m, launched := grantManager(t, 5*time.Second, time.Minute)
	go func() { _, _ = m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write")) }()
	m.Resolve(waitLaunch(t, launched).ID, false, "denied")
	time.Sleep(20 * time.Millisecond)

	res, err := m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write"))
	if err != nil || res.Approved {
		t.Fatalf("retry = %+v, %v; want the reused denial", res, err)
	}
	noLaunch(t, launched)
	if m.Granted("s1", "file", "/w/a.txt", "write") || len(m.Grants("s1")) != 0 {
		t.Fatal("a denial produced a grant")
	}
}

func TestGrants_ExpireAfterTheGrantPeriod(t *testing.T) {
	m, launched := grantManager(t, 5*time.Second, 100*time.Millisecond)
	var changes atomic.Int32
	m.OnGrantChange(func(string) { changes.Add(1) })

	go func() { _, _ = m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write")) }()
	m.Resolve(waitLaunch(t, launched).ID, true, "approved")

	deadline := time.Now().Add(2 * time.Second)
	for changes.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("OnGrantChange ran %d times, want 2 (start and end)", changes.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m.Granted("s1", "file", "/w/a.txt", "write") {
		t.Fatal("the grant outlived its period")
	}
	go func() { _, _ = m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write")) }()
	m.Resolve(waitLaunch(t, launched).ID, false, "denied")
}

// Nobody answered, so nothing is kept and the next request asks again.
func TestGrants_TimeoutIsNotKept(t *testing.T) {
	m, launched := grantManager(t, 50*time.Millisecond, time.Minute)
	if _, err := m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write")); err == nil {
		t.Fatal("want a timeout error")
	}
	waitLaunch(t, launched)

	go func() { _, _ = m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write")) }()
	waitLaunch(t, launched)
}

// Without SetGrantTTL every request opens its own dialog, as before.
func TestGrants_OffByDefault(t *testing.T) {
	m := New("gui", 5*time.Second, nil)
	launched := make(chan Request, 4)
	m.SetLauncher(func(_ context.Context, req Request) error {
		launched <- req
		return nil
	})
	for range 2 {
		go func() { _, _ = m.RequestApproval(context.Background(), fileReq("/w/a.txt", "write")) }()
	}
	a, b := waitLaunch(t, launched), waitLaunch(t, launched)
	m.Resolve(a.ID, false, "")
	m.Resolve(b.ID, false, "")
	if m.Granted("s1", "file", "/w/a.txt", "write") {
		t.Fatal("Granted is true with grants off")
	}
}
