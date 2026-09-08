package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

type scriptedSource struct {
	mu      sync.Mutex
	steps   []func() (*policy.Bundle, error)
	calls   int32
	elapsed []time.Duration
	started time.Time
}

func (s *scriptedSource) Describe() string { return "scripted" }

func (s *scriptedSource) Fetch(ctx context.Context) (*policy.Bundle, error) {
	s.mu.Lock()
	i := int(s.calls)
	atomic.AddInt32(&s.calls, 1)
	var step func() (*policy.Bundle, error)
	if i < len(s.steps) {
		step = s.steps[i]
	} else {
		step = s.steps[len(s.steps)-1]
	}
	if s.started.IsZero() {
		s.started = time.Now()
	} else {
		s.elapsed = append(s.elapsed, time.Since(s.started))
		s.started = time.Now()
	}
	s.mu.Unlock()
	return step()
}

func doc(name string) *policy.Bundle {
	return &policy.Bundle{Data: []byte("version: 1\nname: " + name + "\n")}
}

func pollerOn(src policy.Source, install func(*policy.Policy) error, interval, longPoll time.Duration) *policyPoller {
	m := policy.NewManager("", "unused", nil, "", "")
	m.SetSource(src)
	return newPolicyPoller(m, install, interval, longPoll, nil)
}

func TestPoller_InstallsOnlyChangedDocuments(t *testing.T) {
	var installed []string
	var mu sync.Mutex
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { return doc("a"), nil },
		func() (*policy.Bundle, error) { return nil, policy.ErrNotModified },
		func() (*policy.Bundle, error) { return doc("b"), nil },
		func() (*policy.Bundle, error) { return nil, policy.ErrNotModified },
	}}
	p := pollerOn(src, func(d *policy.Policy) error {
		mu.Lock()
		installed = append(installed, d.Name)
		mu.Unlock()
		return nil
	}, 10*time.Millisecond, 0)

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(installed)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	mu.Lock()
	defer mu.Unlock()
	// A 304 must not look like a change. Reinstalling on every quiet poll
	// would rebuild every session's engine every interval.
	if len(installed) != 2 || installed[0] != "a" || installed[1] != "b" {
		t.Fatalf("installed %v, want [a b]", installed)
	}
}

func TestPoller_KeepsPollingAfterAFailure(t *testing.T) {
	var installed []string
	var mu sync.Mutex
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { return doc("a"), nil },
		func() (*policy.Bundle, error) { return nil, errors.New("connection refused") },
		func() (*policy.Bundle, error) { return nil, errors.New("connection refused") },
		func() (*policy.Bundle, error) { return doc("b"), nil },
		func() (*policy.Bundle, error) { return nil, policy.ErrNotModified },
	}}
	p := pollerOn(src, func(d *policy.Policy) error {
		mu.Lock()
		installed = append(installed, d.Name)
		mu.Unlock()
		return nil
	}, 10*time.Millisecond, 0)

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(installed)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	mu.Lock()
	defer mu.Unlock()
	// Two failed polls must not end the loop; a server that comes back has to
	// be picked up without a restart.
	if len(installed) != 2 || installed[1] != "b" {
		t.Fatalf("installed %v, want the poll after the outage to install b", installed)
	}
}

func TestPoller_AFailedInstallDoesNotStopTheLoop(t *testing.T) {
	var attempts int32
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { return doc("a"), nil },
		func() (*policy.Bundle, error) { return doc("b"), nil },
		func() (*policy.Bundle, error) { return nil, policy.ErrNotModified },
	}}
	p := pollerOn(src, func(*policy.Policy) error {
		atomic.AddInt32(&attempts, 1)
		return errors.New("engine build failed")
	}, 10*time.Millisecond, 0)

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&attempts) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if got := atomic.LoadInt32(&attempts); got < 2 {
		t.Fatalf("install attempts = %d; one failure ended the loop", got)
	}
}

func TestPoller_LongPollLoopsImmediatelyWhenTheServerHeldTheRequest(t *testing.T) {
	held := 200 * time.Millisecond
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { time.Sleep(held); return doc("a"), nil },
		func() (*policy.Bundle, error) { time.Sleep(held); return nil, policy.ErrNotModified },
		func() (*policy.Bundle, error) { time.Sleep(held); return nil, policy.ErrNotModified },
	}}
	// The ticker is an hour. Only the long-poll path can produce a second
	// fetch inside the test.
	p := pollerOn(src, nil, time.Hour, held*2)

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&src.calls) < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if got := atomic.LoadInt32(&src.calls); got < 3 {
		t.Fatalf("fetches = %d; a held long poll must be followed immediately by the next", got)
	}
}

func TestPoller_FallsBackToTheTickerWhenTheServerIgnoresWait(t *testing.T) {
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { return doc("a"), nil },
		func() (*policy.Bundle, error) { return nil, policy.ErrNotModified },
	}}
	// A server that answers instantly must not turn the long poll into a spin.
	p := pollerOn(src, nil, 150*time.Millisecond, 10*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	time.Sleep(500 * time.Millisecond)
	cancel()

	got := atomic.LoadInt32(&src.calls)
	if got > 6 {
		t.Fatalf("fetches = %d in 500ms against a 150ms ticker; the poller is spinning", got)
	}
	if got < 2 {
		t.Fatalf("fetches = %d; the ticker never fired", got)
	}
}

func TestPoller_StopsOnContextCancel(t *testing.T) {
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { return doc("a"), nil },
	}}
	p := pollerOn(src, nil, 10*time.Millisecond, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestPoller_DoesNotReinstallWhatIsAlreadyLoaded(t *testing.T) {
	var installs int32
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { return doc("a"), nil },
	}}
	m := policy.NewManager("", "unused", nil, "", "")
	m.SetSource(src)
	// The daemon has already loaded this document at startup.
	if _, err := m.Get(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	p := newPolicyPoller(m, func(*policy.Policy) error {
		atomic.AddInt32(&installs, 1)
		return nil
	}, 10*time.Millisecond, 0, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	time.Sleep(120 * time.Millisecond)
	cancel()

	// The first poll re-fetches the same bytes and produces a new *Policy
	// pointer, but the document is the one already in force. Reinstalling it
	// would rebuild every session engine for nothing on the first tick after
	// every daemon start.
	if got := atomic.LoadInt32(&installs); got != 0 {
		t.Fatalf("installs = %d on an unchanged document at startup", got)
	}
}

func TestPoller_StopsPromptlyOnCancelInTheLongPollPath(t *testing.T) {
	src := &scriptedSource{steps: []func() (*policy.Bundle, error){
		func() (*policy.Bundle, error) { time.Sleep(50 * time.Millisecond); return doc("a"), nil },
		func() (*policy.Bundle, error) { time.Sleep(50 * time.Millisecond); return nil, policy.ErrNotModified },
	}}
	// Long-poll on, ticker effectively off: every iteration takes the
	// loop-immediately path.
	p := pollerOn(src, nil, time.Hour, 60*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel in the long-poll path")
	}
	after := atomic.LoadInt32(&src.calls)
	time.Sleep(150 * time.Millisecond)
	// The loop must notice the cancel before starting another fetch, rather
	// than firing one more request at a server it is about to stop talking to.
	if got := atomic.LoadInt32(&src.calls); got != after {
		t.Errorf("fetches went from %d to %d after Run returned", after, got)
	}
}
