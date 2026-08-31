package inspect_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/policy"
)

// countingSidecar records every request that reaches it, and echoes back a
// span covering whatever it was sent.
func countingSidecar(t *testing.T, hits *int32, bodies *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		bodies.Store(string(buf[:n]))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"spans":[{"start":0,"end":5,"category":"secret"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sidecarProfiles() map[string]policy.InspectionProfile {
	return map[string]policy.InspectionProfile{
		"pii": {Provider: provider.SidecarName, Categories: []string{"secret"}},
	}
}

// TestPrivacyGate_BlocksContentBeforeItLeavesTheProcess is the test that
// nothing before this PR could write, because no provider made a network
// call.
//
// Everything else about the gate is a unit test against a stub that could not
// leak anything. This one puts a real HTTP server behind a real provider and
// asserts the server was never contacted: the gate has to refuse before the
// request is built, not after.
func TestPrivacyGate_BlocksContentBeforeItLeavesTheProcess(t *testing.T) {
	var hits int32
	var bodies atomic.Value
	srv := countingSidecar(t, &hits, &bodies)

	sc, err := provider.NewSidecar(provider.SidecarConfig{BaseURL: srv.URL, MaxAttempts: 1})
	if err != nil {
		t.Fatalf("NewSidecar: %v", err)
	}

	// The zero-valued PrivacyConfig: remote inspection not enabled.
	c, err := inspect.NewChecker(inspect.Config{
		Profiles:  sidecarProfiles(),
		Providers: []inspect.Provider{sc},
		Privacy:   &inspect.PrivacyConfig{},
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	secret := "TOP_SECRET_PAYLOAD"
	_, err = c.Inspect(context.Background(), policy.InspectRequest{
		Profiles: []string{"pii"}, Kind: inspect.KindProxyBody, Content: secret,
	})
	if err == nil {
		t.Fatal("the gate allowed a remote provider with allow_remote unset")
	}
	if !strings.Contains(err.Error(), "not local") {
		t.Errorf("err should say why, got: %v", err)
	}

	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the sidecar was contacted %d times; content left the process despite the gate", n)
	}
	if sent, ok := bodies.Load().(string); ok && strings.Contains(sent, secret) {
		t.Fatalf("the content reached the wire: %q", sent)
	}
}

// TestPrivacyGate_KindAllowlistBlocksBeforeTheWire is the same proof for the
// per-kind narrowing: a deployment that permits argv inspection remotely but
// not request bodies must not send request bodies.
func TestPrivacyGate_KindAllowlistBlocksBeforeTheWire(t *testing.T) {
	var hits int32
	var bodies atomic.Value
	srv := countingSidecar(t, &hits, &bodies)

	sc, err := provider.NewSidecar(provider.SidecarConfig{BaseURL: srv.URL, MaxAttempts: 1})
	if err != nil {
		t.Fatalf("NewSidecar: %v", err)
	}
	c, err := inspect.NewChecker(inspect.Config{
		Profiles:  sidecarProfiles(),
		Providers: []inspect.Provider{sc},
		Privacy:   &inspect.PrivacyConfig{AllowRemote: true, RemoteKinds: []string{inspect.KindCommand}},
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	if _, err := c.Inspect(context.Background(), policy.InspectRequest{
		Profiles: []string{"pii"}, Kind: inspect.KindProxyBody, Content: "TOP_SECRET_PAYLOAD",
	}); err == nil {
		t.Fatal("a kind outside the allowlist was sent")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the sidecar was contacted %d times for a disallowed kind", n)
	}

	// The allowlisted kind must still reach it, or this is just a gate that
	// blocks everything.
	if _, err := c.Inspect(context.Background(), policy.InspectRequest{
		Profiles: []string{"pii"}, Kind: inspect.KindCommand, Content: "curl x",
	}); err != nil {
		t.Fatalf("an allowlisted kind was refused: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("the sidecar was contacted %d times for an allowlisted kind, want 1", n)
	}
}

// TestPrivacyGate_AllowRemoteLetsTheSidecarWork closes the loop: with the
// gate opened, a real provider over a real transport produces a real verdict.
// This is also the first end-to-end exercise of the Provider interface
// against something asynchronous and fallible.
func TestPrivacyGate_AllowRemoteLetsTheSidecarWork(t *testing.T) {
	var hits int32
	var bodies atomic.Value
	srv := countingSidecar(t, &hits, &bodies)

	sc, err := provider.NewSidecar(provider.SidecarConfig{BaseURL: srv.URL, MaxAttempts: 1})
	if err != nil {
		t.Fatalf("NewSidecar: %v", err)
	}
	c, err := inspect.NewChecker(inspect.Config{
		Profiles:  sidecarProfiles(),
		Providers: []inspect.Provider{sc},
		Privacy:   &inspect.PrivacyConfig{AllowRemote: true},
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	v, err := c.Inspect(context.Background(), policy.InspectRequest{
		Profiles: []string{"pii"}, Kind: inspect.KindProxyBody, Content: "HELLO world",
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !v.Violation {
		t.Fatal("no violation despite the sidecar returning a span")
	}
	if v.Redacted != "[REDACTED:secret] world" {
		t.Errorf("Redacted = %q, want the first five bytes replaced", v.Redacted)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("sidecar hit %d times, want 1", hits)
	}
}
