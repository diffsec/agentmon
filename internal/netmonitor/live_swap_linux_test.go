//go:build linux
// +build linux

package netmonitor

import (
	"testing"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/session"
	"github.com/diffsec/agentmon/pkg/types"
)

// TestLiveSwap_TransparentTCPObservesIt covers the third path through the
// accessor the connection handler uses.
func TestLiveSwap_TransparentTCPObservesIt(t *testing.T) {
	sw := &swapEngine{eng: networkEngine(t, "example.com", "allow")}
	tcp := &TransparentTCP{sessionID: "s", policy: sw.get, emit: &stubEmitter{}}

	before := tcp.policyEngine()
	if before == nil {
		t.Fatal("no engine before the swap")
	}
	if dec := before.CheckNetwork("example.com", 443); dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("before the swap: %q, want allow", dec.EffectiveDecision)
	}

	sw.set(networkEngine(t, "example.com", "deny"))

	after := tcp.policyEngine()
	if after == before {
		t.Fatal("policyEngine() returned the captured engine after a swap")
	}
	if dec := after.CheckNetwork("example.com", 443); dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("after the swap: %q, want deny", dec.EffectiveDecision)
	}
}

// TestLiveSwap_TransparentTCPSessionEngineWins mirrors the precedence check in
// live_swap_test.go, which cannot cover TransparentTCP: it is a stub struct
// off Linux.
func TestLiveSwap_TransparentTCPSessionEngineWins(t *testing.T) {
	sw := &swapEngine{eng: networkEngine(t, "example.com", "allow")}
	sess := &session.Session{ID: "s1"}
	sessionEngine := networkEngine(t, "example.com", "deny")
	sess.SetPolicyEngine(sessionEngine)

	tcp := &TransparentTCP{sessionID: "s1", sess: sess, policy: sw.get}
	if got := tcp.policyEngine(); got != sessionEngine {
		t.Error("resolved to the global engine, want the session's own")
	}
}

// TestLiveSwap_TransparentTCPNilEngineFuncIsSafe.
func TestLiveSwap_TransparentTCPNilEngineFuncIsSafe(t *testing.T) {
	if got := (&TransparentTCP{sessionID: "s"}).policyEngine(); got != nil {
		t.Error("want nil with no getter")
	}
	nilFunc := EngineFunc(func() *policy.Engine { return nil })
	if got := (&TransparentTCP{sessionID: "s", policy: nilFunc}).policyEngine(); got != nil {
		t.Error("want nil when the getter returns nil")
	}
	_ = types.DecisionAllow
}
