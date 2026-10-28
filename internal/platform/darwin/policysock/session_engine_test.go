//go:build darwin

package policysock

import (
	"testing"

	"github.com/diffsec/agentmon/internal/policy"
)

// TestSessionEngineDecidesExecAndSnapshot: a session created with its own
// policy is enforced by that policy in the system extension. Before the
// lookup existed, the extension got the daemon's default policy for every
// session.
func TestSessionEngineDecidesExecAndSnapshot(t *testing.T) {
	mustEngine := func(p *policy.Policy) *policy.Engine {
		t.Helper()
		e, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	defaultEngine := mustEngine(&policy.Policy{
		Version: 1, Name: "default",
		CommandRules: []policy.CommandRule{{Name: "deny-curl", Commands: []string{"curl"}, Decision: "deny"}},
		FileRules:    []policy.FileRule{{Name: "default-file", Paths: []string{"/default/**"}, Operations: []string{"read"}, Decision: "allow"}},
	})
	sessionEngine := mustEngine(&policy.Policy{
		Version: 1, Name: "session",
		CommandRules: []policy.CommandRule{{Name: "allow-curl", Commands: []string{"curl"}, Decision: "allow"}},
		FileRules:    []policy.FileRule{{Name: "session-file", Paths: []string{"/session/**"}, Operations: []string{"read"}, Decision: "allow"}},
	})

	tracker := NewSessionTracker()
	tracker.RegisterProcess("with-policy", 100, 0)
	tracker.RegisterProcess("without-policy", 200, 0)

	adapter := NewPolicyAdapter(defaultEngine, tracker)
	adapter.SetSessionEngineLookup(func(id string) *policy.Engine {
		if id == "with-policy" {
			return sessionEngine
		}
		return nil
	})

	if got := adapter.CheckExec("/usr/bin/curl", nil, 101, 100, "with-policy", ExecContext{}); got.Action != "continue" || got.Rule != "allow-curl" {
		t.Errorf("exec in the session with its own policy = %s by %q, want continue by allow-curl", got.Action, got.Rule)
	}
	if got := adapter.CheckExec("/usr/bin/curl", nil, 201, 200, "without-policy", ExecContext{}); got.Action != "deny" || got.Rule != "deny-curl" {
		t.Errorf("exec in a session with no engine = %s by %q, want deny by deny-curl from the default", got.Action, got.Rule)
	}

	snap := adapter.BuildPolicySnapshot("with-policy", 0)
	if len(snap.FileRules) != 1 || snap.FileRules[0].Pattern != "/session/**" {
		t.Errorf("snapshot file rules = %+v, want the session's /session/**", snap.FileRules)
	}
	// The latest-session path resolves the session before it picks the engine.
	latest := adapter.BuildPolicySnapshot("", 0)
	if latest.SessionID != "without-policy" || len(latest.FileRules) != 1 || latest.FileRules[0].Pattern != "/default/**" {
		t.Errorf("latest snapshot = %s %+v, want without-policy with the default's /default/**", latest.SessionID, latest.FileRules)
	}
}
