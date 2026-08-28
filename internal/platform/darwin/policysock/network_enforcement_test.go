//go:build darwin

package policysock

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

// buildSnapshotFor compiles a policy and returns the snapshot the extension
// would receive for it.
func buildSnapshotFor(t *testing.T, p *policy.Policy) PolicyResponse {
	t.Helper()
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	return NewPolicyAdapter(engine, nil).BuildPolicySnapshot("session-1", 0)
}

// TestSnapshotNetworkEnforcement covers the two fields that drive
// FilterDataProvider's blockingEnabled and failOpen. Both were hardcoded in
// Swift -- false and true -- and assigned by nothing, so no policy could ever
// change them. These assertions are what stops them regressing to constants
// again: a snapshot that omits them leaves the extension in audit fail-open.
func TestSnapshotNetworkEnforcement(t *testing.T) {
	cases := []struct {
		name            string
		policy          *policy.Policy
		wantEnforcement string
		wantFailOpen    bool
	}{
		{
			name: "network rules present enforces and fails closed",
			policy: &policy.Policy{
				Version: 1,
				Name:    "deny-example",
				NetworkRules: []policy.NetworkRule{
					{Name: "deny-example", Domains: []string{"example.com"}, Decision: "deny"},
				},
			},
			wantEnforcement: NetworkEnforcementBlock,
			wantFailOpen:    false,
		},
		{
			// An allow-only rule set still enforces: the point of block mode is
			// that flows the Swift cache cannot decide go to the daemon rather
			// than through, and an allow rule set says the policy has an
			// opinion about network access.
			name: "allow-only network rules still enforce",
			policy: &policy.Policy{
				Version: 1,
				Name:    "allow-example",
				NetworkRules: []policy.NetworkRule{
					{Name: "allow-example", Domains: []string{"example.com"}, Decision: "allow"},
				},
			},
			wantEnforcement: NetworkEnforcementBlock,
			wantFailOpen:    false,
		},
		{
			// Nothing to enforce, so do not pay a synchronous round trip per
			// flow to be told "allow".
			name:            "no network rules audits",
			policy:          &policy.Policy{Version: 1, Name: "files-only"},
			wantEnforcement: NetworkEnforcementAudit,
			wantFailOpen:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := buildSnapshotFor(t, c.policy)

			if resp.NetworkEnforcement != c.wantEnforcement {
				t.Errorf("NetworkEnforcement = %q, want %q",
					resp.NetworkEnforcement, c.wantEnforcement)
			}
			if resp.NetworkFailOpen == nil {
				t.Fatal("NetworkFailOpen is nil; the extension would default to fail-open")
			}
			if *resp.NetworkFailOpen != c.wantFailOpen {
				t.Errorf("NetworkFailOpen = %v, want %v",
					*resp.NetworkFailOpen, c.wantFailOpen)
			}
		})
	}
}

// TestDenyAllSnapshotEnforcesNetwork pins the fail-closed snapshot's network
// half. Its deny defaults already make the Swift cache drop every flow, but the
// blocking path has its own fallback, and a snapshot that means "deny
// everything" must not be undone by a policy-socket timeout.
func TestDenyAllSnapshotEnforcesNetwork(t *testing.T) {
	resp := denyAllSnapshot("session-1")

	if resp.NetworkEnforcement != NetworkEnforcementBlock {
		t.Errorf("NetworkEnforcement = %q, want %q",
			resp.NetworkEnforcement, NetworkEnforcementBlock)
	}
	if resp.NetworkFailOpen == nil || *resp.NetworkFailOpen {
		t.Error("fail-closed snapshot must not ask the extension to fail open")
	}
}

// TestSnapshotNetworkFieldNames pins the JSON keys against
// SessionCache.from(json:) in macos/AgentMon/SessionPolicyCache.swift. Nothing
// else connects the two: the Swift side reads string keys, so a rename here
// compiles, ships, and silently drops the extension back to audit fail-open.
func TestSnapshotNetworkFieldNames(t *testing.T) {
	resp := buildSnapshotFor(t, &policy.Policy{
		Version: 1,
		Name:    "deny-example",
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-example", Domains: []string{"example.com"}, Decision: "deny"},
		},
	})

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if got, ok := decoded["network_enforcement"].(string); !ok || got != "block" {
		t.Errorf("network_enforcement = %v, want \"block\"", decoded["network_enforcement"])
	}
	if got, ok := decoded["network_fail_open"].(bool); !ok || got {
		t.Errorf("network_fail_open = %v, want false", decoded["network_fail_open"])
	}
}

// TestCheckResponsesOmitSnapshotFields keeps the two new fields off the
// per-check replies. They are snapshot-only, and a check reply that carried
// network_fail_open would be read by nothing while implying it meant something.
func TestCheckResponsesOmitSnapshotFields(t *testing.T) {
	raw, err := json.Marshal(PolicyResponse{Allow: true, Rule: "some-rule"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"network_enforcement", "network_fail_open"} {
		if _, present := decoded[key]; present {
			t.Errorf("%s appears on a plain check response: %s", key, raw)
		}
	}
}

// TestActiveSessionsInSnapshot covers the field that stops a session being lost
// to notification coalescing. The extension is told "a session registered",
// fetches the latest, and would never learn about a second one that registered
// in the same window -- that session then holds no policy and enforces nothing,
// silently, for its whole lifetime.
func TestActiveSessionsInSnapshot(t *testing.T) {
	tracker := NewSessionTracker()
	tracker.RegisterProcess("session-a", 100, 0)
	tracker.RegisterProcess("session-b", 200, 0)

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "t"}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	resp := NewPolicyAdapter(engine, tracker).BuildPolicySnapshot("", 0)

	// The fetch itself resolves to the most recent session...
	if resp.SessionID != "session-b" {
		t.Errorf("SessionID = %q, want session-b (most recently registered)", resp.SessionID)
	}
	// ...but both must be listed, or session-a is invisible to the extension.
	want := []string{"session-a", "session-b"}
	if len(resp.ActiveSessions) != len(want) {
		t.Fatalf("ActiveSessions = %v, want %v", resp.ActiveSessions, want)
	}
	for i, id := range want {
		if resp.ActiveSessions[i] != id {
			t.Errorf("ActiveSessions[%d] = %q, want %q (oldest first)", i, resp.ActiveSessions[i], id)
		}
	}

	// Pinned against the key SessionPolicyCache.swift reads by string.
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["active_sessions"].([]any); !ok {
		t.Errorf("active_sessions missing or not an array: %s", raw)
	}
}

// TestActiveSessionsIsACopy guards against handing callers the tracker's own
// slice, which a later RegisterProcess append could mutate under them.
func TestActiveSessionsIsACopy(t *testing.T) {
	tracker := NewSessionTracker()
	tracker.RegisterProcess("session-a", 100, 0)

	got := tracker.ActiveSessions()
	got[0] = "mutated"

	if again := tracker.ActiveSessions(); again[0] != "session-a" {
		t.Errorf("caller mutation leaked into the tracker: got %q", again[0])
	}
}

// TestAwaitSnapshot covers the gate that stops a process starting before the
// extension can police it. Registering a session only posts a notification; the
// extension fetches asynchronously, and until it lands SessionPolicyCache maps
// none of the session's PIDs and ESFClient's AUTH handlers allow everything.
func TestAwaitSnapshot(t *testing.T) {
	t.Run("returns immediately once delivered", func(t *testing.T) {
		tracker := NewSessionTracker()
		tracker.RegisterProcess("session-a", 100, 0)
		tracker.NoteSnapshotDelivered("session-a")

		start := time.Now()
		if !tracker.AwaitSnapshot("session-a", time.Minute) {
			t.Fatal("AwaitSnapshot reported not ready for a delivered session")
		}
		// A minute-long timeout that returns instantly proves it is not polling.
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("took %s for an already-delivered session", elapsed)
		}
	})

	t.Run("waits for a snapshot that arrives late", func(t *testing.T) {
		tracker := NewSessionTracker()
		tracker.RegisterProcess("session-a", 100, 0)

		go func() {
			time.Sleep(50 * time.Millisecond)
			tracker.NoteSnapshotDelivered("session-a")
		}()

		if !tracker.AwaitSnapshot("session-a", 5*time.Second) {
			t.Fatal("AwaitSnapshot gave up on a snapshot that did arrive")
		}
	})

	t.Run("gives up once, not once per command", func(t *testing.T) {
		tracker := NewSessionTracker()
		tracker.RegisterProcess("session-a", 100, 0)

		start := time.Now()
		if tracker.AwaitSnapshot("session-a", 100*time.Millisecond) {
			t.Fatal("AwaitSnapshot reported ready with no snapshot delivered")
		}
		first := time.Since(start)

		// On a machine with no running extension the snapshot never arrives.
		// Paying the timeout before every command would make the daemon
		// unusable there, so the second call must not wait at all.
		start = time.Now()
		if tracker.AwaitSnapshot("session-a", time.Minute) {
			t.Fatal("second call reported ready")
		}
		if second := time.Since(start); second >= first {
			t.Errorf("second call took %s, not meaningfully less than the first (%s)", second, first)
		}
	})

	t.Run("a late snapshot still wins after a timeout", func(t *testing.T) {
		tracker := NewSessionTracker()
		tracker.RegisterProcess("session-a", 100, 0)

		if tracker.AwaitSnapshot("session-a", 50*time.Millisecond) {
			t.Fatal("reported ready with no snapshot")
		}
		// Giving up must not latch the session off: the extension may still
		// arrive, and later commands should see it.
		tracker.NoteSnapshotDelivered("session-a")
		if !tracker.AwaitSnapshot("session-a", time.Second) {
			t.Error("a snapshot delivered after a timeout was ignored")
		}
	})

	t.Run("ending a session clears both flags", func(t *testing.T) {
		tracker := NewSessionTracker()
		tracker.RegisterProcess("session-a", 100, 0)
		tracker.NoteSnapshotDelivered("session-a")
		tracker.EndSession("session-a")

		// A reused ID must not inherit the old session's readiness, or its
		// first command would start unpoliced.
		if tracker.SnapshotDelivered("session-a") {
			t.Error("delivery flag outlived the session")
		}
		if tracker.AwaitSnapshot("session-a", 20*time.Millisecond) {
			t.Error("AwaitSnapshot reported ready for an ended session")
		}
	})

	t.Run("empty session id is never ready", func(t *testing.T) {
		tracker := NewSessionTracker()
		if tracker.AwaitSnapshot("", time.Second) {
			t.Error("reported ready for an empty session id")
		}
	})
}
