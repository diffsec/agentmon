//go:build darwin

package policysock

import (
	"encoding/json"
	"testing"

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
