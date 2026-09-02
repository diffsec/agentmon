package session

import "testing"

// TestPolicyVars_IsCopiedBothWays.
//
// The map crosses a boundary twice: in from the caller that compiled the
// engine, out to the caller rebuilding it. Sharing it either way means one
// session's PROJECT_ROOT can be rewritten by whoever touched the map last,
// and every path rule in that session moves with it.
func TestPolicyVars_IsCopiedBothWays(t *testing.T) {
	s := &Session{ID: "s1"}
	in := map[string]string{"PROJECT_ROOT": "/w1", "HOME": "/home/agent"}
	s.SetPolicyVars(in)

	// Mutating the caller's map must not reach the session.
	in["PROJECT_ROOT"] = "/elsewhere"
	if got := s.PolicyVars()["PROJECT_ROOT"]; got != "/w1" {
		t.Errorf("PROJECT_ROOT = %q after the caller mutated its map, want /w1", got)
	}

	// Mutating what comes out must not reach the session either.
	out := s.PolicyVars()
	out["PROJECT_ROOT"] = "/elsewhere"
	if got := s.PolicyVars()["PROJECT_ROOT"]; got != "/w1" {
		t.Errorf("PROJECT_ROOT = %q after a reader mutated the returned map, want /w1", got)
	}
}

// TestPolicyVars_NilRoundTrips. A session whose engine was compiled without
// substitutions records none, and the reload path uses nil to mean exactly
// that -- so it must not come back as an empty non-nil map.
func TestPolicyVars_NilRoundTrips(t *testing.T) {
	s := &Session{ID: "s1"}
	if got := s.PolicyVars(); got != nil {
		t.Errorf("PolicyVars() = %v on a fresh session, want nil", got)
	}

	s.SetPolicyVars(map[string]string{"PROJECT_ROOT": "/w1"})
	s.SetPolicyVars(nil)
	if got := s.PolicyVars(); got != nil {
		t.Errorf("PolicyVars() = %v after being cleared, want nil", got)
	}
}
