package inspect_test

import (
	"context"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/policy"
)

func policyWithProfile(t *testing.T, profile, category string) *policy.Policy {
	t.Helper()
	return &policy.Policy{
		Version: 1,
		Name:    "t",
		Inspection: &policy.InspectionConfig{
			Profiles: map[string]policy.InspectionProfile{
				profile: {Provider: "s", Categories: []string{category}},
			},
		},
	}
}

func newRegistry() *inspect.Registry {
	return inspect.NewRegistry([]inspect.Provider{&stubProvider{name: "s", local: true}}, nil, 0)
}

// TestRegistry_ChecksProfilesOfTheRequestedPolicy is why this is a registry
// and not a single Checker attached at construction.
//
// The profiles come from the policy, so a session running a named policy file
// needs a Checker built from THAT policy's profiles. A process-wide Checker
// built from the default policy would report every one of the session's
// profiles as undefined, and the session's inspect rules would all fail
// closed.
func TestRegistry_ChecksProfilesOfTheRequestedPolicy(t *testing.T) {
	r := newRegistry()

	a := policyWithProfile(t, "alpha", "secret")
	b := policyWithProfile(t, "beta", "secret")

	ca, err := r.For(a)
	if err != nil {
		t.Fatalf("For(a): %v", err)
	}
	if missing := ca.Missing([]string{"alpha"}); len(missing) != 0 {
		t.Errorf("policy A's own profile was reported missing: %v", missing)
	}

	cb, err := r.For(b)
	if err != nil {
		t.Fatalf("For(b): %v", err)
	}
	if missing := cb.Missing([]string{"beta"}); len(missing) != 0 {
		t.Errorf("policy B's own profile was reported missing: %v", missing)
	}
	if missing := cb.Missing([]string{"alpha"}); len(missing) == 0 {
		t.Error("policy B's checker accepted policy A's profile; the memo returned a stale checker")
	}
}

// TestRegistry_NewPolicyAfterSwapGetsAFreshChecker is the live-update case.
//
// A pushed policy produces a new *policy.Policy and a new engine. If the
// registry kept handing out the checker built from the previous policy, every
// profile added by the update would be reported undefined and its rules would
// fail closed -- a live policy update that silently disables the feature it
// just configured.
func TestRegistry_NewPolicyAfterSwapGetsAFreshChecker(t *testing.T) {
	r := newRegistry()

	before := policyWithProfile(t, "old", "secret")
	if _, err := r.For(before); err != nil {
		t.Fatalf("For(before): %v", err)
	}

	after := policyWithProfile(t, "new", "secret")
	c, err := r.For(after)
	if err != nil {
		t.Fatalf("For(after): %v", err)
	}
	if missing := c.Missing([]string{"new"}); len(missing) != 0 {
		t.Fatalf("the profile added by the update was reported missing: %v", missing)
	}
	if missing := c.Missing([]string{"old"}); len(missing) == 0 {
		t.Error("the removed profile still resolves; the checker was not rebuilt")
	}
}

// TestRegistry_MemoisesTheSamePolicy: repeated calls for one policy must not
// rebuild, since a wire point calls this per request.
func TestRegistry_MemoisesTheSamePolicy(t *testing.T) {
	r := newRegistry()
	p := policyWithProfile(t, "pii", "secret")

	first, err := r.For(p)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	second, err := r.For(p)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if first != second {
		t.Error("the same policy produced two checkers; the memo is not working")
	}
}

// TestRegistry_NilIsSafe. A deployment that never enables inspection leaves
// the registry nil, and the accessor must not panic on the request path.
func TestRegistry_NilIsSafe(t *testing.T) {
	var r *inspect.Registry
	c, err := r.For(policyWithProfile(t, "pii", "secret"))
	if err != nil || c != nil {
		t.Errorf("nil registry returned (%v, %v), want (nil, nil)", c, err)
	}
	if names := r.Providers(); names != nil {
		t.Errorf("Providers() on a nil registry = %v", names)
	}
}

// TestRegistry_PolicyWithNoInspectionBlock must still yield a usable checker,
// which then reports every named profile as undefined rather than crashing.
func TestRegistry_PolicyWithNoInspectionBlock(t *testing.T) {
	r := newRegistry()
	c, err := r.For(&policy.Policy{Version: 1, Name: "bare"})
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if c == nil {
		t.Fatal("no checker for a policy with no inspection block")
	}
	if missing := c.Missing([]string{"anything"}); len(missing) != 1 {
		t.Errorf("Missing() = %v, want one entry", missing)
	}
	if _, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"anything"}, Content: "x"}); err == nil {
		t.Error("an undefined profile returned a clean verdict")
	}
}
