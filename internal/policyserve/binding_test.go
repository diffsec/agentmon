package policyserve

import (
	"strings"
	"testing"
)

func compile(t *testing.T, bs ...Binding) []compiledBinding {
	t.Helper()
	cb, err := compileBindings(&BindingFile{Bindings: bs})
	if err != nil {
		t.Fatalf("compileBindings: %v", err)
	}
	return cb
}

func TestBinding_EmptyFieldIsUnconstrained(t *testing.T) {
	cb := compile(t, Binding{Name: "prod", Policy: "p.yaml", Match: &Match{Tenants: []string{"acme"}}})
	if !cb[0].matches(Selector{Tenant: "acme", Hostname: "anything", User: "anyone"}) {
		t.Error("an unset field must not constrain the match")
	}
	if cb[0].matches(Selector{Tenant: "other"}) {
		t.Error("a set field must constrain the match")
	}
}

func TestBinding_AllFieldsMustMatch(t *testing.T) {
	cb := compile(t, Binding{Name: "b", Policy: "p.yaml", Match: &Match{
		Hostnames: []string{"build-*"},
		Users:     []string{"ci"},
	}})
	if !cb[0].matches(Selector{Hostname: "build-01", User: "ci"}) {
		t.Error("both fields matching should match")
	}
	// One field matching is not enough; an any-of test here would serve the
	// binding to every host running as ci.
	if cb[0].matches(Selector{Hostname: "build-01", User: "dev"}) {
		t.Error("hostname alone matched")
	}
	if cb[0].matches(Selector{Hostname: "laptop", User: "ci"}) {
		t.Error("user alone matched")
	}
}

func TestBinding_TagsRequireAll(t *testing.T) {
	cb := compile(t, Binding{Name: "b", Policy: "p.yaml", Match: &Match{Tags: []string{"prod", "pci"}}})
	if !cb[0].matches(Selector{Tags: []string{"pci", "prod", "eu"}}) {
		t.Error("a superset of the required tags should match")
	}
	if cb[0].matches(Selector{Tags: []string{"prod"}}) {
		t.Error("one of two required tags matched; tags must be all-of")
	}
	if cb[0].matches(Selector{}) {
		t.Error("no tags matched a tag-constrained binding")
	}
}

func TestBinding_MatchingIsCaseInsensitive(t *testing.T) {
	cb := compile(t, Binding{Name: "b", Policy: "p.yaml", Match: &Match{
		Hostnames: []string{"Build-*"},
		Tags:      []string{"PROD"},
	}})
	if !cb[0].matches(Selector{Hostname: "BUILD-01", Tags: []string{"prod"}}) {
		t.Error("case differences must not change which policy an agent gets")
	}
}

func TestBinding_NoMatchBlockIsCatchAll(t *testing.T) {
	cb := compile(t, Binding{Name: "fallback", Policy: "p.yaml"})
	if !cb[0].matches(Selector{}) {
		t.Error("a binding with no match block must be a catch-all")
	}
}

func TestBinding_FirstMatchWins(t *testing.T) {
	cb := compile(t,
		Binding{Name: "specific", Policy: "strict.yaml", Match: &Match{Tags: []string{"prod"}}},
		Binding{Name: "fallback", Policy: "base.yaml"},
	)
	var picked string
	for _, b := range cb {
		if b.matches(Selector{Tags: []string{"prod"}}) {
			picked = b.policy
			break
		}
	}
	if picked != "strict.yaml" {
		t.Errorf("picked %q, want the first matching binding", picked)
	}
}

func TestCompileBindings_RejectsPathsInPolicyName(t *testing.T) {
	for _, bad := range []string{"../secret.yaml", "sub/p.yaml", ".", ".."} {
		_, err := compileBindings(&BindingFile{Bindings: []Binding{{Policy: bad}}})
		if err == nil {
			t.Errorf("policy %q was accepted; it escapes the served directory", bad)
			continue
		}
		if !strings.Contains(err.Error(), "file name") {
			t.Errorf("policy %q: error = %v", bad, err)
		}
	}
}

func TestCompileBindings_RejectsEmptyAndMissing(t *testing.T) {
	if _, err := compileBindings(&BindingFile{}); err == nil {
		t.Error("an empty bindings file was accepted")
	}
	if _, err := compileBindings(&BindingFile{Bindings: []Binding{{Policy: ""}}}); err == nil {
		t.Error("a binding with no policy was accepted")
	}
	if _, err := compileBindings(&BindingFile{Bindings: []Binding{
		{Policy: "p.yaml", Match: &Match{Hostnames: []string{" "}}},
	}}); err == nil {
		t.Error("an empty hostname pattern was accepted")
	}
	if _, err := compileBindings(&BindingFile{Bindings: []Binding{
		{Policy: "p.yaml", Match: &Match{Tags: []string{""}}},
	}}); err == nil {
		t.Error("an empty tag was accepted")
	}
}

func TestCompileBindings_RejectsBadGlob(t *testing.T) {
	_, err := compileBindings(&BindingFile{Bindings: []Binding{
		{Policy: "p.yaml", Match: &Match{Hostnames: []string{"["}}},
	}})
	if err == nil {
		t.Fatal("an unparseable glob was accepted, so the binding would silently match nothing")
	}
}
