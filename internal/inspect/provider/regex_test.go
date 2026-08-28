package provider_test

import (
	"context"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/policy"
)

func newRegex(t *testing.T) *provider.Regex {
	t.Helper()
	r, err := provider.NewRegex(nil)
	if err != nil {
		t.Fatalf("NewRegex: %v", err)
	}
	return r
}

func inspectWith(t *testing.T, r *provider.Regex, categories []string, content string) *inspect.Response {
	t.Helper()
	resp, err := r.Inspect(context.Background(), inspect.Request{
		Profile: "p",
		Spec:    policy.InspectionProfile{Provider: provider.RegexName, Categories: categories},
		Kind:    inspect.KindProxyBody,
		Content: content,
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return resp
}

// TestRegex_FindsAndPositionsEachCategory. The offsets matter as much as the
// detection: the checker redacts from them, so an off-by-one leaves part of a
// secret in the output.
func TestRegex_FindsAndPositionsEachCategory(t *testing.T) {
	r := newRegex(t)
	cases := []struct {
		category string
		content  string
		match    string
	}{
		{"private_email", "write to alice@example.com now", "alice@example.com"},
		{"private_phone", "call 555-123-4567 today", "555-123-4567"},
		{"private_url", "see https://example.com/x?y=1 for more", "https://example.com/x?y=1"},
		{"secret", "export TOKEN=sk-abcdefghijklmnopqrstuvwxyz", "sk-abcdefghijklmnopqrstuvwxyz"},
		{"account_number", "card 4111 1111 1111 1111 on file", "4111 1111 1111 1111"},
	}

	for _, c := range cases {
		t.Run(c.category, func(t *testing.T) {
			resp := inspectWith(t, r, []string{c.category}, c.content)
			if len(resp.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(resp.Findings))
			}
			f := resp.Findings[0]
			if f.Category != c.category {
				t.Errorf("Category = %q, want %q", f.Category, c.category)
			}
			if f.Profile != "p" {
				t.Errorf("Profile = %q, want p", f.Profile)
			}
			if got := c.content[f.Start:f.End]; !strings.Contains(got, c.match) {
				t.Errorf("span [%d,%d) = %q, want it to cover %q", f.Start, f.End, got, c.match)
			}
			if !f.HasSpan() {
				t.Error("HasSpan() = false for a span finding; redaction would refuse to act on it")
			}
		})
	}
}

// TestRegex_CleanContentFindsNothing. Without it, everything above passes for
// a provider that flags every input.
func TestRegex_CleanContentFindsNothing(t *testing.T) {
	resp := inspectWith(t, newRegex(t), nil, "the quick brown fox jumps over the lazy dog")
	if len(resp.Findings) != 0 {
		t.Errorf("clean content produced %d findings: %+v", len(resp.Findings), resp.Findings)
	}
}

// TestRegex_UnknownCategoryIsAnError is the fail-closed case.
//
// A profile asking for `secret` against a provider with no secret pattern
// must not come back clean. Skipping unknown categories is how a profile
// silently inspects nothing.
func TestRegex_UnknownCategoryIsAnError(t *testing.T) {
	r := newRegex(t)
	_, err := r.Inspect(context.Background(), inspect.Request{
		Profile: "p",
		Spec:    policy.InspectionProfile{Provider: provider.RegexName, Categories: []string{"private_person"}},
		Content: "Alice Smith",
	})
	if err == nil {
		t.Fatal("an unsupported category returned a clean response")
	}
	if !strings.Contains(err.Error(), "private_person") {
		t.Errorf("err should name the category, got %v", err)
	}
}

// TestRegex_EmptyCategoriesRunsEverything: a profile naming no categories is
// asking for a general sweep. Running nothing would report clean.
func TestRegex_EmptyCategoriesRunsEverything(t *testing.T) {
	resp := inspectWith(t, newRegex(t), nil, "alice@example.com and sk-abcdefghijklmnopqrstuvwxyz")
	seen := map[string]bool{}
	for _, f := range resp.Findings {
		seen[f.Category] = true
	}
	if !seen["private_email"] || !seen["secret"] {
		t.Errorf("a category-less profile missed findings; saw %v", seen)
	}
}

// TestRegex_IsLocal drives the privacy gate: a provider that lied here would
// have content withheld from it, or worse, sent out.
func TestRegex_IsLocal(t *testing.T) {
	if !newRegex(t).IsLocal() {
		t.Error("the regex provider reported itself as non-local")
	}
}

// TestNewRegex_RejectsUncompilablePattern. internal/proxy/dlp.go's addPattern
// skips a bad pattern silently, and the result is a processor reporting a
// pattern count the operator never chose.
func TestNewRegex_RejectsUncompilablePattern(t *testing.T) {
	_, err := provider.NewRegex(map[string]string{"broken": "(unclosed"})
	if err == nil {
		t.Fatal("an uncompilable pattern was accepted and silently dropped")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("err should name the category, got %v", err)
	}
}

// TestNewRegex_ExtraOverridesBuiltin lets an operator tighten a pattern
// without forking the provider.
func TestNewRegex_ExtraOverridesBuiltin(t *testing.T) {
	r, err := provider.NewRegex(map[string]string{"private_email": `alice@[a-z.]+`})
	if err != nil {
		t.Fatalf("NewRegex: %v", err)
	}
	resp, err := r.Inspect(context.Background(), inspect.Request{
		Profile: "p",
		Spec:    policy.InspectionProfile{Categories: []string{"private_email"}},
		Content: "bob@example.com and alice@example.com",
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (the override should not match bob)", len(resp.Findings))
	}
	if got := "bob@example.com and alice@example.com"[resp.Findings[0].Start:resp.Findings[0].End]; !strings.HasPrefix(got, "alice@") {
		t.Errorf("matched %q, want the alice address", got)
	}
}
