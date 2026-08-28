package inspect_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/policy"
)

// stubProvider is a Provider whose answer is fixed per test.
type stubProvider struct {
	name     string
	local    bool
	findings []inspect.Finding
	err      error
	delay    time.Duration
	calls    int32
}

func (s *stubProvider) Name() string         { return s.name }
func (s *stubProvider) IsLocal() bool        { return s.local }
func (s *stubProvider) Categories() []string { return []string{"secret"} }

func (s *stubProvider) Inspect(ctx context.Context, req inspect.Request) (*inspect.Response, error) {
	atomic.AddInt32(&s.calls, 1)
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return &inspect.Response{Provider: s.name, Findings: s.findings}, nil
}

func newChecker(t *testing.T, profiles map[string]policy.InspectionProfile, providers ...inspect.Provider) *inspect.Checker {
	t.Helper()
	c, err := inspect.NewChecker(inspect.Config{
		Profiles:  profiles,
		Providers: providers,
		Privacy:   &inspect.PrivacyConfig{AllowRemote: true},
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	return c
}

// TestChecker_UnknownProfileIsAnError. Validate catches this at load, but a
// policy can be hot-swapped under a Checker built from the previous one. The
// content was not inspected, so the answer must be an error, not a clean
// verdict.
func TestChecker_UnknownProfileIsAnError(t *testing.T) {
	c := newChecker(t, map[string]policy.InspectionProfile{}, &stubProvider{name: "s", local: true})
	_, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"ghost"}, Content: "x"})
	if err == nil {
		t.Fatal("an undefined profile returned a clean verdict; uninspected content would be allowed")
	}
	if !strings.Contains(err.Error(), `profile "ghost" is not defined`) {
		t.Errorf("err = %v", err)
	}
}

// TestChecker_UnconfiguredProviderIsAnError covers the same failure one level
// down: the profile exists but names a provider nobody wired.
func TestChecker_UnconfiguredProviderIsAnError(t *testing.T) {
	c := newChecker(t, map[string]policy.InspectionProfile{
		"pii": {Provider: "shieldstral", Categories: []string{"secret"}},
	}, &stubProvider{name: "regex", local: true})

	_, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"pii"}, Content: "x"})
	if err == nil {
		t.Fatal("a profile naming an unconfigured provider returned a clean verdict")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("err = %v", err)
	}
}

// TestChecker_OneProviderFailingFailsTheInspection.
//
// Reporting the surviving provider's clean result would answer a question
// nobody asked: the content was checked for some things and not others, with
// no way for the caller to tell which.
func TestChecker_OneProviderFailingFailsTheInspection(t *testing.T) {
	good := &stubProvider{name: "good", local: true}
	bad := &stubProvider{name: "bad", local: true, err: errors.New("upstream 503")}

	c := newChecker(t, map[string]policy.InspectionProfile{
		"a": {Provider: "good", Categories: []string{"secret"}},
		"b": {Provider: "bad", Categories: []string{"secret"}},
	}, good, bad)

	v, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"a", "b"}, Content: "x"})
	if err == nil {
		t.Fatal("a failing provider was reported as a clean inspection")
	}
	if v.Violation {
		t.Error("a failed inspection reported a violation")
	}
	if !strings.Contains(err.Error(), "upstream 503") {
		t.Errorf("err should carry the provider failure, got %v", err)
	}
	// The healthy provider must still have been asked -- failing fast on the
	// first error would make results depend on goroutine scheduling.
	if atomic.LoadInt32(&good.calls) != 1 {
		t.Errorf("healthy provider ran %d times, want 1", good.calls)
	}
}

// TestChecker_NilResponseIsAnError: a provider returning (nil, nil) is broken.
// Treating it as "no findings" would make any such bug a silent fail-open.
func TestChecker_NilResponseIsAnError(t *testing.T) {
	c := newChecker(t, map[string]policy.InspectionProfile{
		"a": {Provider: "nilly", Categories: []string{"secret"}},
	}, &nilProvider{})

	if _, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"a"}, Content: "x"}); err == nil {
		t.Fatal("a nil response was treated as a clean inspection")
	}
}

type nilProvider struct{}

func (nilProvider) Name() string         { return "nilly" }
func (nilProvider) IsLocal() bool        { return true }
func (nilProvider) Categories() []string { return nil }
func (nilProvider) Inspect(context.Context, inspect.Request) (*inspect.Response, error) {
	return nil, nil
}

// TestChecker_MergesOverlappingSpansOnce is why redaction lives in the
// checker rather than in each provider. Two providers reporting overlapping
// spans would otherwise have their rewrites applied in sequence, and the
// first rewrite invalidates every offset the second was measured against.
func TestChecker_MergesOverlappingSpansOnce(t *testing.T) {
	content := "prefix SECRETVALUE suffix"
	// "SECRETVALUE" spans [7,18). Two providers see overlapping halves.
	a := &stubProvider{name: "a", local: true, findings: []inspect.Finding{{Category: "secret", Start: 7, End: 14}}}
	b := &stubProvider{name: "b", local: true, findings: []inspect.Finding{{Category: "secret", Start: 11, End: 18}}}

	c := newChecker(t, map[string]policy.InspectionProfile{
		"a": {Provider: "a", Categories: []string{"secret"}},
		"b": {Provider: "b", Categories: []string{"secret"}},
	}, a, b)

	v, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"a", "b"}, Content: content})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !v.Violation {
		t.Fatal("no violation reported")
	}
	if strings.Contains(v.Redacted, "SECRET") || strings.Contains(v.Redacted, "VALUE") {
		t.Errorf("part of the overlapping span survived: %q", v.Redacted)
	}
	if !strings.HasPrefix(v.Redacted, "prefix ") || !strings.HasSuffix(v.Redacted, " suffix") {
		t.Errorf("surrounding text was corrupted: %q", v.Redacted)
	}
}

// TestChecker_DetailNeverCarriesContent. Findings and summaries end up in
// audit events and error messages; the content they point at is exactly the
// material inspection exists to contain.
func TestChecker_DetailNeverCarriesContent(t *testing.T) {
	content := "my password is hunter2correcthorsebattery"
	p := &stubProvider{name: "p", local: true, findings: []inspect.Finding{
		{Category: "secret", Start: 15, End: len(content)},
		{Category: "private_email", Start: 0, End: 2},
	}}
	c := newChecker(t, map[string]policy.InspectionProfile{"p": {Provider: "p", Categories: []string{"secret"}}}, p)

	v, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"p"}, Content: content})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if strings.Contains(v.Detail, "hunter2") {
		t.Errorf("the detail string leaked content: %q", v.Detail)
	}
	if !strings.Contains(v.Detail, "secret") || !strings.Contains(v.Detail, "private_email") {
		t.Errorf("detail should name the categories, got %q", v.Detail)
	}
	if !strings.HasPrefix(v.Detail, "2 findings") {
		t.Errorf("detail should count the findings, got %q", v.Detail)
	}
}

// TestChecker_PerProviderTimeout keeps one slow provider from holding the
// whole inspection past its own bound.
func TestChecker_PerProviderTimeout(t *testing.T) {
	slow := &stubProvider{name: "slow", local: true, delay: 2 * time.Second}
	c, err := inspect.NewChecker(inspect.Config{
		Profiles:        map[string]policy.InspectionProfile{"s": {Provider: "slow", Categories: []string{"secret"}}},
		Providers:       []inspect.Provider{slow},
		ProviderTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	start := time.Now()
	if _, err := c.Inspect(context.Background(), policy.InspectRequest{Profiles: []string{"s"}, Content: "x"}); err == nil {
		t.Fatal("a timed-out provider was reported as clean")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %s; the per-provider timeout did not apply", elapsed)
	}
}

// TestChecker_NoProfilesIsAnError: an empty profile list means nothing ran.
func TestChecker_NoProfilesIsAnError(t *testing.T) {
	c := newChecker(t, map[string]policy.InspectionProfile{}, &stubProvider{name: "s", local: true})
	if _, err := c.Inspect(context.Background(), policy.InspectRequest{Content: "x"}); err == nil {
		t.Fatal("an empty profile list returned a clean verdict")
	}
}

// TestNewChecker_RejectsDuplicateProviderNames. Last-one-wins would mean half
// the profiles silently reach a provider the operator did not choose.
func TestNewChecker_RejectsDuplicateProviderNames(t *testing.T) {
	_, err := inspect.NewChecker(inspect.Config{
		Providers: []inspect.Provider{&stubProvider{name: "dup"}, &stubProvider{name: "dup"}},
	})
	if err == nil {
		t.Fatal("duplicate provider names were accepted")
	}
	if !strings.Contains(err.Error(), "duplicate provider name") {
		t.Errorf("err = %v", err)
	}
}

// TestChecker_Missing lets a caller refuse a policy up front instead of
// discovering at the first request that every inspect rule fails closed.
func TestChecker_Missing(t *testing.T) {
	c := newChecker(t, map[string]policy.InspectionProfile{
		"ok":     {Provider: "s", Categories: []string{"secret"}},
		"orphan": {Provider: "nowhere", Categories: []string{"secret"}},
	}, &stubProvider{name: "s", local: true})

	if missing := c.Missing([]string{"ok"}); len(missing) != 0 {
		t.Errorf("a runnable profile was reported missing: %v", missing)
	}
	missing := c.Missing([]string{"ok", "orphan", "ghost"})
	if len(missing) != 2 {
		t.Fatalf("Missing() = %v, want 2 entries", missing)
	}
	if !strings.Contains(strings.Join(missing, " "), "nowhere") {
		t.Errorf("missing should name the unconfigured provider: %v", missing)
	}
}
