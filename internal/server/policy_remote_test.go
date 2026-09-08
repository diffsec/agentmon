package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/decisionctx"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/policyserve"
)

func remoteCfg(url string) *config.Config {
	cfg := &config.Config{}
	cfg.Policies.Remote.URL = url
	return cfg
}

func TestBuildRemotePolicySource_NilWhenNoURL(t *testing.T) {
	src, err := buildRemotePolicySource(context.Background(), &config.Config{}, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if src != nil {
		t.Error("a config with no policy server produced a source")
	}
}

func TestBuildRemotePolicySource_WrapsInACacheByDefault(t *testing.T) {
	cfg := remoteCfg("https://policy.example/v1/policy")
	cfg.Policies.Remote.CacheDir = t.TempDir()

	src, err := buildRemotePolicySource(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// The cache is what keeps a restart during a server outage from being a
	// daemon that will not start, so it must be on without asking.
	if _, ok := src.(*policy.CachingSource); !ok {
		t.Fatalf("source is %T, want a *policy.CachingSource", src)
	}
	if !strings.HasPrefix(src.Describe(), "remote:") {
		t.Errorf("Describe() = %q; the cache must name the source it fronts", src.Describe())
	}

	off := false
	cfg.Policies.Remote.Cache = &off
	bare, err := buildRemotePolicySource(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := bare.(*policy.RemoteSource); !ok {
		t.Errorf("cache: false produced %T, want the bare remote source", bare)
	}
}

func TestBuildRemotePolicySource_SanitisesTheURLInDescribe(t *testing.T) {
	cfg := remoteCfg("https://user:secret@policy.example/v1/policy?token=abc123")
	off := false
	cfg.Policies.Remote.Cache = &off

	src, err := buildRemotePolicySource(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Describe reaches the log on every failed poll.
	desc := src.Describe()
	for _, secret := range []string{"secret", "abc123", "token"} {
		if strings.Contains(desc, secret) {
			t.Errorf("Describe() = %q leaks %q", desc, secret)
		}
	}
}

func TestBuildRemotePolicySource_RejectsABadURL(t *testing.T) {
	if _, err := buildRemotePolicySource(context.Background(), remoteCfg("ftp://policy.example/p"), nil); err == nil {
		t.Error("a non-HTTP url built a source")
	}
}

func TestBuildRemotePolicySource_AuthTokenComesFromTheEnvironment(t *testing.T) {
	cfg := remoteCfg("https://policy.example/v1/policy")
	off := false
	cfg.Policies.Remote.Cache = &off
	cfg.Policies.Remote.AuthHeader = "Authorization"
	cfg.Policies.Remote.AuthTokenEnv = "AGENTMON_TEST_POLICY_TOKEN"
	t.Setenv("AGENTMON_TEST_POLICY_TOKEN", "Bearer swordfish")

	src, err := buildRemotePolicySource(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rs := remoteSourceOf(t, src)
	if got := rs.Header.Get("Authorization"); got != "Bearer swordfish" {
		t.Errorf("Authorization = %q, want the value from the environment", got)
	}
}

func TestBuildRemotePolicySource_MissingTokenDoesNotBlockStartup(t *testing.T) {
	cfg := remoteCfg("https://policy.example/v1/policy")
	off := false
	cfg.Policies.Remote.Cache = &off
	cfg.Policies.Remote.AuthHeader = "Authorization"
	cfg.Policies.Remote.AuthTokenEnv = "AGENTMON_TEST_ABSENT_TOKEN"

	src, err := buildRemotePolicySource(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("an absent token killed startup: %v", err)
	}
	rs := remoteSourceOf(t, src)
	// Header.Get cannot tell an absent key from one set to the empty string,
	// and a server that checks for the header's presence sees the difference.
	if _, ok := rs.Header["Authorization"]; ok {
		t.Error("an empty token was sent as a header")
	}
}

func TestApplyDecisionContextHeaders_SkipsUnresolvedFields(t *testing.T) {
	h := http.Header{}
	applyDecisionContextHeaders(h, decisionctx.DecisionContext{
		Hostname: "build-01",
		Tags:     []string{"prod", "eu"},
		User:     decisionctx.User{Value: "ci", Source: decisionctx.SourceOS},
		Extra:    map[string]string{"tenant": "acme"},
	})
	if h.Get(policyserve.HeaderHostname) != "build-01" {
		t.Errorf("hostname = %q", h.Get(policyserve.HeaderHostname))
	}
	if h.Get(policyserve.HeaderUser) != "ci" {
		t.Errorf("user = %q", h.Get(policyserve.HeaderUser))
	}
	if h.Get(policyserve.HeaderTenant) != "acme" {
		t.Errorf("tenant = %q", h.Get(policyserve.HeaderTenant))
	}
	// Sorted, so a binding sees the same value whatever order the sources
	// resolved in.
	if got := h.Get(policyserve.HeaderTags); got != "eu,prod" {
		t.Errorf("tags = %q, want eu,prod", got)
	}

	empty := http.Header{}
	applyDecisionContextHeaders(empty, decisionctx.DecisionContext{})
	// An unresolved signal must be absent, not empty: an empty header would be
	// matched against the binding's patterns instead of leaving the field
	// unconstrained.
	if len(empty) != 0 {
		t.Errorf("an empty decision context set headers: %v", empty)
	}
}

func TestRemotePolicyHTTPClient_TimeoutClearsTheLongPoll(t *testing.T) {
	rc := &config.RemotePolicyConfig{URL: "https://policy.example/v1/policy", LongPoll: "120s"}
	c, err := remotePolicyHTTPClient(rc)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	// A timeout at or below the wait aborts every long poll at the deadline,
	// so the fetch never completes and updates only arrive on the ticker.
	if c.Timeout <= rc.ResolvedLongPoll() {
		t.Errorf("timeout %v does not clear the %v long poll", c.Timeout, rc.ResolvedLongPoll())
	}
}

func TestRemotePolicyHTTPClient_RejectsAnEmptyCABundle(t *testing.T) {
	rc := &config.RemotePolicyConfig{URL: "https://policy.example/v1/policy"}
	rc.TLS.CACertFile = writeFile(t, "not-a-certificate\n")
	if _, err := remotePolicyHTTPClient(rc); err == nil {
		t.Fatal("a CA file with no certificates was accepted, so the client would trust nothing and fail every fetch")
	}
}
