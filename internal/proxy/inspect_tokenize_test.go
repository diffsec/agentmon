package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/policy"
)

const inspectRedactPolicy = `
version: 1
name: t
inspection:
  profiles:
    pii:
      provider: regex
      categories: [private_email]
network_rules:
  - name: guard-llm
    domains: ["127.0.0.1", "localhost"]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_violation: redact
`

// startInspectingProxy runs a real proxy with the inspect hook wired the way
// StartLLMProxy wires it, in the given DLP mode.
func startInspectingProxy(t *testing.T, dlpMode string, upstream http.HandlerFunc) string {
	t.Helper()

	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	p, err := New(Config{
		SessionID: "test-session",
		Proxy:     config.ProxyConfig{Mode: "openai", Providers: config.ProxyProvidersConfig{OpenAI: up.URL}},
		DLP:       config.DLPConfig{Mode: dlpMode, Patterns: config.DLPPatternsConfig{}},
	}, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pol, err := policy.LoadFromBytes([]byte(inspectRedactPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	rx, err := provider.NewRegex(nil)
	if err != nil {
		t.Fatalf("regex provider: %v", err)
	}
	checker, err := inspect.NewRegistry([]inspect.Provider{rx}, nil, 0).For(pol)
	if err != nil {
		t.Fatalf("checker: %v", err)
	}

	hook := NewInspectHook(func() (*policy.Engine, policy.InspectChecker) { return eng, checker }, 0, nil)
	hook.SetDLP(p.DLP())
	p.HookRegistry().Register("", hook)

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Stop(ctx)
	})

	addr := p.Addr()
	if addr == nil {
		t.Fatal("proxy has no address")
	}
	return "http://" + addr.String()
}

const inspectedEmail = "alice@example.com"

// TestInspectRedact_TokenizeRoundTrips is the point of this change.
//
// #29's placeholder destroys the value for everything downstream, not just
// for the model: the reply comes back about an address that no longer exists
// anywhere. A token survives the round trip, and the response detokenizer
// from #31 puts the real value back before the agent sees it.
func TestInspectRedact_TokenizeRoundTrips(t *testing.T) {
	var sawUpstream string
	base := startInspectingProxy(t, "tokenize", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sawUpstream = string(body)
		w.Header().Set("Content-Type", "application/json")
		// Quote the input back, the way a model refers to what it was given.
		_, _ = io.WriteString(w, `{"reply":"contacting `+extractToken(sawUpstream)+` now"}`)
	})

	resp := post(t, base+"/v1/chat/completions", `{"messages":[{"content":"email `+inspectedEmail+`"}]}`)

	if strings.Contains(sawUpstream, inspectedEmail) {
		t.Fatalf("the address reached the model: %s", sawUpstream)
	}
	if !strings.Contains(sawUpstream, "TOK_") {
		t.Fatalf("inspection redacted to something other than a token: %s", sawUpstream)
	}
	if strings.Contains(sawUpstream, "[REDACTED:") {
		t.Errorf("the placeholder was used despite dlp.mode: tokenize: %s", sawUpstream)
	}
	if !strings.Contains(resp, inspectedEmail) {
		t.Errorf("the agent did not get the real address back: %s", resp)
	}
	if strings.Contains(resp, "TOK_") {
		t.Errorf("a token leaked to the agent: %s", resp)
	}
}

// TestInspectRedact_PlaceholderWithoutTokenizeMode. An operator who did not
// ask for tokenization must not have values retained in memory for the
// session; the placeholder keeps nothing.
func TestInspectRedact_PlaceholderWithoutTokenizeMode(t *testing.T) {
	for _, mode := range []string{"redact", "disabled", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			var sawUpstream string
			base := startInspectingProxy(t, mode, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				sawUpstream = string(body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"reply":"ok"}`)
			})

			post(t, base+"/v1/chat/completions", `{"messages":[{"content":"email `+inspectedEmail+`"}]}`)

			if strings.Contains(sawUpstream, inspectedEmail) {
				t.Fatalf("the address reached the model: %s", sawUpstream)
			}
			if !strings.Contains(sawUpstream, "[REDACTED:private_email]") {
				t.Errorf("expected a placeholder in mode %q, got: %s", mode, sawUpstream)
			}
			if strings.Contains(sawUpstream, "TOK_") {
				t.Errorf("mode %q minted a token; the value is now retained for the session: %s", mode, sawUpstream)
			}
		})
	}
}

// TestInspectRedact_SharesOneTokenSpaceWithRegexDLP. Both paths mint from the
// same store, so one value gets one token and Detokenize reverses both. Two
// stores would mean a value found by both got two tokens, and the response
// detokenizer would only know one of them.
func TestInspectRedact_SharesOneTokenSpaceWithRegexDLP(t *testing.T) {
	dp := NewDLPProcessor(config.DLPConfig{
		Mode:     "tokenize",
		Patterns: config.DLPPatternsConfig{Email: true},
	})

	// The regex path mints first.
	res := dp.Process([]byte(`{"to":"`+inspectedEmail+`"}`), DialectOpenAI)
	regexToken := extractToken(string(res.ProcessedData))
	if regexToken == "" {
		t.Fatal("the regex path minted no token")
	}

	// The inspection path must reuse it, not mint a second.
	inspectToken := redactorFor(dp).Replace("private_email", inspectedEmail)
	if inspectToken != regexToken {
		t.Errorf("inspection minted %q, regex minted %q; two token spaces for one value", inspectToken, regexToken)
	}
	if got := dp.Detokenize(inspectToken); got != inspectedEmail {
		t.Errorf("Detokenize(%q) = %q", inspectToken, got)
	}
}

// TestRedactorFor_NilProcessorFallsBack: a proxy with no DLP configured must
// still redact, just without reversibility.
func TestRedactorFor_NilProcessorFallsBack(t *testing.T) {
	var dp *DLPProcessor
	got := redactorFor(dp).Replace("secret", "hunter2")
	if got != "[REDACTED:secret]" {
		t.Errorf("Replace = %q, want a placeholder", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Error("the matched value survived redaction")
	}
}
