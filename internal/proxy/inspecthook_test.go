package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/policy"
)

func buildInspectEngine(t *testing.T, yaml string) (*policy.Engine, policy.InspectChecker) {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	eng, err := policy.NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	rx, err := provider.NewRegex(nil)
	if err != nil {
		t.Fatalf("new regex provider: %v", err)
	}
	reg := inspect.NewRegistry([]inspect.Provider{rx}, nil, 0)
	checker, err := reg.For(p)
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	return eng, checker
}

const redactUpstream = `
version: 1
name: t
inspection:
  profiles:
    pii:
      provider: regex
      categories: [private_email, secret]
network_rules:
  - name: inspect-llm
    domains: ["api.example.com"]
    ports: [443]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_violation: redact
`

func postTo(t *testing.T, url, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.ContentLength = int64(len(body))
	return r
}

func hookFor(eng *policy.Engine, checker policy.InspectChecker, maxBody int64) *InspectHook {
	return NewInspectHook(func() (*policy.Engine, policy.InspectChecker) {
		return eng, checker
	}, maxBody, nil)
}

func readBack(t *testing.T, r *http.Request) string {
	t.Helper()
	if r.Body == nil {
		return ""
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("re-reading body: %v", err)
	}
	return string(b)
}

// TestInspectHook_RedactsBodyInPlace is the point of the hook: the request
// still goes upstream, without the material the policy flagged.
func TestInspectHook_RedactsBodyInPlace(t *testing.T) {
	eng, checker := buildInspectEngine(t, redactUpstream)
	h := hookFor(eng, checker, 0)

	body := `{"prompt":"email alice@example.com about it"}`
	r := postTo(t, "https://api.example.com/v1/chat", body)

	if err := h.PreHook(r, &RequestContext{RequestID: "req-1"}); err != nil {
		t.Fatalf("PreHook aborted a request it should have redacted: %v", err)
	}

	got := readBack(t, r)
	if strings.Contains(got, "alice@example.com") {
		t.Errorf("the email reached the upstream body: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:private_email]") {
		t.Errorf("no placeholder in the rewritten body: %q", got)
	}
	if !strings.Contains(got, `"prompt"`) {
		t.Errorf("surrounding JSON was corrupted: %q", got)
	}
	// A rewritten body has a different length. Leaving the old one set sends
	// a Content-Length that disagrees with the bytes, which upstreams reject
	// or truncate on.
	if r.ContentLength != int64(len(got)) {
		t.Errorf("ContentLength = %d, body is %d bytes", r.ContentLength, len(got))
	}
	if hdr := r.Header.Get("Content-Length"); hdr != "" && hdr != strconv.Itoa(len(got)) {
		t.Errorf("Content-Length header = %q, body is %d bytes", hdr, len(got))
	}
}

// TestInspectHook_CleanBodyPassesUntouched keeps the test above from being
// satisfied by a hook that rewrites everything.
func TestInspectHook_CleanBodyPassesUntouched(t *testing.T) {
	eng, checker := buildInspectEngine(t, redactUpstream)
	h := hookFor(eng, checker, 0)

	body := `{"prompt":"what is the capital of France"}`
	r := postTo(t, "https://api.example.com/v1/chat", body)

	if err := h.PreHook(r, &RequestContext{}); err != nil {
		t.Fatalf("PreHook aborted a clean request: %v", err)
	}
	if got := readBack(t, r); got != body {
		t.Errorf("a clean body was altered:\n got %q\nwant %q", got, body)
	}
}

// TestInspectHook_DeniesOnViolation covers `decision: inspect` with the
// default on_violation of deny.
func TestInspectHook_DeniesOnViolation(t *testing.T) {
	const yaml = `
version: 1
name: t
inspection:
  profiles:
    creds:
      provider: regex
      categories: [secret]
network_rules:
  - name: no-secrets-outbound
    domains: ["api.example.com"]
    ports: [443]
    decision: inspect
    inspect:
      profiles: [creds]
`
	eng, checker := buildInspectEngine(t, yaml)
	h := hookFor(eng, checker, 0)

	r := postTo(t, "https://api.example.com/v1/chat", `{"key":"sk-abcdefghijklmnopqrstuvwxyz"}`)
	err := h.PreHook(r, &RequestContext{})
	if err == nil {
		t.Fatal("a body carrying a secret was forwarded")
	}
	abort, ok := err.(*HookAbortError)
	if !ok {
		t.Fatalf("err = %T, want *HookAbortError so the proxy returns a status rather than 502", err)
	}
	if abort.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", abort.StatusCode)
	}
	// The message is written into the agent's own transcript, which is one
	// of the places the content was being kept out of.
	if strings.Contains(abort.Message, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("the secret leaked into the abort message: %q", abort.Message)
	}
	if !strings.Contains(abort.Message, "no-secrets-outbound") {
		t.Errorf("message should name the rule, got %q", abort.Message)
	}
	if !strings.Contains(abort.Message, "secret") {
		t.Errorf("message should name the category, got %q", abort.Message)
	}
}

// TestInspectHook_IgnoresRulesWithoutAnInspectSpec.
//
// The proxy, the macOS network filter and the Linux netmonitor each enforce
// network policy on their own path. A second enforcement point here would
// change behaviour for every deployment that uses no inspection at all, so
// the hook resolves inspect specs and nothing else.
func TestInspectHook_IgnoresRulesWithoutAnInspectSpec(t *testing.T) {
	const yaml = `
version: 1
name: t
network_rules:
  - name: hard-deny
    domains: ["api.example.com"]
    ports: [443]
    decision: deny
`
	eng, checker := buildInspectEngine(t, yaml)
	h := hookFor(eng, checker, 0)

	r := postTo(t, "https://api.example.com/v1/chat", `{"a":1}`)
	if err := h.PreHook(r, &RequestContext{}); err != nil {
		t.Fatalf("the hook enforced a plain network deny: %v", err)
	}
}

// TestInspectHook_OversizeBodyIsAFailureNotASkip.
//
// A body too large to buffer is uninspected content. Forwarding it would let
// an agent bypass every inspect rule by padding the payload.
func TestInspectHook_OversizeBodyIsAFailureNotASkip(t *testing.T) {
	eng, checker := buildInspectEngine(t, redactUpstream)
	h := hookFor(eng, checker, 32)

	body := `{"prompt":"` + strings.Repeat("x", 500) + `"}`
	r := postTo(t, "https://api.example.com/v1/chat", body)

	err := h.PreHook(r, &RequestContext{})
	if err == nil {
		t.Fatal("an oversize body was forwarded uninspected; padding the payload would bypass every inspect rule")
	}
	abort, ok := err.(*HookAbortError)
	if !ok {
		t.Fatalf("err = %T, want *HookAbortError", err)
	}
	if !strings.Contains(abort.Message, "could not run") {
		t.Errorf("message should say inspection did not run, got %q", abort.Message)
	}
}

// TestInspectHook_OversizeBodyHonoursFailOpen: the cap routes through
// on_failure like any other inspection failure, so an operator who chose
// fail_open gets fail_open.
func TestInspectHook_OversizeBodyHonoursFailOpen(t *testing.T) {
	const yaml = `
version: 1
name: t
inspection:
  profiles:
    pii:
      provider: regex
      categories: [private_email]
network_rules:
  - name: soft
    domains: ["api.example.com"]
    ports: [443]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_failure: fail_open
`
	eng, checker := buildInspectEngine(t, yaml)
	h := hookFor(eng, checker, 32)

	body := `{"prompt":"` + strings.Repeat("x", 500) + `"}`
	r := postTo(t, "https://api.example.com/v1/chat", body)

	if err := h.PreHook(r, &RequestContext{}); err != nil {
		t.Fatalf("fail_open was not honoured for an oversize body: %v", err)
	}
	// The body must survive intact, or fail_open forwards a truncated
	// request, which is worse than blocking it.
	if got := readBack(t, r); got != body {
		t.Errorf("body was truncated to %d bytes, want %d", len(got), len(body))
	}
}

// TestInspectHook_ApproveIsDeniedWithAnExplanation.
//
// A PreHook can abort or proceed; it cannot gate on a human. Silently
// downgrading to allow would drop the gate, and a bare 403 would send the
// operator looking for a rule that denied.
func TestInspectHook_ApproveIsDeniedWithAnExplanation(t *testing.T) {
	const yaml = `
version: 1
name: t
inspection:
  profiles:
    pii:
      provider: regex
      categories: [private_email]
network_rules:
  - name: ask-first
    domains: ["api.example.com"]
    ports: [443]
    decision: inspect
    inspect:
      profiles: [pii]
      on_violation: approve
`
	eng, checker := buildInspectEngine(t, yaml)
	h := hookFor(eng, checker, 0)

	r := postTo(t, "https://api.example.com/v1/chat", `{"to":"alice@example.com"}`)
	err := h.PreHook(r, &RequestContext{})
	if err == nil {
		t.Fatal("a rule requiring approval allowed the request; the gate was dropped")
	}
	abort, ok := err.(*HookAbortError)
	if !ok {
		t.Fatalf("err = %T, want *HookAbortError", err)
	}
	if !strings.Contains(abort.Message, "requires approval") {
		t.Errorf("message should explain approval is unavailable here, got %q", abort.Message)
	}
}

// TestInspectHook_NoResolverOrEngineIsANoOp: a deployment with inspection off
// must not have its proxy traffic touched.
func TestInspectHook_NoResolverOrEngineIsANoOp(t *testing.T) {
	body := `{"prompt":"alice@example.com"}`

	for _, c := range []struct {
		name string
		hook *InspectHook
	}{
		{"nil resolver", NewInspectHook(nil, 0, nil)},
		{"nil engine", NewInspectHook(func() (*policy.Engine, policy.InspectChecker) { return nil, nil }, 0, nil)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := postTo(t, "https://api.example.com/v1/chat", body)
			if err := c.hook.PreHook(r, &RequestContext{}); err != nil {
				t.Fatalf("PreHook errored with no inspection configured: %v", err)
			}
			if got := readBack(t, r); got != body {
				t.Errorf("body was altered: %q", got)
			}
		})
	}
}

// TestInspectHook_ResolvesTheEnginePerRequest is the regression test for the
// stale-engine capture. Proxy.SetPolicyEngine stores a pointer at
// construction, which is why the network, transparent-TCP and DNS paths keep
// enforcing the previous policy after a live update. This hook must not do
// the same.
func TestInspectHook_ResolvesTheEnginePerRequest(t *testing.T) {
	permissive, permissiveChecker := buildInspectEngine(t, `
version: 1
name: t
network_rules:
  - name: nothing-to-inspect
    domains: ["api.example.com"]
    ports: [443]
    decision: allow
`)
	strict, strictChecker := buildInspectEngine(t, redactUpstream)

	eng, checker := permissive, permissiveChecker
	h := NewInspectHook(func() (*policy.Engine, policy.InspectChecker) { return eng, checker }, 0, nil)

	body := `{"prompt":"alice@example.com"}`
	r := postTo(t, "https://api.example.com/v1/chat", body)
	if err := h.PreHook(r, &RequestContext{}); err != nil {
		t.Fatalf("PreHook: %v", err)
	}
	if got := readBack(t, r); got != body {
		t.Fatalf("the permissive policy redacted: %q", got)
	}

	// A live policy update swaps the engine.
	eng, checker = strict, strictChecker

	r2 := postTo(t, "https://api.example.com/v1/chat", body)
	if err := h.PreHook(r2, &RequestContext{}); err != nil {
		t.Fatalf("PreHook after swap: %v", err)
	}
	if got := readBack(t, r2); strings.Contains(got, "alice@example.com") {
		t.Errorf("the hook kept using the pre-swap engine; body still carries the email: %q", got)
	}
}

// TestInspectHook_UnmatchedHostFallsThrough: a destination no rule names hits
// the engine's default-deny for network rules, which carries no inspect spec,
// so the hook leaves it to whatever else enforces network policy.
func TestInspectHook_UnmatchedHostFallsThrough(t *testing.T) {
	eng, checker := buildInspectEngine(t, redactUpstream)
	h := hookFor(eng, checker, 0)

	body := `{"prompt":"alice@example.com"}`
	r := postTo(t, "https://other.example.org/v1/chat", body)
	if err := h.PreHook(r, &RequestContext{}); err != nil {
		t.Fatalf("PreHook enforced on an unmatched host: %v", err)
	}
	if got := readBack(t, r); got != body {
		t.Errorf("body was altered for an unmatched host: %q", got)
	}
}

func TestRequestDestination(t *testing.T) {
	cases := []struct {
		name     string
		build    func() *http.Request
		wantHost string
		wantPort int
	}{
		{
			name:     "absolute https URL, no explicit port",
			build:    func() *http.Request { r, _ := http.NewRequest("POST", "https://api.example.com/v1", nil); return r },
			wantHost: "api.example.com", wantPort: 443,
		},
		{
			name: "explicit port wins",
			build: func() *http.Request {
				r, _ := http.NewRequest("POST", "https://api.example.com:8443/v1", nil)
				return r
			},
			wantHost: "api.example.com", wantPort: 8443,
		},
		{
			name:     "http scheme defaults to 80",
			build:    func() *http.Request { r, _ := http.NewRequest("POST", "http://api.example.com/v1", nil); return r },
			wantHost: "api.example.com", wantPort: 80,
		},
		{
			name:     "uppercase host is lowered for matching",
			build:    func() *http.Request { r, _ := http.NewRequest("POST", "https://API.Example.COM/v1", nil); return r },
			wantHost: "api.example.com", wantPort: 443,
		},
		{
			// A server-side request has no URL host, only the Host header.
			// Reading only r.URL.Host would send every such request to the
			// engine with an empty domain, matching nothing.
			name: "host header only",
			build: func() *http.Request {
				r := httptest.NewRequest("POST", "/v1/chat", nil)
				r.Host = "api.example.com"
				r.URL.Scheme = ""
				r.URL.Host = ""
				return r
			},
			wantHost: "api.example.com", wantPort: 443,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, port := requestDestination(c.build())
			if host != c.wantHost || port != c.wantPort {
				t.Errorf("got (%q, %d), want (%q, %d)", host, port, c.wantHost, c.wantPort)
			}
		})
	}
}

// TestInspectHook_NilBodyIsSafe: a GET through the proxy has no body.
func TestInspectHook_NilBodyIsSafe(t *testing.T) {
	eng, checker := buildInspectEngine(t, redactUpstream)
	h := hookFor(eng, checker, 0)

	r, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.PreHook(r, &RequestContext{}); err != nil {
		t.Fatalf("PreHook on a body-less request: %v", err)
	}
}
