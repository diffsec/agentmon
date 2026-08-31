package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/policy"
)

type sidecarStub struct {
	*httptest.Server
	piiReply    string
	safetyReply string
	status      int
	lastPII     atomic.Value // string: the raw request body
	lastSafety  atomic.Value
	authSeen    atomic.Value
	calls       int32
}

func newSidecarStub(t *testing.T) *sidecarStub {
	t.Helper()
	s := &sidecarStub{status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/inspect/pii", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.calls, 1)
		body := readAll(t, r)
		s.lastPII.Store(body)
		s.authSeen.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.piiReply))
	})
	mux.HandleFunc("/v1/inspect/safety", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.calls, 1)
		s.lastSafety.Store(readAll(t, r))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.safetyReply))
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func readAll(t *testing.T, r *http.Request) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

func newSidecar(t *testing.T, base, apiKey string) *provider.Sidecar {
	t.Helper()
	p, err := provider.NewSidecar(provider.SidecarConfig{BaseURL: base, APIKey: apiKey, MaxAttempts: 1})
	if err != nil {
		t.Fatalf("NewSidecar: %v", err)
	}
	return p
}

func piiRequest(content string, categories ...string) inspect.Request {
	return inspect.Request{
		Profile: "pii",
		Spec:    policy.InspectionProfile{Provider: provider.SidecarName, Categories: categories},
		Kind:    inspect.KindProxyBody,
		Content: content,
	}
}

// TestSidecar_PIISpansBecomeFindings is the happy path, and it pins the
// offsets: the span the sidecar returns must select the exact substring, or
// redaction cuts the wrong bytes.
func TestSidecar_PIISpansBecomeFindings(t *testing.T) {
	content := `{"to":"alice@example.com"}`
	start := strings.Index(content, "alice@example.com")
	end := start + len("alice@example.com")

	s := newSidecarStub(t)
	s.piiReply = `{"spans":[{"start":` + itoa(start) + `,"end":` + itoa(end) + `,"category":"private_email","score":0.99}]}`

	resp, err := newSidecar(t, s.URL, "").Inspect(context.Background(), piiRequest(content, "private_email"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(resp.Findings))
	}
	f := resp.Findings[0]
	if got := content[f.Start:f.End]; got != "alice@example.com" {
		t.Errorf("span selects %q, want the email address", got)
	}
	if f.Category != "private_email" || f.Profile != "pii" {
		t.Errorf("finding = %+v", f)
	}
	if f.Score != 0.99 {
		t.Errorf("Score = %v, want 0.99", f.Score)
	}

	// The request must carry the content and the requested categories.
	sent, _ := s.lastPII.Load().(string)
	if !strings.Contains(sent, "private_email") {
		t.Errorf("request did not name the category: %s", sent)
	}
	var req struct {
		Text       string   `json:"text"`
		Categories []string `json:"categories"`
	}
	if err := json.Unmarshal([]byte(sent), &req); err != nil {
		t.Fatalf("request body is not the documented shape: %v", err)
	}
	if req.Text != content {
		t.Errorf("Text = %q, want the exact content", req.Text)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestSidecar_RejectsSpansThatDoNotMatchTheContent is the failure this
// provider exists to catch early.
//
// Privacy Filter's own decoder works in TOKEN offsets. A sidecar that
// forwards those unconverted returns spans that look entirely plausible and
// cut the wrong bytes out of a request body. Every case here must be an
// error, not a dropped finding: the provider and the daemon disagreeing about
// offsets makes every other span in the response suspect too.
func TestSidecar_RejectsSpansThatDoNotMatchTheContent(t *testing.T) {
	content := "héllo alice@example.com" // 'é' is two bytes, so byte and rune offsets diverge

	cases := []struct {
		name string
		span string
		want string
	}{
		{"past the end", `{"start":0,"end":9999,"category":"private_email"}`, "runs past"},
		{"negative", `{"start":-1,"end":4,"category":"private_email"}`, "negative"},
		{"inverted", `{"start":8,"end":3,"category":"private_email"}`, "inverted"},
		{"empty", `{"start":4,"end":4,"category":"private_email"}`, "empty"},
		{"mid-rune start", `{"start":2,"end":8,"category":"private_email"}`, "inside a UTF-8 sequence"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSidecarStub(t)
			s.piiReply = `{"spans":[` + c.span + `]}`
			_, err := newSidecar(t, s.URL, "").Inspect(context.Background(), piiRequest(content, "private_email"))
			if err == nil {
				t.Fatal("a span that does not match the content was accepted; redaction would cut the wrong bytes")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestSidecar_DropsUnrequestedCategories: a profile scoped to `secret` must
// not start redacting every email because the sidecar volunteered one.
func TestSidecar_DropsUnrequestedCategories(t *testing.T) {
	content := "alice@example.com sk-abcdefghijklmnopqrst"
	s := newSidecarStub(t)
	s.piiReply = `{"spans":[
		{"start":0,"end":17,"category":"private_email"},
		{"start":18,"end":40,"category":"secret"}
	]}`

	resp, err := newSidecar(t, s.URL, "").Inspect(context.Background(), piiRequest(content, "secret"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("got %d findings, want only the requested category", len(resp.Findings))
	}
	if resp.Findings[0].Category != "secret" {
		t.Errorf("kept %q, want secret", resp.Findings[0].Category)
	}
}

// TestSidecar_UnsupportedCategoryIsRejectedBeforeSending is the fail-closed
// case, and it must happen before any content leaves the process.
func TestSidecar_UnsupportedCategoryIsRejectedBeforeSending(t *testing.T) {
	s := newSidecarStub(t)
	_, err := newSidecar(t, s.URL, "").Inspect(context.Background(), piiRequest("secret stuff", "invented_category"))
	if err == nil {
		t.Fatal("an unsupported category returned a clean result")
	}
	if !strings.Contains(err.Error(), "invented_category") {
		t.Errorf("err = %v", err)
	}
	if n := atomic.LoadInt32(&s.calls); n != 0 {
		t.Errorf("content was sent to the sidecar %d times despite the profile being invalid", n)
	}
}

func safetyRequest(content string, queries ...policy.InspectionQuery) inspect.Request {
	return inspect.Request{
		Profile: "exfil",
		Spec:    policy.InspectionProfile{Provider: provider.SidecarName, Instruct: "be strict", Queries: queries},
		Kind:    inspect.KindProxyBody,
		Content: content,
	}
}

// TestSidecar_SafetyThresholdIsPolicy: the profile's threshold decides, not
// the sidecar's own verdict. An operator who wrote 0.9 must not be overridden
// by a service defaulting to 0.5.
func TestSidecar_SafetyThresholdIsPolicy(t *testing.T) {
	s := newSidecarStub(t)
	// The sidecar says yes at 0.6. Below a 0.9 threshold, above a 0.5 one.
	s.safetyReply = `{"results":[{"id":"exfil","score":0.6,"verdict":true}]}`
	p := newSidecar(t, s.URL, "")

	strict, err := p.Inspect(context.Background(), safetyRequest("payload",
		policy.InspectionQuery{ID: "exfil", Text: "does it?", Threshold: 0.9}))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(strict.Findings) != 0 {
		t.Errorf("a score of 0.6 tripped a 0.9 threshold; the sidecar's verdict overrode policy")
	}

	loose, err := p.Inspect(context.Background(), safetyRequest("payload",
		policy.InspectionQuery{ID: "exfil", Text: "does it?", Threshold: 0.5}))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(loose.Findings) != 1 {
		t.Fatalf("a score of 0.6 did not trip a 0.5 threshold; got %d findings", len(loose.Findings))
	}
	if loose.Findings[0].Category != "exfil" {
		t.Errorf("Category = %q, want the query id", loose.Findings[0].Category)
	}
}

// TestSidecar_SafetyFallsBackToVerdictWithoutAScore. A score of 0.0 and an
// absent score are the same JSON zero value, which is why score is a pointer.
func TestSidecar_SafetyFallsBackToVerdictWithoutAScore(t *testing.T) {
	s := newSidecarStub(t)
	s.safetyReply = `{"results":[{"id":"exfil","verdict":true}]}`
	resp, err := newSidecar(t, s.URL, "").Inspect(context.Background(), safetyRequest("payload",
		policy.InspectionQuery{ID: "exfil", Text: "does it?"}))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("a verdict of true with no score produced %d findings, want 1", len(resp.Findings))
	}

	s.safetyReply = `{"results":[{"id":"exfil","score":0.0}]}`
	resp, err = newSidecar(t, s.URL, "").Inspect(context.Background(), safetyRequest("payload",
		policy.InspectionQuery{ID: "exfil", Text: "does it?"}))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("an explicit score of 0.0 was treated as a violation")
	}
}

// TestSidecar_UnansweredQueryIsAnError. Reporting the answered queries as a
// clean result would mean the profile checked less than it said it did.
func TestSidecar_UnansweredQueryIsAnError(t *testing.T) {
	s := newSidecarStub(t)
	s.safetyReply = `{"results":[{"id":"a","score":0.1}]}`
	_, err := newSidecar(t, s.URL, "").Inspect(context.Background(), safetyRequest("payload",
		policy.InspectionQuery{ID: "a", Text: "?"},
		policy.InspectionQuery{ID: "b", Text: "?"}))
	if err == nil {
		t.Fatal("a partially answered safety request returned a clean result")
	}
	if !strings.Contains(err.Error(), `"b"`) {
		t.Errorf("err should name the unanswered query, got %v", err)
	}
}

// TestSidecar_IgnoresUnaskedResults: a sidecar must not be able to inject
// findings the policy did not author.
func TestSidecar_IgnoresUnaskedResults(t *testing.T) {
	s := newSidecarStub(t)
	s.safetyReply = `{"results":[{"id":"a","score":0.1},{"id":"smuggled","score":1.0}]}`
	resp, err := newSidecar(t, s.URL, "").Inspect(context.Background(), safetyRequest("payload",
		policy.InspectionQuery{ID: "a", Text: "?"}))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("the sidecar injected a finding for a question nobody asked: %+v", resp.Findings)
	}
}

// TestSidecar_ErrorsDoNotLeakContent. This error reaches the audit log and,
// through the proxy hook, the agent's transcript.
func TestSidecar_ErrorsDoNotLeakContent(t *testing.T) {
	s := newSidecarStub(t)
	s.status = http.StatusInternalServerError
	s.piiReply = `{"error":"failed on input alice@example.com"}`

	_, err := newSidecar(t, s.URL, "").Inspect(context.Background(), piiRequest("alice@example.com", "private_email"))
	if err == nil {
		t.Fatal("a 500 was treated as a clean result")
	}
	if strings.Contains(err.Error(), "alice@example.com") {
		t.Errorf("the error echoed the content back: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err should carry the status, got %v", err)
	}
}

// TestSidecar_MalformedResponseIsAnError covers a body that is not the
// documented shape at all.
func TestSidecar_MalformedResponseIsAnError(t *testing.T) {
	for _, body := range []string{`not json`, `{"spans":"nope"}`, `{"unexpected":1}`} {
		s := newSidecarStub(t)
		s.piiReply = body
		if _, err := newSidecar(t, s.URL, "").Inspect(context.Background(), piiRequest("x", "secret")); err == nil {
			t.Errorf("body %q was accepted as a clean result", body)
		}
	}
}

// TestSidecar_SendsBearerToken.
func TestSidecar_SendsBearerToken(t *testing.T) {
	s := newSidecarStub(t)
	s.piiReply = `{"spans":[]}`
	if _, err := newSidecar(t, s.URL, "hunter2").Inspect(context.Background(), piiRequest("x", "secret")); err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got, _ := s.authSeen.Load().(string); got != "Bearer hunter2" {
		t.Errorf("Authorization = %q", got)
	}
}

// TestSidecar_ContextCancellationIsAnError, not a clean result.
func TestSidecar_ContextCancellationIsAnError(t *testing.T) {
	s := newSidecarStub(t)
	s.piiReply = `{"spans":[]}`
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newSidecar(t, s.URL, "").Inspect(ctx, piiRequest("x", "secret")); err == nil {
		t.Fatal("a cancelled context produced a clean result")
	}
}

// TestSidecar_IsNotLocal is what subjects it to the privacy gate. A sidecar
// bound to localhost still sends content out of the process, and nothing in
// an HTTP URL proves where it resolves to.
func TestSidecar_IsNotLocal(t *testing.T) {
	p := newSidecar(t, "http://127.0.0.1:1", "")
	if lp, ok := any(p).(interface{ IsLocal() bool }); ok && lp.IsLocal() {
		t.Fatal("the sidecar provider claims to be local; the privacy gate would wave content through to it")
	}
}

func TestNewSidecar_RejectsBadBaseURL(t *testing.T) {
	for _, c := range []struct{ url, want string }{
		{"", "required"},
		{"ftp://host", "must be http or https"},
		{"http://", "no host"},
		{"://nope", "base_url"},
	} {
		if _, err := provider.NewSidecar(provider.SidecarConfig{BaseURL: c.url}); err == nil {
			t.Errorf("base_url %q was accepted", c.url)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("base_url %q: err = %v, want %q", c.url, err, c.want)
		}
	}
}
