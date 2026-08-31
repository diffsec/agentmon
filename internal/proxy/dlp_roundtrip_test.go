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
)

// startTokenizingProxy runs a real proxy in tokenize mode in front of a fake
// upstream, and returns the proxy's base URL. upstream is handed the request
// body it actually received, so a test can assert what left the machine.
func startTokenizingProxy(t *testing.T, upstream http.HandlerFunc) (string, func()) {
	t.Helper()

	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	p, err := New(Config{
		SessionID: "test-session",
		Proxy:     config.ProxyConfig{Mode: "openai", Providers: config.ProxyProvidersConfig{OpenAI: up.URL}},
		DLP:       config.DLPConfig{Mode: "tokenize", Patterns: config.DLPPatternsConfig{Email: true}},
	}, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Stop(ctx)
	}
	t.Cleanup(stop)

	addr := p.Addr()
	if addr == nil {
		t.Fatal("proxy has no address after Start")
	}
	return "http://" + addr.String(), stop
}

const secretEmail = "alice@example.com"

// TestDLPTokenize_RoundTripsThroughTheProxy is the end-to-end proof that
// tokenize mode is now a two-way door.
//
// Before this change Detokenize had no callers anywhere in the tree: the
// request went upstream with TOK_<hex> substituted, and the response came
// back referring to tokens the agent had no way to resolve. The feature was
// shipped, configurable, and half-implemented.
func TestDLPTokenize_RoundTripsThroughTheProxy(t *testing.T) {
	var sawUpstream string
	base, _ := startTokenizingProxy(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sawUpstream = string(body)
		// Echo the token back the way a model would quote its input.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"reply":"I will contact `+extractToken(string(body))+` shortly"}`)
	})

	resp := post(t, base+"/v1/chat/completions", `{"messages":[{"content":"email `+secretEmail+`"}]}`)

	// The upstream must never have seen the real address.
	if strings.Contains(sawUpstream, secretEmail) {
		t.Fatalf("the address reached the upstream: %s", sawUpstream)
	}
	if !strings.Contains(sawUpstream, "TOK_") {
		t.Fatalf("nothing was tokenized: %s", sawUpstream)
	}

	// The agent must get the real address back.
	if !strings.Contains(resp, secretEmail) {
		t.Errorf("the response was not detokenized: %s", resp)
	}
	if strings.Contains(resp, "TOK_") {
		t.Errorf("a token leaked to the agent: %s", resp)
	}
}

// TestDLPTokenize_RoundTripsThroughAnSSEStream covers the path that matters
// most in practice: LLM responses are streamed, and SSE never reaches
// ModifyResponse — RoundTrip streams it and returns errSSEHandled. Fixing
// only the buffered path would have left tokenize mode broken for the common
// case while looking fixed.
func TestDLPTokenize_RoundTripsThroughAnSSEStream(t *testing.T) {
	var sawUpstream string
	base, _ := startTokenizingProxy(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sawUpstream = string(body)
		tok := extractToken(sawUpstream)

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)

		// Split the token across two SSE writes, which is exactly what a
		// token-by-token model stream does.
		mid := len(tok) / 2
		for _, chunk := range []string{
			`data: {"delta":"contacting ` + tok[:mid],
			tok[mid:] + ` now"}` + "\n\n",
			"data: [DONE]\n\n",
		} {
			_, _ = io.WriteString(w, chunk)
			if flusher != nil {
				flusher.Flush()
			}
		}
	})

	resp := post(t, base+"/v1/chat/completions", `{"messages":[{"content":"email `+secretEmail+`"}]}`)

	if strings.Contains(sawUpstream, secretEmail) {
		t.Fatalf("the address reached the upstream: %s", sawUpstream)
	}
	if !strings.Contains(resp, secretEmail) {
		t.Errorf("the streamed response was not detokenized: %q", resp)
	}
	if strings.Contains(resp, "TOK_") {
		t.Errorf("a token leaked to the agent through the stream: %q", resp)
	}
}

func post(t *testing.T, url, body string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The dialect detector keys on the auth header (dialect.go:90); without
	// one the proxy answers "unknown LLM dialect" and never reaches DLP.
	req.Header.Set("Authorization", "Bearer sk-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return string(out)
}

func extractToken(s string) string {
	i := strings.Index(s, "TOK_")
	if i < 0 || i+tokenLen > len(s) {
		return ""
	}
	return s[i : i+tokenLen]
}
