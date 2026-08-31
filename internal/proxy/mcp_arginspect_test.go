package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/config"

	"github.com/diffsec/agentmon/internal/mcpregistry"
	"github.com/diffsec/agentmon/internal/policy"
)

const argPolicyYAML = `
version: 1
name: test
inspection:
  profiles:
    pii:
      provider: privacy_filter
      categories: [private_email]
mcp_inspect_rules:
  - name: inspect-weather-args
    tools: ["get_weather"]
    decision: inspect
    inspect:
      profiles: [pii]
      on_violation: %ONVIOLATION%
      on_failure: %ONFAILURE%
`

// argChecker answers with whatever the test wants, so these tests exercise
// the wiring rather than any provider.
type argChecker struct {
	verdict policy.InspectVerdict
	err     error
	calls   int
	gotBody string
}

func (c *argChecker) Inspect(_ context.Context, req policy.InspectRequest) (policy.InspectVerdict, error) {
	c.calls++
	c.gotBody = req.Content
	return c.verdict, c.err
}

func newArgInspectorFor(t *testing.T, onViolation, onFailure string, checker policy.InspectChecker) *mcpArgInspector {
	t.Helper()
	yaml := strings.Replace(argPolicyYAML, "%ONVIOLATION%", onViolation, 1)
	yaml = strings.Replace(yaml, "%ONFAILURE%", onFailure, 1)

	p, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	eng, err := policy.NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return newMCPArgInspector(func() (*policy.Engine, policy.InspectChecker) {
		return eng, checker
	}, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func argRegistry() *mcpregistry.Registry {
	return newTestRegistry("my-server", "stdio", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
		{Name: "send_email", Hash: "def456"},
	})
}

func anthropicToolBody(input string) []byte {
	return []byte(`{"stop_reason":"tool_use","content":[
		{"type":"text","text":"here you go"},
		{"type":"tool_use","id":"toolu_01","name":"get_weather","input":` + input + `}
	]}`)
}

// TestMCPArgs_MatchesOnlyWhatARuleNames. Inference runs at a few KB/s
// (docs/inspection.md), and matches() is what the streaming paths ask before
// holding a tool call back. A false positive here adds the model's latency to
// every tool call in the session.
func TestMCPArgs_MatchesOnlyWhatARuleNames(t *testing.T) {
	a := newArgInspectorFor(t, "deny", "fail_closed", &argChecker{})

	if !a.matches("my-server", "get_weather") {
		t.Error("matches() = false for the tool the rule names")
	}
	if a.matches("my-server", "send_email") {
		t.Error("matches() = true for a tool no rule names")
	}
	var nilInsp *mcpArgInspector
	if nilInsp.matches("my-server", "get_weather") {
		t.Error("a nil inspector matched; the streaming paths call this on a nil receiver")
	}
}

// TestMCPArgs_Decide covers the resolution table. Each row is a distinct way
// the arguments can fail to be safe, and each has a different correct answer.
func TestMCPArgs_Decide(t *testing.T) {
	clean := policy.InspectVerdict{}
	violation := policy.InspectVerdict{Violation: true, Profile: "pii", Detail: "1 finding: private_email"}
	redacting := policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}
	corrupt := policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding",
		Redacted: `{"to":"[REDACTED`, // truncated, not valid JSON
	}

	cases := []struct {
		name                    string
		onViolation, onFailure  string
		verdict                 policy.InspectVerdict
		err                     error
		args                    string
		oversize                bool
		wantBlock, wantRedacted bool
	}{
		{name: "clean", onViolation: "deny", onFailure: "fail_closed", verdict: clean, args: `{"city":"NYC"}`},
		{name: "violation denies", onViolation: "deny", onFailure: "fail_closed", verdict: violation, args: `{"to":"a@b.c"}`, wantBlock: true},
		{name: "violation allowed", onViolation: "allow", onFailure: "fail_closed", verdict: violation, args: `{"to":"a@b.c"}`},
		{name: "violation redacts", onViolation: "redact", onFailure: "fail_closed", verdict: redacting, args: `{"to":"a@b.c"}`, wantRedacted: true},
		{name: "approve blocks", onViolation: "approve", onFailure: "fail_closed", verdict: violation, args: `{"to":"a@b.c"}`, wantBlock: true},
		{name: "corrupt redaction blocks", onViolation: "redact", onFailure: "fail_closed", verdict: corrupt, args: `{"to":"a@b.c"}`, wantBlock: true},
		{name: "provider error fails closed", onViolation: "deny", onFailure: "fail_closed", err: errors.New("boom"), args: `{"a":1}`, wantBlock: true},
		{name: "provider error fails open", onViolation: "deny", onFailure: "fail_open", err: errors.New("boom"), args: `{"a":1}`},
		{name: "oversize fails closed", onViolation: "deny", onFailure: "fail_closed", verdict: clean, oversize: true, wantBlock: true},
		{name: "oversize fails open", onViolation: "deny", onFailure: "fail_open", verdict: clean, oversize: true},
		{name: "no arguments is clean", onViolation: "deny", onFailure: "fail_closed", verdict: violation, args: ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checker := &argChecker{verdict: c.verdict, err: c.err}
			a := newArgInspectorFor(t, c.onViolation, c.onFailure, checker)

			v := a.decide(context.Background(), "my-server", "get_weather", json.RawMessage(c.args), c.oversize)
			if !v.Inspected {
				t.Fatal("Inspected = false for a tool the rule names")
			}
			if v.Block != c.wantBlock {
				t.Errorf("Block = %v, want %v (reason %q)", v.Block, c.wantBlock, v.Reason)
			}
			if (v.Redacted != nil) != c.wantRedacted {
				t.Errorf("Redacted = %s, want redacted = %v", v.Redacted, c.wantRedacted)
			}
			if c.wantBlock && v.Reason == "" {
				t.Error("a block with no reason; the agent gets a tool call removed with no explanation")
			}
			// The approve arm must say why, or it is indistinguishable
			// from an ordinary deny and the operator goes looking for a
			// rule that denied.
			if c.onViolation == "approve" && c.wantBlock && !strings.Contains(v.Reason, "approval") {
				t.Errorf("reason = %q, want it to say approval is unavailable here", v.Reason)
			}
			// A block reason is written into the agent's own transcript,
			// which is one of the places the content was being kept out of.
			if strings.Contains(v.Reason, "a@b.c") {
				t.Errorf("reason leaks the matched text: %q", v.Reason)
			}
		})
	}
}

// TestMCPArgs_UnmatchedToolIsNotInspected. A tool no rule names must not
// reach a provider at all.
func TestMCPArgs_UnmatchedToolIsNotInspected(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{Violation: true, Detail: "1 finding"}}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	v := a.decide(context.Background(), "my-server", "send_email", json.RawMessage(`{"to":"a@b.c"}`), false)
	if v.Inspected {
		t.Error("Inspected = true for a tool no rule names")
	}
	if v.Block {
		t.Error("a tool no rule names was blocked")
	}
	if checker.calls != 0 {
		t.Errorf("checker was called %d times, want 0", checker.calls)
	}
}

// TestMCPArgs_OversizeIsNotTruncation. Accumulating a prefix and inspecting
// it clean would report the whole argument clean. The accumulator has to
// remember that it stopped.
func TestMCPArgs_OversizeIsNotTruncation(t *testing.T) {
	acc := newAccumulator(10)
	acc.add("12345")
	acc.add("67890123") // pushes past the cap
	if !acc.overflow {
		t.Fatal("overflow = false after exceeding the cap")
	}
	if acc.bytes() != nil {
		t.Errorf("bytes() = %s after overflow; a truncated prefix must not be offered for inspection", acc.bytes())
	}

	// Later fragments are discarded rather than resetting the flag.
	acc.add("x")
	if !acc.overflow {
		t.Error("overflow was cleared by a later fragment")
	}
}

// TestInterceptMCPToolCalls_ArgsRedacted checks the whole non-streaming path:
// the response the agent reads must carry the redacted arguments, and nothing
// else about the response may change.
func TestInterceptMCPToolCalls_ArgsRedacted(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}}
	a := newArgInspectorFor(t, "redact", "fail_closed", checker)

	body := anthropicToolBody(`{"to":"alice@example.com"}`)
	result := interceptMCPToolCalls(context.Background(), body, DialectAnthropic, argRegistry(),
		newAllowingPolicy(), "req_1", "sess_1", nil, nil, nil, a)

	if result.HasBlocked {
		t.Fatal("a redacted call was reported as blocked")
	}
	if result.RewrittenBody == nil {
		t.Fatal("no rewritten body; the agent would receive the original arguments")
	}
	out := string(result.RewrittenBody)
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the rewritten body still carries the matched text: %s", out)
	}
	if !strings.Contains(out, "[REDACTED:private_email]") {
		t.Fatalf("the redaction did not reach the body: %s", out)
	}
	// Everything else about the response has to survive: a lost text block
	// or a changed stop_reason breaks the turn for reasons unrelated to the
	// rule that fired.
	if !strings.Contains(out, "here you go") {
		t.Errorf("the text block was dropped: %s", out)
	}
	if !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Errorf("stop_reason changed on a call that was not blocked: %s", out)
	}
	if !strings.Contains(out, `"toolu_01"`) {
		t.Errorf("the tool_use id was lost: %s", out)
	}

	if len(result.Events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(result.Events))
	}
	ev := result.Events[0]
	if ev.Action != "redact" {
		t.Errorf("event action = %q, want redact", ev.Action)
	}
	if strings.Contains(string(ev.Input), "alice@example.com") {
		t.Errorf("the audit event carries the pre-redaction arguments: %s", ev.Input)
	}
	if ev.InspectRule != "inspect-weather-args" {
		t.Errorf("event inspect_rule = %q, want the matched rule", ev.InspectRule)
	}
}

// TestInterceptMCPToolCalls_ArgsBlocked. A blocked call must be replaced, and
// its arguments must not survive anywhere the agent or an operator can read
// them back.
func TestInterceptMCPToolCalls_ArgsBlocked(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
	}}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	body := anthropicToolBody(`{"to":"alice@example.com"}`)
	result := interceptMCPToolCalls(context.Background(), body, DialectAnthropic, argRegistry(),
		newAllowingPolicy(), "req_1", "sess_1", nil, nil, nil, a)

	if !result.HasBlocked {
		t.Fatal("HasBlocked = false for a call inspection denied")
	}
	out := string(result.RewrittenBody)
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the blocked arguments reached the agent: %s", out)
	}
	if strings.Contains(out, `"tool_use"`) && strings.Contains(out, `"get_weather"`) {
		t.Errorf("the tool_use block survived: %s", out)
	}
	// Every tool_use was blocked, so the turn ends rather than waiting for a
	// tool result that will never come.
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Errorf("stop_reason was not rewritten: %s", out)
	}
	if strings.Contains(string(result.Events[0].Input), "alice@example.com") {
		t.Errorf("the audit event carries the blocked arguments: %s", result.Events[0].Input)
	}
}

// TestInterceptMCPToolCalls_ArgsRedactedOpenAI. OpenAI carries arguments as a
// JSON *string*, so the redacted object has to be re-encoded as one.
// Splicing it in raw would produce a tool call whose arguments are an object
// where the API contract says a string.
func TestInterceptMCPToolCalls_ArgsRedactedOpenAI(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}}
	a := newArgInspectorFor(t, "redact", "fail_closed", checker)

	body := []byte(`{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[
		{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"to\":\"alice@example.com\"}"}}
	]}}]}`)

	result := interceptMCPToolCalls(context.Background(), body, DialectOpenAI, argRegistry(),
		newAllowingPolicy(), "req_1", "sess_1", nil, nil, nil, a)

	if result.RewrittenBody == nil {
		t.Fatal("no rewritten body")
	}
	if strings.Contains(string(result.RewrittenBody), "alice@example.com") {
		t.Fatalf("the rewritten body still carries the matched text: %s", result.RewrittenBody)
	}

	var out struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result.RewrittenBody, &out); err != nil {
		t.Fatalf("the rewritten body is not a valid OpenAI response: %v", err)
	}
	if len(out.Choices) != 1 || len(out.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("tool call structure changed: %s", result.RewrittenBody)
	}
	tc := out.Choices[0].Message.ToolCalls[0]
	if tc.ID != "call_1" || tc.Function.Name != "get_weather" {
		t.Errorf("tool call identity changed: %+v", tc)
	}
	// arguments must still decode as a string containing JSON.
	if !json.Valid([]byte(tc.Function.Arguments)) {
		t.Fatalf("arguments is not a JSON string containing JSON: %q", tc.Function.Arguments)
	}
	if !strings.Contains(tc.Function.Arguments, "[REDACTED:private_email]") {
		t.Errorf("arguments = %q, want the redacted value", tc.Function.Arguments)
	}
}

// TestInterceptMCPToolCalls_RedactionIsPerCall. Blocking is keyed on the tool
// NAME, which is all the rewriters could match on before. Redaction cannot
// be: two calls to the same tool can carry different arguments, and rewriting
// both with one call's redaction would corrupt the other.
func TestInterceptMCPToolCalls_RedactionIsPerCall(t *testing.T) {
	// Only the second call's arguments come back with a finding.
	checker := &perCallChecker{dirty: `{"to":"alice@example.com"}`}
	a := newArgInspectorFor(t, "redact", "fail_closed", checker)

	body := []byte(`{"stop_reason":"tool_use","content":[
		{"type":"tool_use","id":"toolu_clean","name":"get_weather","input":{"city":"NYC"}},
		{"type":"tool_use","id":"toolu_dirty","name":"get_weather","input":{"to":"alice@example.com"}}
	]}`)

	result := interceptMCPToolCalls(context.Background(), body, DialectAnthropic, argRegistry(),
		newAllowingPolicy(), "req_1", "sess_1", nil, nil, nil, a)

	if result.RewrittenBody == nil {
		t.Fatal("no rewritten body")
	}
	out := string(result.RewrittenBody)
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the flagged call was not redacted: %s", out)
	}
	if !strings.Contains(out, `"NYC"`) {
		t.Fatalf("the clean call's arguments were overwritten: %s", out)
	}
	if !strings.Contains(out, `"toolu_clean"`) || !strings.Contains(out, `"toolu_dirty"`) {
		t.Errorf("a tool_use block was lost: %s", out)
	}
}

// perCallChecker reports a finding only for the exact content it was told to
// treat as dirty.
type perCallChecker struct{ dirty string }

func (c *perCallChecker) Inspect(_ context.Context, req policy.InspectRequest) (policy.InspectVerdict, error) {
	if req.Content != c.dirty {
		return policy.InspectVerdict{}, nil
	}
	return policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}, nil
}

// TestInterceptMCPToolCalls_NoInspectorIsUnchanged. Every session without
// mcp_inspect_rules must behave exactly as it did, including leaving
// RewrittenBody nil so the original bytes reach the agent.
func TestInterceptMCPToolCalls_NoInspectorIsUnchanged(t *testing.T) {
	body := anthropicToolBody(`{"to":"alice@example.com"}`)
	result := interceptMCPToolCalls(context.Background(), body, DialectAnthropic, argRegistry(),
		newAllowingPolicy(), "req_1", "sess_1", nil, nil, nil, nil)

	if result.HasBlocked {
		t.Error("a call was blocked with no inspector configured")
	}
	if result.RewrittenBody != nil {
		t.Errorf("the body was rewritten with no inspector configured: %s", result.RewrittenBody)
	}
	if len(result.Events) != 1 || result.Events[0].Action != "allow" {
		t.Errorf("events = %+v, want a single allow", result.Events)
	}
	if result.Events[0].InspectRule != "" {
		t.Errorf("event names an inspect rule that did not run: %q", result.Events[0].InspectRule)
	}
}

// TestProxy_ArgRedaction_Integration is the end-to-end check that a redacted
// tool call actually reaches the agent through the proxy.
//
// The unit tests above verify that interceptMCPToolCalls produces a rewritten
// body. This one verifies that ModifyResponse uses it. Those were separate
// conditions until this change: the proxy only substituted the rewritten body
// when something had been blocked, so a purely redacting policy produced a
// rewrite that was computed and thrown away.
func TestProxy_ArgRedaction_Integration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "msg_1", "type": "message", "role": "assistant",
			"stop_reason": "tool_use",
			"content": [
				{"type": "text", "text": "Sending that."},
				{"type": "tool_use", "id": "toolu_01", "name": "get_weather",
				 "input": {"to": "alice@example.com"}}
			]
		}`))
	}))
	defer upstream.Close()

	cfg := Config{
		SessionID: "test-arg-redaction",
		Proxy: config.ProxyConfig{
			Mode: "embedded", Port: 0,
			Providers: config.ProxyProvidersConfig{Anthropic: upstream.URL},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New(cfg, t.TempDir(), logger)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	p.SetRegistry(argRegistry())

	// No MCP tool policy at all, only argument inspection. That combination
	// is what the interception gate has to recognise.
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}}
	eng := engineFor(t, "redact", "fail_closed")
	p.SetMCPArgInspection(func() (*policy.Engine, policy.InspectChecker) {
		return eng, checker
	}, 0)

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Stop(sctx)
	}()

	req, err := http.NewRequest(http.MethodPost,
		"http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "sk-ant-test-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if checker.calls != 1 {
		t.Fatalf("checker was called %d times, want 1; the interception gate did not run", checker.calls)
	}
	if strings.Contains(string(body), "alice@example.com") {
		t.Fatalf("the agent received the unredacted arguments:\n%s", body)
	}
	if !strings.Contains(string(body), "[REDACTED:private_email]") {
		t.Fatalf("the redaction did not reach the agent:\n%s", body)
	}
	if !strings.Contains(string(body), "Sending that.") {
		t.Errorf("the rest of the response was lost:\n%s", body)
	}
}

// engineFor builds a policy engine from argPolicyYAML.
func engineFor(t *testing.T, onViolation, onFailure string) *policy.Engine {
	t.Helper()
	yaml := strings.Replace(argPolicyYAML, "%ONVIOLATION%", onViolation, 1)
	yaml = strings.Replace(yaml, "%ONFAILURE%", onFailure, 1)
	pol, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := pol.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}
