package mcpinspect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/policy"
)

const argInspectPolicy = `
version: 1
name: test
inspection:
  profiles:
    pii:
      provider: privacy_filter
      categories: [private_email]
mcp_inspect_rules:
  - name: inspect-fetch-args
    tools: ["web_fetch"]
    decision: inspect
    inspect:
      profiles: [pii]
      on_violation: %s
      on_failure: %s
`

// fakeChecker answers with whatever the test wants, so these tests exercise
// the wiring rather than any provider.
type fakeChecker struct {
	verdict policy.InspectVerdict
	err     error
	calls   int
	gotKind string
	gotBody string
}

func (f *fakeChecker) Inspect(_ context.Context, req policy.InspectRequest) (policy.InspectVerdict, error) {
	f.calls++
	f.gotKind = req.Kind
	f.gotBody = req.Content
	return f.verdict, f.err
}

func newArgInspector(t *testing.T, onViolation, onFailure string, checker policy.InspectChecker) (*Inspector, *[]interface{}) {
	t.Helper()
	yaml := strings.Replace(argInspectPolicy, "%s", onViolation, 1)
	yaml = strings.Replace(yaml, "%s", onFailure, 1)

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

	var events []interface{}
	insp := NewInspectorWithDetection("sess", "websearch", func(ev interface{}) {
		events = append(events, ev)
	})
	insp.SetArgInspection(&ArgInspection{
		Resolve: func() (*policy.Engine, policy.InspectChecker) { return eng, checker },
	})
	return insp, &events
}

func toolsCall(tool, args string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`)
}

// TestArgInspection_CleanCallIsForwarded. The common case must stay
// untouched: an inspected tool call that comes back clean is forwarded byte
// for byte, not rewritten and not blocked.
func TestArgInspection_CleanCallIsForwarded(t *testing.T) {
	checker := &fakeChecker{}
	insp, events := newArgInspector(t, "deny", "fail_closed", checker)

	msg := toolsCall("web_fetch", `{"url":"https://example.com"}`)
	res, err := insp.Inspect(context.Background(), msg, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res != nil && res.Action == "block" {
		t.Fatalf("a clean call was blocked: %s", res.Reason)
	}
	if res != nil && res.Rewritten != nil {
		t.Error("a clean call was rewritten")
	}
	if checker.calls != 1 {
		t.Fatalf("checker was called %d times, want 1", checker.calls)
	}
	if checker.gotKind != inspect.KindMCPArgs {
		t.Errorf("inspected kind = %q, want %q", checker.gotKind, inspect.KindMCPArgs)
	}
	if checker.gotBody != `{"url":"https://example.com"}` {
		t.Errorf("inspected content = %q, want the raw arguments", checker.gotBody)
	}
	if len(*events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(*events))
	}
	ev := (*events)[0].(MCPToolCalledEvent)
	if ev.Action != "allow" {
		t.Errorf("event action = %q, want allow", ev.Action)
	}
	if ev.InspectRule != "inspect-fetch-args" {
		t.Errorf("event inspect_rule = %q, want the matched rule", ev.InspectRule)
	}
}

// TestArgInspection_UnmatchedToolIsNotInspected. Inference runs at a few KB/s
// (docs/inspection.md), so inspecting a tool no rule names is not merely
// wasted work -- it puts a model in front of every tool call in the session.
func TestArgInspection_UnmatchedToolIsNotInspected(t *testing.T) {
	checker := &fakeChecker{verdict: policy.InspectVerdict{Violation: true, Detail: "1 finding"}}
	insp, _ := newArgInspector(t, "deny", "fail_closed", checker)

	res, err := insp.Inspect(context.Background(), toolsCall("read_file", `{"path":"/tmp/x"}`), DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res != nil && res.Action == "block" {
		t.Fatal("a tool no rule names was blocked")
	}
	if checker.calls != 0 {
		t.Errorf("checker was called %d times for an unmatched tool, want 0", checker.calls)
	}
}

// TestArgInspection_ViolationBlocks is the control this whole wire point
// exists for. Before it, handleToolsCall annotated the event and forwarded
// the call regardless.
func TestArgInspection_ViolationBlocks(t *testing.T) {
	checker := &fakeChecker{verdict: policy.InspectVerdict{
		Violation: true,
		Profile:   "pii",
		Detail:    "1 finding: private_email",
	}}
	insp, events := newArgInspector(t, "deny", "fail_closed", checker)

	msg := toolsCall("web_fetch", `{"url":"https://example.com/?to=alice@example.com"}`)
	res, err := insp.Inspect(context.Background(), msg, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res == nil || res.Action != "block" {
		t.Fatalf("result = %+v, want a block", res)
	}
	if !strings.Contains(res.Reason, "private_email") {
		t.Errorf("reason = %q, want it to name the category found", res.Reason)
	}
	// The reason is written back to the agent as a JSON-RPC error and lands
	// in the agent's own transcript, which is one of the places the content
	// was being kept out of.
	if strings.Contains(res.Reason, "alice@example.com") {
		t.Errorf("reason leaks the matched text: %q", res.Reason)
	}
	ev := (*events)[0].(MCPToolCalledEvent)
	if ev.Action != "block" {
		t.Errorf("event action = %q, want block", ev.Action)
	}
	if strings.Contains(ev.InspectDetail, "alice@example.com") {
		t.Errorf("event detail leaks the matched text: %q", ev.InspectDetail)
	}
}

// TestArgInspection_OnFailure. A provider that errors, times out or is not
// configured means the arguments were NOT inspected. That must reach the
// rule's on_failure, which defaults to fail_closed -- never a silent forward.
func TestArgInspection_OnFailure(t *testing.T) {
	for _, c := range []struct {
		onFailure string
		wantBlock bool
	}{
		{"fail_closed", true},
		{"fail_open", false},
		{"approve", true}, // no approver on this path; deny with a reason
	} {
		t.Run(c.onFailure, func(t *testing.T) {
			checker := &fakeChecker{err: errors.New("provider exploded")}
			insp, events := newArgInspector(t, "deny", c.onFailure, checker)

			res, err := insp.Inspect(context.Background(), toolsCall("web_fetch", `{"url":"x"}`), DirectionRequest)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			blocked := res != nil && res.Action == "block"
			if blocked != c.wantBlock {
				t.Fatalf("on_failure %s: blocked = %v, want %v (result %+v)", c.onFailure, blocked, c.wantBlock, res)
			}
			ev := (*events)[0].(MCPToolCalledEvent)
			if ev.InspectError == "" {
				t.Error("the event records no inspection error; an operator has no way to tell a failed inspection from a clean one")
			}
		})
	}
}

// TestArgInspection_NoInspectorConfiguredFailsClosed. A policy that asks for
// inspection on a host with no inspector must not forward the call: that is
// uninspected content under a rule that said to inspect it.
func TestArgInspection_NoInspectorConfiguredFailsClosed(t *testing.T) {
	insp, _ := newArgInspector(t, "deny", "fail_closed", nil)

	res, err := insp.Inspect(context.Background(), toolsCall("web_fetch", `{"url":"x"}`), DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res == nil || res.Action != "block" {
		t.Fatalf("result = %+v, want a block when no inspector is configured", res)
	}
}

// TestArgInspection_RedactRewritesTheCall. Redaction is the useful action for
// PII in a tool argument: the call still happens, without the value.
func TestArgInspection_RedactRewritesTheCall(t *testing.T) {
	checker := &fakeChecker{verdict: policy.InspectVerdict{
		Violation: true,
		Profile:   "pii",
		Detail:    "1 finding: private_email",
		Redacted:  `{"url":"https://example.com","to":"[REDACTED:private_email]"}`,
	}}
	insp, events := newArgInspector(t, "redact", "fail_closed", checker)

	msg := toolsCall("web_fetch", `{"url":"https://example.com","to":"alice@example.com"}`)
	res, err := insp.Inspect(context.Background(), msg, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res == nil || res.Action == "block" {
		t.Fatalf("result = %+v, want the call forwarded with a rewrite", res)
	}
	if res.Rewritten == nil {
		t.Fatal("no rewritten message; the original arguments would be forwarded unchanged")
	}
	if strings.Contains(string(res.Rewritten), "alice@example.com") {
		t.Fatalf("the rewritten message still carries the matched text: %s", res.Rewritten)
	}

	// The rewrite must still be the same request. A lost id leaves the
	// client waiting for a reply it can never correlate; a lost method
	// fails at the server.
	got, err := ParseToolsCallRequest(res.Rewritten)
	if err != nil {
		t.Fatalf("the rewritten message no longer parses as a tools/call: %v", err)
	}
	if got.Method != "tools/call" || string(got.ID) != "1" || got.Params.Name != "web_fetch" {
		t.Errorf("rewritten request = %+v; method, id and tool name must survive", got)
	}
	if !strings.Contains(string(got.Params.Arguments), "[REDACTED:private_email]") {
		t.Errorf("arguments = %s, want the redacted value", got.Params.Arguments)
	}

	ev := (*events)[0].(MCPToolCalledEvent)
	if ev.Action != "redact" {
		t.Errorf("event action = %q, want redact", ev.Action)
	}
}

// TestArgInspection_RedactPreservesUnknownFields. The rewrite goes through
// map[string]json.RawMessage precisely so a field this package does not model
// -- an MCP extension, a `_meta` block -- survives it. Dropping one would
// break the call in a way that looks like the server's fault.
func TestArgInspection_RedactPreservesUnknownFields(t *testing.T) {
	checker := &fakeChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}}
	insp, _ := newArgInspector(t, "redact", "fail_closed", checker)

	msg := []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","extra":"keep","params":{"name":"web_fetch","_meta":{"trace":"abc"},"arguments":{"to":"alice@example.com"}}}`)
	res, err := insp.Inspect(context.Background(), msg, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res == nil || res.Rewritten == nil {
		t.Fatalf("result = %+v, want a rewrite", res)
	}

	var out map[string]json.RawMessage
	if err := json.Unmarshal(res.Rewritten, &out); err != nil {
		t.Fatalf("rewritten message does not parse: %v", err)
	}
	if string(out["extra"]) != `"keep"` {
		t.Errorf("top-level field dropped: extra = %s", out["extra"])
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(out["params"], &params); err != nil {
		t.Fatalf("params does not parse: %v", err)
	}
	if string(params["_meta"]) != `{"trace":"abc"}` {
		t.Errorf("params field dropped: _meta = %s", params["_meta"])
	}
}

// TestArgInspection_CorruptRedactionBlocks. Redaction rewrites the arguments
// as raw JSON text, so a span crossing a structural character produces
// something that no longer parses. Forwarding it would corrupt the call;
// forwarding the original would send exactly the content the rule flagged.
func TestArgInspection_CorruptRedactionBlocks(t *testing.T) {
	checker := &fakeChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding",
		Redacted: `{"to":"[REDACTED:private_email]`, // truncated, not valid JSON
	}}
	insp, _ := newArgInspector(t, "redact", "fail_closed", checker)

	msg := toolsCall("web_fetch", `{"to":"alice@example.com"}`)
	res, err := insp.Inspect(context.Background(), msg, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res == nil || res.Action != "block" {
		t.Fatalf("result = %+v, want a block when redaction produced invalid JSON", res)
	}
	if res.Rewritten != nil {
		t.Error("a corrupt rewrite was offered for forwarding")
	}
}

// TestArgInspection_NoArgumentsIsClean. A tools/call with no arguments
// carries no content. Routing it through on_failure would deny every
// zero-argument call under a fail_closed rule, which is most of them.
func TestArgInspection_NoArgumentsIsClean(t *testing.T) {
	checker := &fakeChecker{}
	insp, _ := newArgInspector(t, "deny", "fail_closed", checker)

	msg := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"web_fetch"}}`)
	res, err := insp.Inspect(context.Background(), msg, DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res != nil && res.Action == "block" {
		t.Fatalf("a call with no arguments was blocked: %s", res.Reason)
	}
	if checker.calls != 0 {
		t.Errorf("checker was called %d times for a call with no arguments, want 0", checker.calls)
	}
}

// TestArgInspection_ApproveBlocksWithAReason. The wrapper forwards or refuses
// one JSON-RPC line and has nobody to ask for approval. Downgrading to allow
// would pass content a rule asked a human to look at.
func TestArgInspection_ApproveBlocksWithAReason(t *testing.T) {
	checker := &fakeChecker{verdict: policy.InspectVerdict{Violation: true, Detail: "1 finding"}}
	insp, _ := newArgInspector(t, "approve", "fail_closed", checker)

	res, err := insp.Inspect(context.Background(), toolsCall("web_fetch", `{"to":"x"}`), DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res == nil || res.Action != "block" {
		t.Fatalf("result = %+v, want a block", res)
	}
	if !strings.Contains(res.Reason, "approval") {
		t.Errorf("reason = %q, want it to say approval is unavailable here", res.Reason)
	}
}

// TestArgInspection_DisabledKeepsTheOldBehaviour. Every existing deployment
// has no ArgInspection installed, and must keep the alert-only detector
// behaviour rather than acquiring a new way to block.
func TestArgInspection_Disabled(t *testing.T) {
	var events []interface{}
	insp := NewInspectorWithDetection("sess", "websearch", func(ev interface{}) {
		events = append(events, ev)
	})

	res, err := insp.Inspect(context.Background(), toolsCall("web_fetch", `{"to":"alice@example.com"}`), DirectionRequest)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res != nil {
		t.Fatalf("result = %+v, want nil with no ArgInspection installed", res)
	}
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	if ev := events[0].(MCPToolCalledEvent); ev.Action != "" {
		t.Errorf("event action = %q, want empty when inspection did not run", ev.Action)
	}
}

// TestArgInspection_EventDoesNotCarryFlaggedContent. MCPToolCalledEvent is
// persisted and streamed to clients (internal/api/mcp_event.go). A blocked
// call's arguments are exactly what the rule flagged, and a redacted call's
// originals are what the rule asked to have taken out; putting either in the
// event stream would undo the control at the moment it fired.
func TestArgInspection_EventDoesNotCarryFlaggedContent(t *testing.T) {
	t.Run("blocked", func(t *testing.T) {
		checker := &fakeChecker{verdict: policy.InspectVerdict{
			Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		}}
		insp, events := newArgInspector(t, "deny", "fail_closed", checker)

		_, err := insp.Inspect(context.Background(), toolsCall("web_fetch", `{"to":"alice@example.com"}`), DirectionRequest)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		ev := (*events)[0].(MCPToolCalledEvent)
		if strings.Contains(string(ev.Input), "alice@example.com") {
			t.Fatalf("the audit event carries the flagged arguments: %s", ev.Input)
		}
		if ev.InspectDetail == "" {
			t.Error("the event says nothing about what was found; dropping Input must not also drop the reason")
		}
	})

	t.Run("redacted", func(t *testing.T) {
		checker := &fakeChecker{verdict: policy.InspectVerdict{
			Violation: true, Profile: "pii", Detail: "1 finding: private_email",
			Redacted: `{"to":"[REDACTED:private_email]"}`,
		}}
		insp, events := newArgInspector(t, "redact", "fail_closed", checker)

		_, err := insp.Inspect(context.Background(), toolsCall("web_fetch", `{"to":"alice@example.com"}`), DirectionRequest)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		ev := (*events)[0].(MCPToolCalledEvent)
		if strings.Contains(string(ev.Input), "alice@example.com") {
			t.Fatalf("the audit event carries the pre-redaction arguments: %s", ev.Input)
		}
		if !strings.Contains(string(ev.Input), "[REDACTED:private_email]") {
			t.Errorf("the event lost the arguments entirely; it should record the redacted form: %s", ev.Input)
		}
	})

	t.Run("clean call keeps its arguments", func(t *testing.T) {
		insp, events := newArgInspector(t, "deny", "fail_closed", &fakeChecker{})

		_, err := insp.Inspect(context.Background(), toolsCall("web_fetch", `{"url":"https://example.com"}`), DirectionRequest)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		ev := (*events)[0].(MCPToolCalledEvent)
		if !strings.Contains(string(ev.Input), "https://example.com") {
			t.Errorf("a clean call lost its arguments from the audit trail: %s", ev.Input)
		}
	})
}
