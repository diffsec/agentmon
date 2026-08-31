package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/mcpinspect"
	"github.com/diffsec/agentmon/internal/mcpregistry"
	"github.com/diffsec/agentmon/internal/policy"
)

// anthropicArgSSE builds a stream whose tool_use arguments arrive as several
// input_json_delta fragments, which is the shape that makes argument
// inspection hard: the decision point every other MCP control uses is
// content_block_start, where the arguments do not exist yet.
func anthropicArgSSE(toolName, toolID string, fragments ...string) string {
	var b strings.Builder
	b.WriteString("event: message_start\n")
	b.WriteString(`data: {"type":"message_start","message":{"id":"msg_1"}}`)
	b.WriteString("\n\n")

	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
	b.WriteString("\n\n")
	b.WriteString("event: content_block_delta\n")
	b.WriteString(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Looking that up."}}`)
	b.WriteString("\n\n")
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":0}`)
	b.WriteString("\n\n")

	b.WriteString("event: content_block_start\n")
	b.WriteString(`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"` + toolID + `","name":"` + toolName + `","input":{}}}`)
	b.WriteString("\n\n")
	for _, f := range fragments {
		enc, _ := json.Marshal(f)
		b.WriteString("event: content_block_delta\n")
		b.WriteString(`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":` + string(enc) + `}}`)
		b.WriteString("\n\n")
	}
	b.WriteString("event: content_block_stop\n")
	b.WriteString(`data: {"type":"content_block_stop","index":1}`)
	b.WriteString("\n\n")

	b.WriteString("event: message_delta\n")
	b.WriteString(`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":25}}`)
	b.WriteString("\n\n")
	b.WriteString("event: message_stop\n")
	b.WriteString(`data: {"type":"message_stop"}`)
	b.WriteString("\n\n")
	return b.String()
}

func runArgSSE(t *testing.T, dialect Dialect, input string, a *mcpArgInspector) (string, []mcpinspect.MCPToolCallInterceptedEvent) {
	t.Helper()
	reg := mcpregistry.NewRegistry()
	reg.Register("my-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "abc123"},
		{Name: "send_email", Hash: "def456"},
	})

	var events []mcpinspect.MCPToolCallInterceptedEvent
	onEvent := func(ev mcpinspect.MCPToolCallInterceptedEvent) { events = append(events, ev) }

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	interceptor := NewSSEInterceptor(reg, nil, dialect, "sess_1", "req_1", onEvent, logger, nil, nil, nil, a)

	var clientBuf bytes.Buffer
	interceptor.Stream(context.Background(), strings.NewReader(input), &clientBuf)
	return clientBuf.String(), events
}

// TestSSEArgs_AnthropicCleanCallIsReplayedIntact is the property everything
// else rests on: a held tool call that inspects clean must reach the client
// exactly as it arrived. Hold-back that mangles the common case is worse than
// no inspection at all.
func TestSSEArgs_AnthropicCleanCallIsReplayedIntact(t *testing.T) {
	checker := &argChecker{}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	input := anthropicArgSSE("get_weather", "toolu_01", `{"city":`, `"NYC"}`)
	out, events := runArgSSE(t, DialectAnthropic, input, a)

	if checker.gotBody != `{"city":"NYC"}` {
		t.Fatalf("inspected content = %q, want the reassembled arguments", checker.gotBody)
	}
	for _, want := range []string{
		`"type":"tool_use"`,
		`"toolu_01"`,
		`"get_weather"`,
		`{\"city\":`,
		`\"NYC\"}`,
		`"type":"content_block_stop","index":1`,
		`"stop_reason":"tool_use"`,
		"Looking that up.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("client output is missing %s\n---\n%s", want, out)
		}
	}
	// Both fragments must survive as separate deltas: replacing them with a
	// single delta would work for a client that concatenates, and break one
	// that counts events.
	if got := strings.Count(out, "input_json_delta"); got != 2 {
		t.Errorf("input_json_delta events = %d, want the original 2\n---\n%s", got, out)
	}
	if len(events) != 1 || events[0].Action != "allow" {
		t.Fatalf("events = %+v, want a single allow", events)
	}
	if events[0].InspectRule != "inspect-weather-args" {
		t.Errorf("event inspect_rule = %q", events[0].InspectRule)
	}
}

// TestSSEArgs_AnthropicUnmatchedToolIsNotHeld. A tool no rule names must
// stream straight through. Holding it would add the model's own latency to
// every tool call in the session.
func TestSSEArgs_AnthropicUnmatchedToolIsNotHeld(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{Violation: true, Detail: "1 finding"}}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	input := anthropicArgSSE("send_email", "toolu_02", `{"to":"a@b.c"}`)
	out, _ := runArgSSE(t, DialectAnthropic, input, a)

	if checker.calls != 0 {
		t.Errorf("checker was called %d times for a tool no rule names, want 0", checker.calls)
	}
	if !strings.Contains(out, `"send_email"`) {
		t.Errorf("the tool call did not reach the client\n---\n%s", out)
	}
}

// TestSSEArgs_AnthropicViolationBlocks. The tool_use block must not reach the
// client, and stop_reason must become end_turn so the agent stops waiting for
// a tool result that will never come.
func TestSSEArgs_AnthropicViolationBlocks(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
	}}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	input := anthropicArgSSE("get_weather", "toolu_01", `{"to":"alice@`, `example.com"}`)
	out, events := runArgSSE(t, DialectAnthropic, input, a)

	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the flagged arguments reached the client\n---\n%s", out)
	}
	if strings.Contains(out, `"type":"tool_use"`) {
		t.Errorf("the blocked tool_use block reached the client\n---\n%s", out)
	}
	if !strings.Contains(out, "blocked by policy") {
		t.Errorf("no replacement text block\n---\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Errorf("stop_reason was not rewritten, so the agent waits for a tool result\n---\n%s", out)
	}
	if len(events) != 1 || events[0].Action != "block" {
		t.Fatalf("events = %+v, want a single block", events)
	}
	if strings.Contains(string(events[0].Input), "alice@example.com") {
		t.Errorf("the audit event carries the flagged arguments: %s", events[0].Input)
	}
	if strings.Contains(events[0].Reason, "alice@example.com") {
		t.Errorf("the reason leaks the matched text: %q", events[0].Reason)
	}
}

// TestSSEArgs_AnthropicRedactRewritesTheCall. The call still runs, without
// the value.
func TestSSEArgs_AnthropicRedactRewritesTheCall(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}}
	a := newArgInspectorFor(t, "redact", "fail_closed", checker)

	input := anthropicArgSSE("get_weather", "toolu_01", `{"to":"alice@`, `example.com"}`)
	out, events := runArgSSE(t, DialectAnthropic, input, a)

	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the matched text reached the client\n---\n%s", out)
	}
	if !strings.Contains(out, `REDACTED:private_email`) {
		t.Fatalf("the redacted value did not reach the client\n---\n%s", out)
	}
	if !strings.Contains(out, `"type":"tool_use"`) || !strings.Contains(out, `"toolu_01"`) {
		t.Errorf("the tool call itself was dropped instead of redacted\n---\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Errorf("stop_reason changed on a call that was not blocked\n---\n%s", out)
	}
	// Reassembling the emitted partial_json fragments must give back exactly
	// the redacted arguments -- a client concatenates them and parses the
	// result.
	if got := reassemblePartialJSON(out); got != `{"to":"[REDACTED:private_email]"}` {
		t.Errorf("reassembled arguments = %q, want the redacted object", got)
	}
	if len(events) != 1 || events[0].Action != "redact" {
		t.Fatalf("events = %+v, want a single redact", events)
	}
	if strings.Contains(string(events[0].Input), "alice@example.com") {
		t.Errorf("the audit event carries the pre-redaction arguments: %s", events[0].Input)
	}
}

// TestSSEArgs_AnthropicFailureRoutesThroughOnFailure. A provider that errors
// means the arguments were not inspected, and the rule decides.
func TestSSEArgs_AnthropicFailureRoutesThroughOnFailure(t *testing.T) {
	for _, c := range []struct {
		onFailure string
		wantBlock bool
	}{{"fail_closed", true}, {"fail_open", false}} {
		t.Run(c.onFailure, func(t *testing.T) {
			checker := &argChecker{err: errArgProvider}
			a := newArgInspectorFor(t, "deny", c.onFailure, checker)

			input := anthropicArgSSE("get_weather", "toolu_01", `{"city":"NYC"}`)
			out, events := runArgSSE(t, DialectAnthropic, input, a)

			blocked := !strings.Contains(out, `"type":"tool_use"`)
			if blocked != c.wantBlock {
				t.Fatalf("on_failure %s: blocked = %v, want %v\n---\n%s", c.onFailure, blocked, c.wantBlock, out)
			}
			if len(events) != 1 {
				t.Fatalf("events = %+v, want 1", events)
			}
			if events[0].InspectError == "" {
				t.Error("the event records no inspection error; an operator cannot tell a failed inspection from a clean one")
			}
		})
	}
}

// TestSSEArgs_AnthropicTruncatedStreamBlocks. A stream that ends before
// content_block_stop leaves arguments that were never complete and therefore
// never inspected. Releasing them would forward exactly the content a rule
// asked to have checked.
func TestSSEArgs_AnthropicTruncatedStreamBlocks(t *testing.T) {
	checker := &argChecker{}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	// Everything up to and including the first argument fragment, then EOF.
	full := anthropicArgSSE("get_weather", "toolu_01", `{"to":"alice@example.com"}`)
	cut := strings.Index(full, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}")
	if cut < 0 {
		t.Fatal("test fixture changed shape")
	}
	out, events := runArgSSE(t, DialectAnthropic, full[:cut], a)

	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("an uninspected tool call reached the client\n---\n%s", out)
	}
	if !strings.Contains(out, "blocked by policy") {
		t.Errorf("no replacement block for the truncated tool call\n---\n%s", out)
	}
	if len(events) != 1 || events[0].Action != "block" {
		t.Fatalf("events = %+v, want a single block", events)
	}
	if checker.calls != 0 {
		t.Errorf("checker was called %d times on incomplete arguments, want 0", checker.calls)
	}
}

// openAIArgSSE builds an OpenAI stream whose tool call arguments arrive as
// fragments after the first chunk.
//
// The first chunk carries the opening argument fragment, which is what the
// real API sends: dropping it loses the leading brace and every later
// reassembly is invalid JSON.
func openAIArgSSE(toolName, toolID string, fragments ...string) string {
	var b strings.Builder
	b.WriteString(`data: {"id":"chatcmpl_1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`)
	b.WriteString("\n\n")

	first := ""
	if len(fragments) > 0 {
		first, fragments = fragments[0], fragments[1:]
	}
	firstEnc, _ := json.Marshal(first)
	b.WriteString(`data: {"id":"chatcmpl_1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"` + toolID + `","type":"function","function":{"name":"` + toolName + `","arguments":` + string(firstEnc) + `}}]}}]}`)
	b.WriteString("\n\n")
	for _, f := range fragments {
		enc, _ := json.Marshal(f)
		b.WriteString(`data: {"id":"chatcmpl_1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":` + string(enc) + `}}]}}]}`)
		b.WriteString("\n\n")
	}
	b.WriteString(`data: {"id":"chatcmpl_1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)
	b.WriteString("\n\n")
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

// TestSSEArgs_OpenAICleanCallIsReleased. The OpenAI dialect has to reach the
// same outcome as the Anthropic one. A control that covers one dialect and
// not the other is a bypass: the agent picks the dialect.
func TestSSEArgs_OpenAICleanCallIsReleased(t *testing.T) {
	checker := &argChecker{}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	input := openAIArgSSE("get_weather", "call_1", `{"city":`, `"NYC"}`)
	out, events := runArgSSE(t, DialectOpenAI, input, a)

	if checker.gotBody != `{"city":"NYC"}` {
		t.Fatalf("inspected content = %q, want the reassembled arguments", checker.gotBody)
	}
	if got := openAIToolArguments(t, out); got != `{"city":"NYC"}` {
		t.Errorf("released arguments = %q, want the originals\n---\n%s", got, out)
	}
	if !strings.Contains(out, `"finish_reason":"tool_calls"`) {
		t.Errorf("finish_reason changed on a call that was not blocked\n---\n%s", out)
	}
	// The release must precede the finish chunk, or the agent sees
	// finish_reason: tool_calls with no tool call to act on.
	if idx, fin := strings.Index(out, `"call_1"`), strings.Index(out, `"finish_reason"`); idx < 0 || idx > fin {
		t.Errorf("the released tool call is not before the finish chunk\n---\n%s", out)
	}
	if len(events) != 1 || events[0].Action != "allow" {
		t.Fatalf("events = %+v, want a single allow", events)
	}
}

// TestSSEArgs_OpenAIRedactRewritesTheCall.
func TestSSEArgs_OpenAIRedactRewritesTheCall(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
		Redacted: `{"to":"[REDACTED:private_email]"}`,
	}}
	a := newArgInspectorFor(t, "redact", "fail_closed", checker)

	input := openAIArgSSE("get_weather", "call_1", `{"to":"alice@`, `example.com"}`)
	out, events := runArgSSE(t, DialectOpenAI, input, a)

	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the matched text reached the client\n---\n%s", out)
	}
	if got := openAIToolArguments(t, out); got != `{"to":"[REDACTED:private_email]"}` {
		t.Errorf("released arguments = %q, want the redacted object\n---\n%s", got, out)
	}
	if len(events) != 1 || events[0].Action != "redact" {
		t.Fatalf("events = %+v, want a single redact", events)
	}
}

// TestSSEArgs_OpenAIViolationBlocks. Nothing survived, so finish_reason must
// become "stop".
func TestSSEArgs_OpenAIViolationBlocks(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "pii", Detail: "1 finding: private_email",
	}}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	input := openAIArgSSE("get_weather", "call_1", `{"to":"alice@example.com"}`)
	out, events := runArgSSE(t, DialectOpenAI, input, a)

	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the flagged arguments reached the client\n---\n%s", out)
	}
	if strings.Contains(out, `"call_1"`) {
		t.Errorf("the blocked tool call reached the client\n---\n%s", out)
	}
	if !strings.Contains(out, "blocked by content inspection") {
		t.Errorf("no notice for the blocked call\n---\n%s", out)
	}
	if !strings.Contains(out, `"finish_reason":"stop"`) {
		t.Errorf("finish_reason was not rewritten, so the agent waits for a tool result\n---\n%s", out)
	}
	// The notice has to arrive before the chunk that closes the response.
	// After it, the agent has already finished the turn and never renders it.
	if n, f := strings.Index(out, "blocked by content inspection"), strings.Index(out, `"finish_reason"`); n < 0 || n > f {
		t.Errorf("the blocked-call notice is not before the finish chunk\n---\n%s", out)
	}
	if len(events) != 1 || events[0].Action != "block" {
		t.Fatalf("events = %+v, want a single block", events)
	}
}

// TestSSEArgs_OpenAITruncatedStreamBlocks.
func TestSSEArgs_OpenAITruncatedStreamBlocks(t *testing.T) {
	a := newArgInspectorFor(t, "deny", "fail_closed", &argChecker{})

	full := openAIArgSSE("get_weather", "call_1", `{"to":"alice@example.com"}`)
	cut := strings.Index(full, `"finish_reason":"tool_calls"`)
	if cut < 0 {
		t.Fatal("test fixture changed shape")
	}
	// Trim back to the start of the finish chunk's line.
	cut = strings.LastIndex(full[:cut], "data: ")
	out, events := runArgSSE(t, DialectOpenAI, full[:cut], a)

	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("an uninspected tool call reached the client\n---\n%s", out)
	}
	if len(events) != 1 || events[0].Action != "block" {
		t.Fatalf("events = %+v, want a single block", events)
	}
}

// TestSSEArgs_OpenAIUnmatchedToolIsNotHeld.
func TestSSEArgs_OpenAIUnmatchedToolIsNotHeld(t *testing.T) {
	checker := &argChecker{verdict: policy.InspectVerdict{Violation: true, Detail: "1 finding"}}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	input := openAIArgSSE("send_email", "call_2", `{"to":"a@b.c"}`)
	out, _ := runArgSSE(t, DialectOpenAI, input, a)

	if checker.calls != 0 {
		t.Errorf("checker was called %d times for a tool no rule names, want 0", checker.calls)
	}
	if !strings.Contains(out, `"send_email"`) {
		t.Errorf("the tool call did not reach the client\n---\n%s", out)
	}
}

// reassemblePartialJSON concatenates every input_json_delta fragment in an
// Anthropic SSE stream, the way a client does.
func reassemblePartialJSON(sse string) string {
	var b strings.Builder
	for _, line := range strings.Split(sse, "\n") {
		data, ok := extractSSEData(line)
		if !ok {
			continue
		}
		b.WriteString(extractInputJSONDelta(data))
	}
	return b.String()
}

// openAIToolArguments concatenates every tool_call argument fragment in an
// OpenAI SSE stream.
func openAIToolArguments(t *testing.T, sse string) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(sse, "\n") {
		data, ok := extractSSEData(line)
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk openAIChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, c := range chunk.Choices {
			for _, tc := range c.Delta.ToolCalls {
				b.WriteString(tc.Function.Arguments)
			}
		}
	}
	return b.String()
}

var errArgProvider = errArg("provider exploded")

type errArg string

func (e errArg) Error() string { return string(e) }

// TestSSEArgs_AnthropicTextDeltaIsNotAnArgument. A delta at a held index that
// is not an input_json_delta carries no arguments. Feeding it to the
// accumulator would splice model prose into the JSON, and the call would
// then fail inspection or fail to parse for reasons the agent never caused.
func TestSSEArgs_AnthropicTextDeltaIsNotAnArgument(t *testing.T) {
	checker := &argChecker{}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	// A stray text_delta arrives at the tool_use index, between the two
	// argument fragments.
	input := anthropicArgSSE("get_weather", "toolu_01", `{"city":`, `"NYC"}`)
	stray := "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"NONSENSE"}}` + "\n\n"
	marker := "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}"
	input = strings.Replace(input, marker, stray+marker, 1)

	out, _ := runArgSSE(t, DialectAnthropic, input, a)

	if checker.gotBody != `{"city":"NYC"}` {
		t.Fatalf("inspected content = %q; a text_delta was spliced into the arguments", checker.gotBody)
	}
	if !strings.Contains(out, "NONSENSE") {
		t.Errorf("the stray delta was dropped rather than replayed\n---\n%s", out)
	}
}

// TestReplaceBlockInput_RejectsWhatItCannotRewrite. The callers treat an
// error here as "block the call", so anything this accepts is something the
// agent receives.
func TestReplaceBlockInput_RejectsWhatItCannotRewrite(t *testing.T) {
	valid := json.RawMessage(`{"type":"tool_use","id":"toolu_1","name":"t","input":{"a":1}}`)

	if _, err := replaceBlockInput(valid, json.RawMessage(`{"a":`)); err == nil {
		t.Error("invalid redacted input was accepted")
	}
	if _, err := replaceBlockInput(json.RawMessage(`"not an object"`), json.RawMessage(`{"a":1}`)); err == nil {
		t.Error("a non-object block was accepted")
	}

	out, err := replaceBlockInput(valid, json.RawMessage(`{"a":"[REDACTED]"}`))
	if err != nil {
		t.Fatalf("a valid rewrite failed: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("the rewrite does not parse: %v", err)
	}
	if string(got["id"]) != `"toolu_1"` || string(got["name"]) != `"t"` {
		t.Errorf("the block's identity changed: %s", out)
	}
	if string(got["input"]) != `{"a":"[REDACTED]"}` {
		t.Errorf("input = %s, want the redacted object", got["input"])
	}
}

// TestReplaceToolCallArguments_EncodesAsAString. OpenAI's contract says
// function.arguments is a JSON string. Splicing the redacted object in raw
// would produce an object there, which clients parse differently or not at
// all.
func TestReplaceToolCallArguments_EncodesAsAString(t *testing.T) {
	valid := json.RawMessage(`{"id":"call_1","type":"function","function":{"name":"t","arguments":"{\"a\":1}"}}`)

	if _, err := replaceToolCallArguments(valid, json.RawMessage(`{"a":`)); err == nil {
		t.Error("invalid redacted arguments were accepted")
	}
	if _, err := replaceToolCallArguments(json.RawMessage(`{"id":"call_1"}`), json.RawMessage(`{"a":1}`)); err == nil {
		t.Error("a tool call with no function object was accepted")
	}

	out, err := replaceToolCallArguments(valid, json.RawMessage(`{"a":"[REDACTED]"}`))
	if err != nil {
		t.Fatalf("a valid rewrite failed: %v", err)
	}
	var got struct {
		ID       string `json:"id"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("arguments is not a JSON string: %v (%s)", err, out)
	}
	if got.ID != "call_1" || got.Function.Name != "t" {
		t.Errorf("the tool call's identity changed: %s", out)
	}
	if got.Function.Arguments != `{"a":"[REDACTED]"}` {
		t.Errorf("arguments = %q, want the redacted object encoded as a string", got.Function.Arguments)
	}
}

// TestInterceptionGatesIncludeArgumentInspection. Both gates decide whether
// the interception pipeline runs at all. A session whose policy uses
// mcp_inspect_rules but sets no MCP tool policy would otherwise take the
// pass-through path, and every inspect rule would be a no-op with nothing in
// the log to say so.
func TestInterceptionGatesIncludeArgumentInspection(t *testing.T) {
	a := newArgInspectorFor(t, "deny", "fail_closed", &argChecker{})

	t.Run("non-streaming", func(t *testing.T) {
		p := &Proxy{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if p.hasInterception() {
			t.Fatal("hasInterception() = true with no controls configured")
		}
		p.mcpArgs = a
		if !p.hasInterception() {
			t.Error("hasInterception() = false with argument inspection configured")
		}
	})

	t.Run("streaming", func(t *testing.T) {
		reg := mcpregistry.NewRegistry()
		tr := &sseProxyTransport{registry: reg}
		if tr.hasInterception() {
			t.Fatal("hasInterception() = true with no controls configured")
		}
		tr.mcpArgs = a
		if !tr.hasInterception() {
			t.Error("hasInterception() = false with argument inspection configured")
		}
	})
}

// TestSSEArgs_OpenAIMultipleHeldCallsKeepTheirOrder. Two tool calls in one
// response are released together, and the order the model chose is the order
// the agent executes them in. Ranging the held map would pick a different
// order on each run, so a two-step plan would sometimes run backwards.
func TestSSEArgs_OpenAIMultipleHeldCallsKeepTheirOrder(t *testing.T) {
	checker := &argChecker{}
	a := newArgInspectorFor(t, "deny", "fail_closed", checker)

	var b strings.Builder
	b.WriteString(`data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"}}]}`)
	b.WriteString("\n\n")
	b.WriteString(`data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[` +
		`{"index":0,"id":"call_first","type":"function","function":{"name":"get_weather","arguments":"{\"n\":1}"}},` +
		`{"index":1,"id":"call_second","type":"function","function":{"name":"get_weather","arguments":"{\"n\":2}"}}` +
		`]}}]}`)
	b.WriteString("\n\n")
	b.WriteString(`data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)
	b.WriteString("\n\ndata: [DONE]\n\n")

	// Run it repeatedly: a map-ordering bug shows up as a flake, not a
	// failure, so one pass proves nothing.
	for i := 0; i < 20; i++ {
		out, events := runArgSSE(t, DialectOpenAI, b.String(), a)
		first, second := strings.Index(out, "call_first"), strings.Index(out, "call_second")
		if first < 0 || second < 0 {
			t.Fatalf("a released tool call is missing\n---\n%s", out)
		}
		if first > second {
			t.Fatalf("the released tool calls came out reversed\n---\n%s", out)
		}
		if len(events) != 2 {
			t.Fatalf("events = %d, want 2", len(events))
		}
		if events[0].ToolCallID != "call_first" || events[1].ToolCallID != "call_second" {
			t.Fatalf("audit events came out of order: %s then %s", events[0].ToolCallID, events[1].ToolCallID)
		}
	}
}
