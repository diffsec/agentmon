// internal/shim/mcp_wrapper_test.go
package shim

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestMCPWrapper_ForwardData(t *testing.T) {
	// Create a simple pipe to simulate stdin/stdout
	input := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	output := &bytes.Buffer{}

	var capturedMessages [][]byte
	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		capturedMessages = append(capturedMessages, append([]byte{}, data...))
		return nil, false // don't block
	}

	// Run wrapper (forwards input to output)
	err := ForwardWithInspection(input, output, MCPDirectionRequest, inspector, nil)
	if err != nil && err != io.EOF {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	// Verify data was forwarded
	if !bytes.Contains(output.Bytes(), []byte("tools/list")) {
		t.Error("expected output to contain forwarded data")
	}

	// Verify inspector was called
	if len(capturedMessages) == 0 {
		t.Error("expected inspector to be called")
	}
}

func TestMCPWrapper_DirectionTypes(t *testing.T) {
	if MCPDirectionRequest.String() != "request" {
		t.Errorf("MCPDirectionRequest.String() = %q, want request", MCPDirectionRequest.String())
	}
	if MCPDirectionResponse.String() != "response" {
		t.Errorf("MCPDirectionResponse.String() = %q, want response", MCPDirectionResponse.String())
	}
}

func TestMCPWrapper_BlockedMessageNotForwarded(t *testing.T) {
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed"}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"also_allowed"}}` + "\n",
	)
	output := &bytes.Buffer{}

	// Block the sampling request (id:2), allow everything else.
	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		return nil, bytes.Contains(data, []byte("sampling/createMessage"))
	}

	err := ForwardWithInspection(input, output, MCPDirectionRequest, inspector, nil)
	if err != nil && err != io.EOF {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	out := output.String()
	if !strings.Contains(out, `"id":1`) {
		t.Error("expected first message (id:1) to be forwarded")
	}
	if strings.Contains(out, `"sampling/createMessage"`) {
		t.Error("expected second message (sampling) to be blocked (not forwarded)")
	}
	if !strings.Contains(out, `"id":3`) {
		t.Error("expected third message (id:3) to be forwarded")
	}
}

func TestMCPWrapper_BlockedRequest_WritesErrorToReplyWriter(t *testing.T) {
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","id":42,"method":"sampling/createMessage","params":{}}` + "\n",
	)
	dst := &bytes.Buffer{}
	replyWriter := &bytes.Buffer{}

	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		return nil, true // block everything
	}

	err := ForwardWithInspection(input, dst, MCPDirectionRequest, inspector, replyWriter)
	if err != nil {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	// The original message must not be forwarded to dst (server stdin).
	if dst.Len() > 0 {
		t.Error("blocked request should not be forwarded to dst")
	}

	// A JSON-RPC error should appear on the replyWriter (client stdout).
	reply := replyWriter.String()
	if !strings.Contains(reply, `"error"`) {
		t.Fatalf("expected JSON-RPC error in replyWriter, got: %s", reply)
	}

	var errResp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(reply)), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if string(errResp.ID) != "42" {
		t.Errorf("error response id = %s, want 42", errResp.ID)
	}
	if errResp.Error.Code != -32600 {
		t.Errorf("error code = %d, want -32600", errResp.Error.Code)
	}
	if !strings.Contains(errResp.Error.Message, "blocked") {
		t.Errorf("error message = %q, want to contain 'blocked'", errResp.Error.Message)
	}
}

func TestMCPWrapper_BlockedResponse_WritesErrorToDst(t *testing.T) {
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"evil"}]}}` + "\n",
	)
	dst := &bytes.Buffer{}

	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		return nil, true // block everything
	}

	err := ForwardWithInspection(input, dst, MCPDirectionResponse, inspector, nil)
	if err != nil {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	// For response direction, the error should be written to dst.
	out := dst.String()
	if !strings.Contains(out, `"error"`) {
		t.Fatalf("expected JSON-RPC error in dst for blocked response, got: %s", out)
	}
	if !strings.Contains(out, `"id":7`) {
		t.Error("error response should contain the original message id")
	}
}

func TestMCPWrapper_BlockedNotification_NoError(t *testing.T) {
	// Notifications have no "id" field — blocking them should not produce an error.
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` + "\n",
	)
	dst := &bytes.Buffer{}
	replyWriter := &bytes.Buffer{}

	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		return nil, true // block
	}

	err := ForwardWithInspection(input, dst, MCPDirectionRequest, inspector, replyWriter)
	if err != nil {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	if dst.Len() > 0 {
		t.Error("blocked notification should not produce output on dst")
	}
	if replyWriter.Len() > 0 {
		t.Error("blocked notification should not produce output on replyWriter")
	}
}

func TestExtractJSONRPCID(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantID string
		wantOK bool
	}{
		{"numeric id", `{"jsonrpc":"2.0","id":42,"method":"foo"}`, "42", true},
		{"string id", `{"jsonrpc":"2.0","id":"abc","method":"foo"}`, `"abc"`, true},
		{"null id", `{"jsonrpc":"2.0","id":null,"method":"foo"}`, "", false},
		{"no id", `{"jsonrpc":"2.0","method":"foo"}`, "", false},
		{"invalid json", `not json`, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := extractJSONRPCID([]byte(tt.input))
			if tt.wantOK {
				if id == nil {
					t.Fatal("expected non-nil id")
				}
				if string(id) != tt.wantID {
					t.Errorf("id = %s, want %s", id, tt.wantID)
				}
			} else {
				if id != nil {
					t.Errorf("expected nil id, got %s", id)
				}
			}
		})
	}
}

// TestMCPWrapper_RewrittenMessageIsForwarded. Content inspection redacts a
// tool argument by handing back a replacement message. If the wrapper
// forwarded the original anyway, on_violation: redact would report a
// redaction that never reached the server.
func TestMCPWrapper_RewrittenMessageIsForwarded(t *testing.T) {
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_fetch","arguments":{"to":"alice@example.com"}}}` + "\n",
	)
	dst := &bytes.Buffer{}

	replacement := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_fetch","arguments":{"to":"[REDACTED]"}}}`)
	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		return replacement, false
	}

	if err := ForwardWithInspection(input, dst, MCPDirectionRequest, inspector, nil); err != nil {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	out := dst.String()
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("the original message was forwarded, not the rewrite: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("the rewrite was not forwarded: %s", out)
	}
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		t.Errorf("framing broken: %q", out)
	}
}

// TestMCPWrapper_BlockBeatsRewrite. An inspector that both rewrites and
// blocks must block: forwarding the rewrite would let a denied call through
// in redacted form.
func TestMCPWrapper_BlockBeatsRewrite(t *testing.T) {
	input := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}` + "\n")
	dst := &bytes.Buffer{}
	replyWriter := &bytes.Buffer{}

	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":1}}`), true
	}

	if err := ForwardWithInspection(input, dst, MCPDirectionRequest, inspector, replyWriter); err != nil {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}
	if dst.Len() > 0 {
		t.Errorf("a blocked message was forwarded: %s", dst.String())
	}
	if !strings.Contains(replyWriter.String(), `"error"`) {
		t.Errorf("no JSON-RPC error was sent to the client: %s", replyWriter.String())
	}
}

// TestMCPWrapper_RewriteWithNewlineBlocks. Framing here is one JSON-RPC
// message per line, so a rewrite carrying a newline would split one message
// into two. Falling back to the original instead would forward exactly the
// content a rule asked to have redacted.
func TestMCPWrapper_RewriteWithNewlineBlocks(t *testing.T) {
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"to":"alice@example.com"}}}` + "\n",
	)
	dst := &bytes.Buffer{}
	replyWriter := &bytes.Buffer{}

	inspector := func(data []byte, dir MCPDirection) ([]byte, bool) {
		return []byte("{\"jsonrpc\":\"2.0\",\n\"id\":1}"), false
	}

	if err := ForwardWithInspection(input, dst, MCPDirectionRequest, inspector, replyWriter); err != nil {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}
	if dst.Len() > 0 {
		t.Errorf("a newline-bearing rewrite was forwarded: %q", dst.String())
	}
	if strings.Contains(replyWriter.String(), "alice@example.com") {
		t.Error("the original content leaked into the reply")
	}
	if !strings.Contains(replyWriter.String(), `"error"`) {
		t.Errorf("no JSON-RPC error was sent: %s", replyWriter.String())
	}
}
