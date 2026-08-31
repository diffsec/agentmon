// internal/shim/mcp_wrapper.go
package shim

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// MCPDirection indicates whether a message is a request or response.
type MCPDirection int

const (
	MCPDirectionRequest MCPDirection = iota
	MCPDirectionResponse
)

// String returns the string representation of MCPDirection.
func (d MCPDirection) String() string {
	switch d {
	case MCPDirectionRequest:
		return "request"
	case MCPDirectionResponse:
		return "response"
	default:
		return "unknown"
	}
}

// MCPInspector is called for each message passing through the wrapper.
//
// It returns the message to forward and whether to block. A nil rewrite
// forwards the original bytes; a non-nil one replaces them, which is how
// content inspection redacts a tool argument in flight. block takes
// precedence: a blocked message is never forwarded, rewritten or not.
type MCPInspector func(data []byte, dir MCPDirection) (rewritten []byte, block bool)

// ForwardWithInspection copies data from src to dst while calling inspector
// for each line (JSON-RPC message). If the inspector blocks, a JSON-RPC error
// response is written so the caller does not hang waiting for a reply that
// never arrives. For blocked requests, the error is sent to replyWriter (the
// client); for blocked responses, it replaces the original in dst. If
// replyWriter is nil, blocked requests are dropped silently. Returns when src
// is exhausted.
func ForwardWithInspection(src io.Reader, dst io.Writer, dir MCPDirection, inspector MCPInspector, replyWriter io.Writer) error {
	scanner := bufio.NewScanner(src)
	// Increase buffer size for large messages
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Inspect and check if blocked
		if inspector != nil && len(line) > 0 {
			rewritten, block := inspector(line, dir)
			if block {
				writeBlockError(line, dir, dst, replyWriter)
				continue
			}
			if rewritten != nil {
				// The framing here is one JSON-RPC message per line, so a
				// rewrite carrying a newline would split one message into
				// two. json.Marshal escapes newlines inside strings and
				// emits none between tokens, so this is unreachable through
				// the redaction path -- and if some other rewrite ever
				// reaches it, blocking is the only safe answer. Falling back
				// to the original would forward exactly the content a rule
				// asked to have redacted.
				if bytes.ContainsAny(rewritten, "\n\r") {
					writeBlockError(line, dir, dst, replyWriter)
					continue
				}
				line = rewritten
			}
		}

		// Forward as a single write to prevent interleaved framing when dst
		// is shared between goroutines (e.g. syncWriter on os.Stdout).
		// Copy line to avoid mutating the scanner's internal buffer.
		frame := make([]byte, len(line)+1)
		copy(frame, line)
		frame[len(line)] = '\n'
		if _, err := dst.Write(frame); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// writeBlockError synthesizes a JSON-RPC error response for a blocked message.
// For request direction, the error is sent to replyWriter (the client).
// For response direction, the error replaces the blocked message in dst.
func writeBlockError(blockedMsg []byte, dir MCPDirection, dst, replyWriter io.Writer) {
	id := extractJSONRPCID(blockedMsg)
	if id == nil {
		return // notification or unparseable — no response needed
	}

	target := dst
	if dir == MCPDirectionRequest {
		if replyWriter == nil {
			return
		}
		target = replyWriter
	}

	errResp := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":-32600,\"message\":\"blocked by security policy\"}}\n", string(id))
	target.Write([]byte(errResp)) //nolint:errcheck
}

// extractJSONRPCID extracts the "id" field from a JSON-RPC message.
// Returns the raw JSON value, or nil if no id is present (e.g. notifications).
func extractJSONRPCID(data []byte) json.RawMessage {
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}
	if len(msg.ID) == 0 || string(msg.ID) == "null" {
		return nil
	}
	return msg.ID
}
