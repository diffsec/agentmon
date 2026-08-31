// internal/shim/mcp_bridge.go
package shim

import (
	"context"

	"github.com/diffsec/agentmon/internal/mcpinspect"
)

// MCPBridge connects the shim's stdio wrapper to the mcpinspect package.
type MCPBridge struct {
	inspector *mcpinspect.Inspector
}

// NewMCPBridge creates a bridge without pattern detection (backward compatible).
func NewMCPBridge(sessionID, serverID string, emitter func(interface{})) *MCPBridge {
	return &MCPBridge{
		inspector: mcpinspect.NewInspector(sessionID, serverID, emitter),
	}
}

// NewMCPBridgeWithDetection creates a bridge with pattern detection enabled.
func NewMCPBridgeWithDetection(sessionID, serverID string, emitter func(interface{})) *MCPBridge {
	return &MCPBridge{
		inspector: mcpinspect.NewInspectorWithDetection(sessionID, serverID, emitter),
	}
}

// Inspect processes an MCP message and emits relevant events.
//
// It returns the message to forward in place of the original (nil to forward
// it unchanged) and whether to block it.
//
// ctx bounds content inspection of tools/call arguments. The wrapper has no
// deadline of its own -- it copies until the stream ends -- so this is
// context.Background() and the bound that matters is the rule's own
// inspect.timeout, applied inside inspect.Resolve.
func (b *MCPBridge) Inspect(data []byte, dir MCPDirection) (rewritten []byte, block bool) {
	mcpDir := mcpinspect.DirectionRequest
	if dir == MCPDirectionResponse {
		mcpDir = mcpinspect.DirectionResponse
	}

	result, _ := b.inspector.Inspect(context.Background(), data, mcpDir)
	if result == nil {
		return nil, false
	}
	if result.Action == "block" {
		return nil, true
	}
	return result.Rewritten, false
}

// Inspector exposes the underlying MCP inspector so a caller can install
// argument inspection with SetArgInspection.
func (b *MCPBridge) Inspector() *mcpinspect.Inspector { return b.inspector }

// InspectorFunc returns a function suitable for ForwardWithInspection.
func (b *MCPBridge) InspectorFunc() MCPInspector {
	return func(data []byte, dir MCPDirection) ([]byte, bool) {
		return b.Inspect(data, dir)
	}
}
