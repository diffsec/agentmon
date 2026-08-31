package api

import (
	"strings"

	"github.com/diffsec/agentmon/internal/mcpinspect"
	"github.com/diffsec/agentmon/pkg/types"
	"github.com/google/uuid"
)

// mcpInterceptedToEvent converts an MCPToolCallInterceptedEvent from the LLM
// proxy into a types.Event suitable for the event store and broker.
func mcpInterceptedToEvent(ev mcpinspect.MCPToolCallInterceptedEvent) types.Event {
	decision := types.DecisionAllow
	if ev.Action == "block" {
		decision = types.DecisionDeny
	}

	// Derive a rule identifier from the action. The proxy-level event doesn't
	// carry the matched config.MCPToolRule, so we synthesise a short label.
	rule := "mcp-" + ev.Action // "mcp-allow", "mcp-redact" or "mcp-block"
	// An mcp_inspect_rules match names a real rule, and that name is what an
	// operator reading the audit log needs to find the line they wrote.
	if ev.InspectRule != "" {
		rule = ev.InspectRule
	}

	e := types.Event{
		ID:        uuid.NewString(),
		Timestamp: ev.Timestamp,
		Type:      "mcp_tool_call_intercepted",
		SessionID: ev.SessionID,
		Source:    "llm_proxy",
		Path:      ev.ToolName,
		Domain:    ev.ServerID,
		EffectiveAction: ev.Action,
		Policy: &types.PolicyInfo{
			Decision:          decision,
			EffectiveDecision: decision,
			Rule:              rule,
			Message:           ev.Reason,
		},
		Fields: map[string]any{
			"request_id":  ev.RequestID,
			"dialect":     ev.Dialect,
			"tool_name":   ev.ToolName,
			"tool_call_id": ev.ToolCallID,
			"server_id":   ev.ServerID,
			"server_type": ev.ServerType,
			"server_addr": ev.ServerAddr,
			"tool_hash":   ev.ToolHash,
			"action":      ev.Action,
			"reason":      ev.Reason,
		},
	}

	// Content inspection details, when a rule matched. Absent otherwise, so
	// an event from a session with no inspect rules is byte-identical to
	// what it was before.
	if ev.InspectRule != "" {
		e.Fields["inspect_rule"] = ev.InspectRule
	}
	if ev.InspectDetail != "" {
		e.Fields["inspect_detail"] = ev.InspectDetail
	}
	if ev.InspectError != "" {
		e.Fields["inspect_error"] = ev.InspectError
	}
	return e
}

// mcpCrossServerToEvent converts an MCPCrossServerEvent into a types.Event
// suitable for the event store and broker.
func mcpCrossServerToEvent(ev mcpinspect.MCPCrossServerEvent) types.Event {
	// Convert related calls to a JSON-compatible slice of maps.
	relatedCalls := make([]map[string]any, len(ev.RelatedCalls))
	for i, rc := range ev.RelatedCalls {
		relatedCalls[i] = map[string]any{
			"timestamp":    rc.Timestamp,
			"server_id":    rc.ServerID,
			"tool_name":    rc.ToolName,
			"tool_call_id": rc.ToolCallID,
			"request_id":   rc.RequestID,
			"action":       rc.Action,
			"category":     rc.Category,
		}
	}

	return types.Event{
		ID:              uuid.NewString(),
		Timestamp:       ev.Timestamp,
		Type:            "mcp_cross_server_blocked",
		SessionID:       ev.SessionID,
		Source:          "llm_proxy",
		Path:            ev.BlockedToolName,
		Domain:          ev.BlockedServerID,
		EffectiveAction: "block",
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              crossServerPolicyRule(ev.Rule),
			Message:           ev.Reason,
		},
		Fields: map[string]any{
			"rule":              ev.Rule,
			"severity":          ev.Severity,
			"blocked_server_id": ev.BlockedServerID,
			"blocked_tool_name": ev.BlockedToolName,
			"reason":            ev.Reason,
			"related_calls":     relatedCalls,
		},
	}
}

// crossServerPolicyRule normalises a cross-server rule name for the Policy.Rule
// field. Rules that already start with "cross_server_" are returned as-is;
// others get the prefix added (e.g. "read_then_send" → "cross_server_read_then_send").
func crossServerPolicyRule(rule string) string {
	if strings.HasPrefix(rule, "cross_server_") {
		return rule
	}
	return "cross_server_" + rule
}
