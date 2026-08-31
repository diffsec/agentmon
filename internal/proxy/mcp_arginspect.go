package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/pkg/types"
)

// DefaultMCPArgMaxBytes caps how much of a streamed tool argument is
// accumulated before inspection.
//
// On the streaming paths the arguments arrive as fragments and must be held
// until complete, so an unbounded accumulator is a memory surface the model
// on the other end controls. Exceeding the cap is a failed inspection, not a
// skip: arguments too large to inspect are uninspected arguments, and the
// rule's on_failure decides -- a deny by default.
//
// 1 MiB because a tool argument is a function call's parameters, not a
// payload. Real ones run to kilobytes; anything near this is already
// anomalous.
const DefaultMCPArgMaxBytes = 1 << 20

// mcpArgInspector runs the policy's mcp_inspect_rules over MCP tool-call
// arguments extracted from a model response.
//
// The tool call the model emits is where an agent puts a credential or a
// customer record into an argument, and it is the last point before the agent
// sends it to an MCP server the daemon does not proxy.
type mcpArgInspector struct {
	// resolve supplies the engine and inspector per call, so a live policy
	// swap is observed. See InspectContextFunc.
	resolve InspectContextFunc
	logger  *slog.Logger
	// maxArgs bounds accumulated streamed arguments. Zero uses
	// DefaultMCPArgMaxBytes.
	maxArgs int
}

func newMCPArgInspector(resolve InspectContextFunc, maxArgs int, logger *slog.Logger) *mcpArgInspector {
	if resolve == nil {
		return nil
	}
	if maxArgs <= 0 {
		maxArgs = DefaultMCPArgMaxBytes
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &mcpArgInspector{resolve: resolve, maxArgs: maxArgs, logger: logger}
}

// limit returns the accumulation cap.
func (a *mcpArgInspector) limit() int {
	if a == nil {
		return DefaultMCPArgMaxBytes
	}
	return a.maxArgs
}

// matches reports whether any mcp_inspect_rule selects this tool call.
//
// The streaming paths ask before deciding whether to hold a tool_use block
// back until its arguments are complete. Holding back every tool call would
// add the model's own latency to calls no rule names, so this has to be
// cheap: it is a glob match over the compiled rules and touches no provider.
func (a *mcpArgInspector) matches(serverID, toolName string) bool {
	if a == nil || a.resolve == nil {
		return false
	}
	eng, _ := a.resolve()
	if eng == nil {
		return false
	}
	return eng.CheckMCPTool(serverID, toolName).Inspect != nil
}

// argVerdict is what inspection decided about one tool call's arguments.
type argVerdict struct {
	// Block is true when the call must not reach the agent.
	Block bool
	// Reason explains a block. It names the rule and the categories found,
	// never the matched text.
	Reason string
	// Redacted is the rewritten arguments, non-nil only when the resolved
	// action was redact and the rewrite is valid JSON.
	Redacted json.RawMessage
	// Rule, Detail and Err go on the audit event.
	Rule   string
	Detail string
	Err    error
	// Inspected is false when no rule matched, which is the difference
	// between "checked and clean" and "not checked".
	Inspected bool
}

// decide runs inspection over one tool call's arguments.
//
// args is the raw JSON of the tool's input. A nil or empty args resolves
// clean rather than through on_failure: there is no content, so the rule was
// satisfied vacuously, and routing it to on_failure would deny every
// zero-argument call under a fail_closed rule.
//
// oversize reports that the caller stopped accumulating at the cap. It is
// routed through on_failure, because a prefix of the arguments inspected
// clean says nothing about the rest.
func (a *mcpArgInspector) decide(ctx context.Context, serverID, toolName string, args json.RawMessage, oversize bool) argVerdict {
	if a == nil || a.resolve == nil {
		return argVerdict{}
	}
	eng, checker := a.resolve()
	if eng == nil {
		return argVerdict{}
	}

	dec := eng.CheckMCPTool(serverID, toolName)
	if dec.Inspect == nil {
		return argVerdict{}
	}

	var res inspect.Result
	switch {
	case oversize:
		res = inspect.Fail(dec, string(args),
			fmt.Errorf("tool arguments exceed the %d byte inspection limit", a.limit()))
	case len(args) == 0:
		res = inspect.Result{Decision: dec}
		res.Decision.EffectiveDecision = types.DecisionAllow
		if dec.Inspect.CleanDecision != "" {
			res.Decision.EffectiveDecision = dec.Inspect.CleanDecision
		}
	default:
		// PlaceholderRedactor, deliberately, where the request-body hook
		// uses a reversible token. A token survives the round trip only
		// because the response comes back through this proxy and
		// DetokenizeReader restores it. A redacted tool argument does not
		// come back: the agent sends it to an MCP server the daemon does
		// not sit in front of, so a token would arrive there as a TOK_<hex>
		// string nothing can resolve. The value has to actually be gone.
		res = inspect.Resolve(ctx, checker, dec, inspect.KindMCPArgs, string(args))
	}

	v := argVerdict{
		Inspected: true,
		Rule:      res.Decision.Rule,
		Detail:    res.Verdict.Detail,
		Err:       res.Err,
	}

	switch res.Decision.EffectiveDecision {
	case types.DecisionAllow:
		if !res.Rewritten {
			return v
		}
		if !json.Valid([]byte(res.Content)) {
			// Redaction rewrites the arguments as raw JSON text, so a span
			// labelled across a structural character can leave something
			// that no longer parses. Handing that to the agent would
			// produce a tool call the server rejects as the agent's fault;
			// keeping the original would pass exactly what the rule
			// flagged.
			v.Block = true
			v.Reason = fmt.Sprintf("tool %q blocked by content inspection: redaction did not produce valid JSON arguments", toolName)
			return v
		}
		v.Redacted = json.RawMessage(res.Content)
		return v

	case types.DecisionApprove:
		// Nothing on this path can ask a human: the proxy is mid-response,
		// streaming to an agent that is waiting. Denying with an explicit
		// reason beats downgrading to allow. The blocking shape exists at
		// internal/db/proxy/postgres/approvalwait.go and is the follow-up.
		v.Block = true
		v.Reason = fmt.Sprintf("tool %q blocked by content inspection: this rule requires approval, which the proxy path cannot request", toolName)
		return v

	default:
		v.Block = true
		v.Reason = argBlockReason(toolName, res)
		return v
	}
}

// argBlockReason names the rule and what was found, never the matched text.
// It is written into the response the agent reads, which is one of the places
// the content was being kept out of.
func argBlockReason(toolName string, res inspect.Result) string {
	msg := fmt.Sprintf("tool %q blocked by content inspection", toolName)
	if res.Decision.Rule != "" {
		msg += " (rule " + res.Decision.Rule + ")"
	}
	switch {
	case res.Err != nil:
		msg += ": inspection could not run"
	case res.Verdict.Detail != "":
		msg += ": " + res.Verdict.Detail
	}
	return msg
}

// accumulator collects a streamed tool argument, stopping at the cap.
//
// It records that it stopped rather than silently truncating: a truncated
// argument that inspects clean would report the whole call clean, which is
// the failure mode this type exists to prevent.
type accumulator struct {
	buf      []byte
	limit    int
	overflow bool
}

func newAccumulator(limit int) *accumulator {
	if limit <= 0 {
		limit = DefaultMCPArgMaxBytes
	}
	return &accumulator{limit: limit}
}

func (a *accumulator) add(s string) {
	if a.overflow {
		return
	}
	if len(a.buf)+len(s) > a.limit {
		a.overflow = true
		return
	}
	a.buf = append(a.buf, s...)
}

func (a *accumulator) bytes() json.RawMessage {
	if a.overflow || len(a.buf) == 0 {
		return nil
	}
	return json.RawMessage(a.buf)
}
