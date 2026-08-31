package mcpinspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/pkg/types"
)

// ArgInspection makes tools/call arguments subject to the policy's
// mcp_inspect_rules.
//
// Without one installed, handleToolsCall behaves exactly as it did before:
// the pattern detector annotates the event and nothing is ever blocked. That
// alert-only behaviour was deliberate, but it means an agent could put a
// credential or a customer record into a tool argument and the only trace was
// a log line after the fact.
type ArgInspection struct {
	// Resolve supplies the policy engine and its inspector for the current
	// call.
	//
	// It is a function rather than two stored pointers so the engine is
	// resolved per call. A captured engine keeps enforcing the policy that
	// was live when the inspector was built, which is the bug documented at
	// internal/api/session_policy.go:47 for the network, transparent-TCP
	// and DNS paths. This does not need to be a fourth instance of it.
	Resolve func() (*policy.Engine, policy.InspectChecker)

	// Redactor is the replacement strategy for on_violation: redact. Nil
	// uses inspect.PlaceholderRedactor, which retains nothing but also
	// destroys the value for the tool being called.
	Redactor inspect.Redactor
}

// SetArgInspection installs argument inspection. Pass nil to disable it.
func (i *Inspector) SetArgInspection(a *ArgInspection) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.argInspect = a
}

func (i *Inspector) argInspection() *ArgInspection {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.argInspect
}

// inspectToolArgs runs the policy's mcp_inspect_rules over one tool call's
// arguments and reports what should happen to the message.
//
// It returns a nil result when the call is to be forwarded unchanged, which
// covers both "no rule matched" and "inspection found nothing".
func (i *Inspector) inspectToolArgs(ctx context.Context, data []byte, req *ToolsCallRequest) (*InspectResult, *inspect.Result) {
	ai := i.argInspection()
	if ai == nil || ai.Resolve == nil {
		return nil, nil
	}
	eng, checker := ai.Resolve()
	if eng == nil {
		return nil, nil
	}

	dec := eng.CheckMCPTool(i.serverID, req.Params.Name)
	if dec.Inspect == nil {
		return nil, nil
	}

	var res inspect.Result
	if len(req.Params.Arguments) == 0 {
		// A tools/call with no arguments carries no content, so there is
		// nothing an inspector could look at. Resolving it clean is right:
		// the rule asked for the arguments to be inspected and they were,
		// vacuously. Routing it through on_failure instead would deny every
		// zero-argument call under a fail_closed rule.
		res = inspect.Result{Decision: dec, Verdict: policy.InspectVerdict{}}
		res.Decision.EffectiveDecision = cleanDecisionOf(dec)
	} else {
		res = inspect.Resolve(ctx, checker, dec, inspect.KindMCPArgs, string(req.Params.Arguments),
			inspect.WithRedactor(ai.Redactor))
	}

	switch res.Decision.EffectiveDecision {
	case types.DecisionAllow:
		if !res.Rewritten {
			return nil, &res
		}
		rewritten, err := replaceToolArguments(data, []byte(res.Content))
		if err != nil {
			// Redaction produced something that is no longer a valid
			// tools/call. Forwarding it would corrupt the call in a way the
			// server reports as the agent's fault, and forwarding the
			// original would send exactly the content the rule flagged.
			// Block, and say which it was.
			return &InspectResult{
				Action: "block",
				Reason: fmt.Sprintf("tool %q blocked by content inspection: redaction did not produce a valid request (%v)", req.Params.Name, err),
			}, &res
		}
		return &InspectResult{Action: "allow", Rewritten: rewritten}, &res

	case types.DecisionApprove:
		// There is no approver on this path: the wrapper forwards or
		// refuses one JSON-RPC line and has nobody to ask. Denying with an
		// explicit reason beats downgrading to allow, and beats a bare
		// block the operator would go looking for a deny rule to explain.
		// The blocking shape exists at
		// internal/db/proxy/postgres/approvalwait.go and is the follow-up.
		return &InspectResult{
			Action: "block",
			Reason: fmt.Sprintf("tool %q blocked by content inspection: this rule requires approval, which the MCP stdio path cannot request", req.Params.Name),
		}, &res

	default:
		return &InspectResult{
			Action: "block",
			Reason: argBlockReason(req.Params.Name, res),
		}, &res
	}
}

// cleanDecisionOf is what a rule resolves to when inspection finds nothing.
// It mirrors inspect.Resolve's own fallback for a Decision the engine built,
// which always carries CleanDecision.
func cleanDecisionOf(dec policy.Decision) types.Decision {
	if dec.Inspect != nil && dec.Inspect.CleanDecision != "" {
		return dec.Inspect.CleanDecision
	}
	return types.DecisionAllow
}

// argBlockReason names the rule and what was found, never the matched text.
// The reason is written back to the agent as a JSON-RPC error message, which
// lands in the agent's own transcript -- one of the places the content was
// being kept out of.
func argBlockReason(tool string, res inspect.Result) string {
	msg := fmt.Sprintf("tool %q blocked by content inspection", tool)
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

// replaceToolArguments substitutes params.arguments in a tools/call message,
// leaving every other field of the message and of params byte-identical.
//
// Redaction rewrites the arguments as raw JSON text, so the result can stop
// being JSON: a span the model labels across a `","` boundary produces
// something that no longer parses, and a replacement containing a quote or a
// backslash would do the same. Parsing the result back is the check that the
// message is still a legal tools/call; the caller blocks when it is not,
// rather than handing a corrupted request to the server.
func replaceToolArguments(data, arguments []byte) ([]byte, error) {
	if !json.Valid(arguments) {
		return nil, errors.New("redacted arguments are not valid JSON")
	}

	var msg map[string]json.RawMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("reparsing the message: %w", err)
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(msg["params"], &params); err != nil {
		return nil, fmt.Errorf("reparsing params: %w", err)
	}
	params["arguments"] = json.RawMessage(arguments)

	paramsRaw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("re-encoding params: %w", err)
	}
	msg["params"] = json.RawMessage(paramsRaw)

	out, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("re-encoding the message: %w", err)
	}
	// The message must still parse as the request it started as. A rewrite
	// that changed the method or lost the id would be forwarded happily by
	// the wrapper and fail at the server.
	if _, err := ParseToolsCallRequest(out); err != nil {
		return nil, err
	}
	return out, nil
}
