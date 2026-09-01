package policy

import (
	"context"
	"strings"
	"time"

	"github.com/diffsec/agentmon/pkg/types"
)

// DefaultCommandInspectTimeout bounds inspection of a command's argv when the
// rule sets no `inspect.timeout`.
//
// Command inspection is the one place the engine resolves an inspect decision
// itself, which means it runs inside whatever is waiting on the check: an API
// exec call, a seccomp USER_NOTIF, or a macOS ES_AUTH_EXEC callback. The
// seccomp path has no deadline of its own -- the process simply stays blocked
// -- so an unbounded inspector would hang an exec indefinitely with nothing
// in the log to explain it.
//
// Two seconds because that is already the tightest deadline in the tree:
// macos/AgentMon/ESFClient.swift's execDecisionTimeout, whose watchdog denies
// the exec if no verdict arrives. A command rule asking for longer than that
// is denied on macOS whatever this constant says, so matching it keeps the
// two platforms answering the same way.
const DefaultCommandInspectTimeout = 2 * time.Second

// resolveCommandInspection turns an inspect-bearing command decision into a
// terminal one.
//
// This is the only Check* that resolves inspection in the engine, and it can
// because for a command the engine already holds the content: the argv IS the
// content. CheckFile matches a path and CheckNetwork a destination, neither of
// which is the thing to inspect, so those must stay deferred to a caller that
// holds the bytes (see internal/inspect.Resolve).
//
// Resolving here rather than in the callers is what makes the decision uniform
// across enforcement layers. internal/netmonitor/unix/execve_handler.go and
// internal/platform/darwin/policysock/handler.go both act on
// EffectiveDecision, so a decision left unresolved reads as a deny to them --
// and a command the API layer had inspected and cleared would be denied again
// at exec time.
//
// It deliberately does NOT implement on_violation: redact. A rewritten argv
// has nowhere to go: Decision carries a verdict, not arguments, and running a
// command with placeholder arguments is worse than refusing it. validateInspection
// rejects redact on a command rule at load time, so this arm is reached only
// by a Decision built by hand.
func (e *Engine) resolveCommandInspection(ctx context.Context, dec Decision, command string, args []string) Decision {
	info := dec.Inspect
	if info == nil {
		return dec
	}
	if e.inspector == nil {
		return applyInspectFailure(dec, info, "no inspector is configured")
	}

	timeout := DefaultCommandInspectTimeout
	if info.TimeoutMS > 0 {
		timeout = time.Duration(info.TimeoutMS) * time.Millisecond
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	verdict, err := e.inspector.Inspect(ctx, InspectRequest{
		Profiles: info.Profiles,
		Kind:     inspectKindCommand,
		Content:  commandContent(command, args),
	})
	if err != nil {
		return applyInspectFailure(dec, info, err.Error())
	}

	if !verdict.Violation {
		dec.EffectiveDecision = inspectCleanDecision(info)
		return dec
	}

	switch info.OnViolation {
	case "allow":
		dec.EffectiveDecision = types.DecisionAllow
	case "approve":
		dec.EffectiveDecision = types.DecisionApprove
	default:
		// "deny", and "redact" -- which Validate refuses on this rule kind
		// because there is nowhere to put a rewritten argv.
		dec.EffectiveDecision = types.DecisionDeny
	}
	if verdict.Detail != "" {
		dec.Message = appendInspectReason(dec.Message, verdict.Detail)
	}
	return dec
}

// inspectKindCommand mirrors internal/inspect.KindCommand. It is spelled out
// here rather than imported because internal/inspect depends on this package,
// not the other way round; the two are pinned together by a test.
const inspectKindCommand = "command"

// commandContent is what an inspector sees for a command.
//
// The binary and its arguments are joined with single spaces rather than
// shell-quoted. A provider is looking for a value inside the argv -- an email
// address, a token, a customer record -- and quoting would put escapes through
// the middle of exactly those values, changing what a span classifier matches
// and what a safety classifier reads.
func commandContent(command string, args []string) string {
	if len(args) == 0 {
		return command
	}
	var b strings.Builder
	b.WriteString(command)
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(a)
	}
	return b.String()
}

// applyInspectFailure routes a failed inspection through the rule's
// on_failure. It mirrors internal/inspect.failure, which does the same for the
// wire points that hold their own content.
func applyInspectFailure(dec Decision, info *types.InspectInfo, reason string) Decision {
	switch info.OnFailure {
	case "fail_open":
		dec.EffectiveDecision = inspectCleanDecision(info)
	case "approve":
		dec.EffectiveDecision = types.DecisionApprove
	default:
		// "fail_closed", the schema default, and anything unrecognised.
		dec.EffectiveDecision = types.DecisionDeny
	}
	dec.Message = appendInspectReason(dec.Message, "inspection failed: "+reason)
	return dec
}

// inspectCleanDecision is what the rule resolves to when inspection finds
// nothing. wrapRuleDecision captured it before forcing the fail-closed deny,
// because it is enforce/shadow-aware and cannot be reconstructed from
// PolicyDecision alone.
func inspectCleanDecision(info *types.InspectInfo) types.Decision {
	if info.CleanDecision != "" {
		return info.CleanDecision
	}
	return types.DecisionAllow
}

func appendInspectReason(msg, reason string) string {
	if msg == "" {
		return reason
	}
	return msg + ": " + reason
}
