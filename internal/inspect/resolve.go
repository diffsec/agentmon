package inspect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/pkg/types"
)

// RedactingChecker is optionally implemented by inspectors that accept a
// caller-supplied redaction strategy. *Checker implements it.
type RedactingChecker interface {
	InspectWith(ctx context.Context, req policy.InspectRequest, r Redactor) (policy.InspectVerdict, error)
}

// Result is the outcome of resolving an inspect-bearing decision.
type Result struct {
	// Decision is the resolved decision. Its EffectiveDecision is now
	// terminal -- allow, deny or approve -- and safe for an enforcement
	// backend to act on.
	Decision policy.Decision
	// Content is what the caller should use going forward. It differs from
	// the input only when Rewritten is true.
	Content string
	// Rewritten is true when on_violation was redact and spans were
	// replaced.
	Rewritten bool
	// Verdict is what the inspector reported. Zero when inspection failed.
	Verdict policy.InspectVerdict
	// Err is the inspection failure that sent this through on_failure. It
	// is nil on both a clean result and a violation; a non-nil Err means
	// the content was NOT successfully inspected.
	Err error
}

// Resolve turns an unresolved inspect decision into a terminal one.
//
// The policy engine cannot do this: it matches rules against a path, an argv
// or a destination and never holds the content, so it emits a decision whose
// EffectiveDecision is deny with the inspection spec attached. Every caller
// that does hold the content -- a proxy body hook, the DLP pass, an MCP
// argument check -- routes it through here.
//
// A decision with no inspection spec is returned untouched, so callers can
// funnel every decision through Resolve without first testing for one.
func Resolve(ctx context.Context, checker policy.InspectChecker, dec policy.Decision, kind, content string, opts ...Option) Result {
	var o options
	for _, fn := range opts {
		fn(&o)
	}

	info := dec.Inspect
	if info == nil {
		return Result{Decision: dec, Content: content}
	}

	if checker == nil {
		return failure(dec, content, info, errors.New("no inspector is configured"))
	}

	// The rule's timeout bounds the whole inspection, across every profile.
	// Without it a caller's own deadline is the only bound, and an AUTH
	// decision or a proxied request would hang for as long as the slowest
	// provider takes.
	if info.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(info.TimeoutMS)*time.Millisecond)
		defer cancel()
	}

	req := policy.InspectRequest{
		Profiles: info.Profiles,
		Kind:     kind,
		Content:  content,
	}

	var verdict policy.InspectVerdict
	var err error
	// A caller that supplied a redactor gets it used only if the checker can
	// take one. Falling back silently is right: the placeholder still
	// redacts, so the rule is still enforced -- it just loses reversibility.
	if rc, ok := checker.(RedactingChecker); ok && o.redactor != nil {
		verdict, err = rc.InspectWith(ctx, req, o.redactor)
	} else {
		verdict, err = checker.Inspect(ctx, req)
	}
	if err != nil {
		return failure(dec, content, info, err)
	}

	if !verdict.Violation {
		dec.EffectiveDecision = cleanDecision(info)
		return Result{Decision: dec, Content: content, Verdict: verdict}
	}

	res := Result{Decision: dec, Content: content, Verdict: verdict}
	switch info.OnViolation {
	case "allow":
		res.Decision.EffectiveDecision = types.DecisionAllow
	case "approve":
		res.Decision.EffectiveDecision = types.DecisionApprove
	case "redact":
		// Redaction needs spans. A query-based profile answers "does this
		// exfiltrate credentials?" with a yes and no offsets, so there is
		// nothing to rewrite -- and returning the original content under an
		// allow would pass exactly the content the rule flagged. Fail closed
		// instead, and say why.
		if verdict.Redacted == "" {
			res.Decision.EffectiveDecision = types.DecisionDeny
			res.Decision.Message = appendReason(dec.Message,
				"inspection found a violation with no redactable span; on_violation: redact cannot apply, denying")
			return res
		}
		res.Decision.EffectiveDecision = types.DecisionAllow
		res.Content = verdict.Redacted
		res.Rewritten = true
	default:
		// "deny", and anything Validate did not catch. wrapDecision's
		// default arm makes the same choice for the same reason.
		res.Decision.EffectiveDecision = types.DecisionDeny
	}

	if verdict.Detail != "" {
		res.Decision.Message = appendReason(res.Decision.Message, verdict.Detail)
	}
	return res
}

// Fail routes a caller-side failure through the rule's on_failure, without
// calling an inspector.
//
// It exists because some reasons the content cannot be inspected are known
// before an inspector would be reached -- a body over the caller's size cap,
// a stream that could not be buffered. Those must reach the same on_failure
// the rule declares, not a bare deny and not a skip: a request body too large
// to inspect is uninspected content, exactly like a provider timeout.
func Fail(dec policy.Decision, content string, err error) Result {
	if dec.Inspect == nil {
		return Result{Decision: dec, Content: content, Err: err}
	}
	return failure(dec, content, dec.Inspect, err)
}

// failure applies on_failure. It is reached whenever the content was not
// successfully inspected -- no inspector, an unknown profile, a privacy
// refusal, a provider error, a timeout.
func failure(dec policy.Decision, content string, info *types.InspectInfo, err error) Result {
	res := Result{Decision: dec, Content: content, Err: err}
	switch info.OnFailure {
	case "fail_open":
		res.Decision.EffectiveDecision = cleanDecision(info)
	case "approve":
		res.Decision.EffectiveDecision = types.DecisionApprove
	default:
		// "fail_closed", the schema default, and anything unrecognised.
		res.Decision.EffectiveDecision = types.DecisionDeny
	}
	res.Decision.Message = appendReason(dec.Message, fmt.Sprintf("inspection failed: %v", err))
	return res
}

// cleanDecision is what the rule resolves to when inspection finds nothing.
//
// The engine captured it before forcing the fail-closed deny, because it is
// enforce/shadow-aware and cannot be reconstructed from PolicyDecision alone.
// An InspectInfo built by hand may not carry it; allow is the right fallback,
// since the only paths that reach here are a clean inspection and an explicit
// fail_open, and both mean "let it through".
func cleanDecision(info *types.InspectInfo) types.Decision {
	if info.CleanDecision != "" {
		return info.CleanDecision
	}
	return types.DecisionAllow
}

func appendReason(msg, reason string) string {
	if msg == "" {
		return reason
	}
	return msg + ": " + reason
}
