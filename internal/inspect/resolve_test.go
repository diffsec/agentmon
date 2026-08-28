package inspect_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/pkg/types"
)

// fakeChecker lets the outcome matrix be driven directly. Building these
// verdicts through a real provider would couple the matrix to regex
// behaviour, and the matrix is about what Resolve does with an answer, not
// about how the answer was reached.
type fakeChecker struct {
	verdict policy.InspectVerdict
	err     error
	delay   time.Duration
	calls   int
}

func (f *fakeChecker) Inspect(ctx context.Context, _ policy.InspectRequest) (policy.InspectVerdict, error) {
	f.calls++
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return policy.InspectVerdict{}, ctx.Err()
		}
	}
	return f.verdict, f.err
}

func decisionWith(info *types.InspectInfo) policy.Decision {
	return policy.Decision{
		PolicyDecision:    types.DecisionInspect,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "r",
		Inspect:           info,
	}
}

// TestResolve_NoSpecIsUntouched lets callers funnel every decision through
// Resolve without first testing for a spec.
func TestResolve_NoSpecIsUntouched(t *testing.T) {
	dec := policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow, Rule: "r"}
	res := inspect.Resolve(context.Background(), &fakeChecker{}, dec, inspect.KindFile, "body")
	if res.Decision.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q, want allow", res.Decision.EffectiveDecision)
	}
	if res.Content != "body" || res.Rewritten {
		t.Error("content was altered for a decision with no inspection spec")
	}
}

// TestResolve_OnViolation is the violation half of the outcome matrix.
func TestResolve_OnViolation(t *testing.T) {
	cases := []struct {
		onViolation string
		redacted    string
		want        types.Decision
		wantRewrite bool
	}{
		{onViolation: "deny", want: types.DecisionDeny},
		{onViolation: "allow", want: types.DecisionAllow},
		{onViolation: "approve", want: types.DecisionApprove},
		{onViolation: "redact", redacted: "[REDACTED:secret]", want: types.DecisionAllow, wantRewrite: true},
		// An unrecognised value must deny. Validate rejects these at load,
		// so reaching here means a policy arrived some other way -- and
		// guessing is how a typo becomes an allow.
		{onViolation: "sideways", want: types.DecisionDeny},
	}

	for _, c := range cases {
		t.Run(c.onViolation, func(t *testing.T) {
			checker := &fakeChecker{verdict: policy.InspectVerdict{
				Violation: true, Profile: "p", Detail: "1 finding: secret", Redacted: c.redacted,
			}}
			dec := decisionWith(&types.InspectInfo{
				Profiles: []string{"p"}, OnViolation: c.onViolation,
				OnFailure: "fail_closed", CleanDecision: types.DecisionAllow,
			})

			res := inspect.Resolve(context.Background(), checker, dec, inspect.KindProxyBody, "token=sk-live")
			if res.Decision.EffectiveDecision != c.want {
				t.Errorf("EffectiveDecision = %q, want %q", res.Decision.EffectiveDecision, c.want)
			}
			if res.Rewritten != c.wantRewrite {
				t.Errorf("Rewritten = %v, want %v", res.Rewritten, c.wantRewrite)
			}
			if c.wantRewrite && res.Content != c.redacted {
				t.Errorf("Content = %q, want the redacted text", res.Content)
			}
			if !c.wantRewrite && res.Content != "token=sk-live" {
				t.Errorf("Content was altered without a rewrite: %q", res.Content)
			}
			if res.Err != nil {
				t.Errorf("Err = %v; a violation is a successful inspection, not a failure", res.Err)
			}
		})
	}
}

// TestResolve_RedactWithNoSpanDenies is the case that is easy to get wrong.
//
// A query-based profile answers "does this exfiltrate credentials?" with a
// yes and no offsets, so there is nothing to rewrite. Allowing the original
// content through would pass exactly the content the rule flagged.
func TestResolve_RedactWithNoSpanDenies(t *testing.T) {
	checker := &fakeChecker{verdict: policy.InspectVerdict{
		Violation: true, Profile: "exfil", Detail: "1 finding: credential_exfil", Redacted: "",
	}}
	dec := decisionWith(&types.InspectInfo{
		Profiles: []string{"exfil"}, OnViolation: "redact",
		OnFailure: "fail_closed", CleanDecision: types.DecisionAllow,
	})

	res := inspect.Resolve(context.Background(), checker, dec, inspect.KindProxyBody, "secret payload")
	if res.Decision.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny; redact with no span must not allow the flagged content", res.Decision.EffectiveDecision)
	}
	if res.Content != "secret payload" || res.Rewritten {
		t.Error("content was reported as rewritten when nothing could be rewritten")
	}
	if !strings.Contains(res.Decision.Message, "no redactable span") {
		t.Errorf("message should explain why, got %q", res.Decision.Message)
	}
}

// TestResolve_OnFailure covers every way inspection can fail to produce an
// answer. All of them are failures, never clean results.
func TestResolve_OnFailure(t *testing.T) {
	cases := []struct {
		onFailure string
		want      types.Decision
	}{
		{onFailure: "fail_closed", want: types.DecisionDeny},
		{onFailure: "fail_open", want: types.DecisionAllow},
		{onFailure: "approve", want: types.DecisionApprove},
		{onFailure: "", want: types.DecisionDeny},         // schema default
		{onFailure: "elsewise", want: types.DecisionDeny}, // unrecognised
	}

	for _, c := range cases {
		name := c.onFailure
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			checker := &fakeChecker{err: errors.New("provider exploded")}
			dec := decisionWith(&types.InspectInfo{
				Profiles: []string{"p"}, OnViolation: "deny",
				OnFailure: c.onFailure, CleanDecision: types.DecisionAllow,
			})

			res := inspect.Resolve(context.Background(), checker, dec, inspect.KindFile, "body")
			if res.Decision.EffectiveDecision != c.want {
				t.Errorf("EffectiveDecision = %q, want %q", res.Decision.EffectiveDecision, c.want)
			}
			if res.Err == nil {
				t.Error("Err was nil; the caller cannot tell an uninspected allow from an inspected one")
			}
			if !strings.Contains(res.Decision.Message, "inspection failed") {
				t.Errorf("message should record the failure, got %q", res.Decision.Message)
			}
		})
	}
}

// TestResolve_NilCheckerIsAFailure: an inspect-bearing policy installed with
// no inspector wired must not resolve to the operator's decision by accident.
func TestResolve_NilCheckerIsAFailure(t *testing.T) {
	dec := decisionWith(&types.InspectInfo{
		Profiles: []string{"p"}, OnViolation: "deny", OnFailure: "fail_closed",
		CleanDecision: types.DecisionAllow,
	})
	res := inspect.Resolve(context.Background(), nil, dec, inspect.KindFile, "body")
	if res.Decision.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny with no inspector", res.Decision.EffectiveDecision)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "no inspector") {
		t.Errorf("Err = %v, want it to name the missing inspector", res.Err)
	}
}

// TestResolve_TimeoutIsAFailure: the rule's timeout must actually bound the
// call. Without it a slow provider stalls whatever held the decision -- an
// ESF AUTH response, a proxied request.
func TestResolve_TimeoutIsAFailure(t *testing.T) {
	checker := &fakeChecker{delay: 2 * time.Second, verdict: policy.InspectVerdict{}}
	dec := decisionWith(&types.InspectInfo{
		Profiles: []string{"p"}, OnViolation: "deny", OnFailure: "fail_closed",
		TimeoutMS: 50, CleanDecision: types.DecisionAllow,
	})

	start := time.Now()
	res := inspect.Resolve(context.Background(), checker, dec, inspect.KindFile, "body")
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("took %s; the rule timeout did not bound the call", elapsed)
	}
	if res.Decision.EffectiveDecision != types.DecisionDeny {
		t.Errorf("EffectiveDecision = %q, want deny on timeout", res.Decision.EffectiveDecision)
	}
	if res.Err == nil {
		t.Error("a timeout was not reported as a failure")
	}
}

// TestResolve_CleanRestoresShadowApprove pins why CleanDecision is carried
// rather than derived. A shadow-mode approve has PolicyDecision approve and
// an effective decision of allow. A resolver deriving from PolicyDecision
// would turn every shadow-mode approve into a hard gate the moment an
// inspect precondition was added to it.
func TestResolve_CleanRestoresShadowApprove(t *testing.T) {
	dec := policy.Decision{
		PolicyDecision:    types.DecisionApprove,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "shadow-approve",
		Inspect: &types.InspectInfo{
			Profiles: []string{"p"}, Require: true, OnViolation: "deny",
			OnFailure: "fail_closed", CleanDecision: types.DecisionAllow,
		},
	}
	res := inspect.Resolve(context.Background(), &fakeChecker{}, dec, inspect.KindFile, "clean")
	if res.Decision.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q, want allow (shadow mode), not approve", res.Decision.EffectiveDecision)
	}
	if res.Decision.PolicyDecision != types.DecisionApprove {
		t.Errorf("PolicyDecision changed to %q; the operator's decision must be preserved", res.Decision.PolicyDecision)
	}
}
