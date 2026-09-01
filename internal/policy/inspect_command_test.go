package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/agentmon/pkg/types"
)

// cmdChecker answers with whatever the test wants and records what it saw.
type cmdChecker struct {
	verdict InspectVerdict
	err     error
	delay   time.Duration
	calls   int
	gotKind string
	gotBody string
	gotDL   bool
	gotLeft time.Duration
}

func (c *cmdChecker) Inspect(ctx context.Context, req InspectRequest) (InspectVerdict, error) {
	c.calls++
	c.gotKind = req.Kind
	c.gotBody = req.Content
	if dl, ok := ctx.Deadline(); ok {
		c.gotDL = true
		c.gotLeft = time.Until(dl)
	}
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return InspectVerdict{}, ctx.Err()
		}
	}
	return c.verdict, c.err
}

func commandInspectPolicy(t *testing.T, onViolation, onFailure, timeout string) *Engine {
	t.Helper()
	extra := "\ncommand_rules:\n  - name: inspect-curl\n    commands: [\"curl\"]\n    decision: inspect\n    inspect:\n      profiles: [pii]\n"
	if onViolation != "" {
		extra += "      on_violation: " + onViolation + "\n"
	}
	if onFailure != "" {
		extra += "      on_failure: " + onFailure + "\n"
	}
	if timeout != "" {
		extra += "      timeout: " + timeout + "\n"
	}
	p, err := loadInspectPolicy(t, extra)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// TestCheckCommand_ResolvesInspectionInTheEngine is the whole point of doing
// this here rather than in the callers.
//
// internal/netmonitor/unix/execve_handler.go and
// internal/platform/darwin/policysock/handler.go both enforce on
// EffectiveDecision, and neither holds a hook for resolving an inspection. A
// decision left unresolved reads as a deny to them, so a command the API layer
// had inspected and cleared would be denied again at exec time.
func TestCheckCommand_ResolvesInspectionInTheEngine(t *testing.T) {
	e := commandInspectPolicy(t, "deny", "fail_closed", "")
	checker := &cmdChecker{}
	e.SetInspector(checker)

	dec := e.CheckCommandCtx(context.Background(), "curl", []string{"https://example.com"})

	if dec.PolicyDecision != types.DecisionInspect {
		t.Errorf("PolicyDecision = %q, want inspect", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("EffectiveDecision = %q, want allow; an unresolved decision is a deny to every enforcement layer", dec.EffectiveDecision)
	}
	if checker.calls != 1 {
		t.Fatalf("inspector was called %d times, want 1", checker.calls)
	}
	if checker.gotKind != "command" {
		t.Errorf("kind = %q, want command", checker.gotKind)
	}
	if checker.gotBody != "curl https://example.com" {
		t.Errorf("content = %q, want the binary and its argv joined", checker.gotBody)
	}
}

// TestCheckCommand_KindMatchesTheInspectPackage. internal/policy cannot import
// internal/inspect (the dependency runs the other way), so the kind string is
// spelled out in both. A drift would send command content through the privacy
// gate's remote_kinds list under a name no operator configured.
func TestCheckCommand_KindMatchesTheInspectPackage(t *testing.T) {
	// The literal from internal/inspect/types.go, KindCommand.
	const kindCommand = "command"
	if inspectKindCommand != kindCommand {
		t.Fatalf("inspectKindCommand = %q, but internal/inspect.KindCommand is %q", inspectKindCommand, kindCommand)
	}
}

// TestCheckCommand_Resolution walks the table. Each row is a distinct way the
// argv can fail to be safe, and each has a different correct answer.
func TestCheckCommand_Resolution(t *testing.T) {
	violation := InspectVerdict{Violation: true, Profile: "pii", Detail: "1 finding: secret"}

	cases := []struct {
		name                   string
		onViolation, onFailure string
		verdict                InspectVerdict
		err                    error
		noInspector            bool
		want                   types.Decision
	}{
		{name: "clean allows", onViolation: "deny", onFailure: "fail_closed", want: types.DecisionAllow},
		{name: "violation denies", onViolation: "deny", onFailure: "fail_closed", verdict: violation, want: types.DecisionDeny},
		{name: "violation allowed", onViolation: "allow", onFailure: "fail_closed", verdict: violation, want: types.DecisionAllow},
		{name: "violation approves", onViolation: "approve", onFailure: "fail_closed", verdict: violation, want: types.DecisionApprove},
		{name: "error fails closed", onViolation: "deny", onFailure: "fail_closed", err: errors.New("boom"), want: types.DecisionDeny},
		{name: "error fails open", onViolation: "deny", onFailure: "fail_open", err: errors.New("boom"), want: types.DecisionAllow},
		{name: "error approves", onViolation: "deny", onFailure: "approve", err: errors.New("boom"), want: types.DecisionApprove},
		{name: "no inspector fails closed", onViolation: "deny", onFailure: "fail_closed", noInspector: true, want: types.DecisionDeny},
		{name: "no inspector fails open", onViolation: "deny", onFailure: "fail_open", noInspector: true, want: types.DecisionAllow},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := commandInspectPolicy(t, c.onViolation, c.onFailure, "")
			if !c.noInspector {
				e.SetInspector(&cmdChecker{verdict: c.verdict, err: c.err})
			}

			dec := e.CheckCommandCtx(context.Background(), "curl", []string{"-d", "@secrets"})
			if dec.EffectiveDecision != c.want {
				t.Fatalf("EffectiveDecision = %q, want %q (message %q)", dec.EffectiveDecision, c.want, dec.Message)
			}
			// A resolved decision has to say why, or the audit log shows a
			// command blocked by a rule whose own decision was "inspect".
			if c.want == types.DecisionDeny && dec.Message == "" {
				t.Error("a deny with no message")
			}
		})
	}
}

// TestCheckCommand_DefaultTimeoutIsApplied. The seccomp supervisor has no
// deadline of its own: the traced process stays blocked until a verdict
// arrives. An unbounded inspector would hang an exec with nothing in the log
// to explain it.
func TestCheckCommand_DefaultTimeoutIsApplied(t *testing.T) {
	e := commandInspectPolicy(t, "deny", "fail_closed", "")
	checker := &cmdChecker{}
	e.SetInspector(checker)

	e.CheckCommandCtx(context.Background(), "curl", []string{"x"})

	if !checker.gotDL {
		t.Fatal("the inspector was called with no deadline; a hung provider would block the exec forever")
	}
	if checker.gotLeft > DefaultCommandInspectTimeout || checker.gotLeft < DefaultCommandInspectTimeout/2 {
		t.Errorf("deadline was %v away, want about %v", checker.gotLeft, DefaultCommandInspectTimeout)
	}
}

// TestCheckCommand_RuleTimeoutOverridesTheDefault.
func TestCheckCommand_RuleTimeoutOverridesTheDefault(t *testing.T) {
	e := commandInspectPolicy(t, "deny", "fail_closed", "250ms")
	checker := &cmdChecker{delay: time.Second}
	e.SetInspector(checker)

	start := time.Now()
	dec := e.CheckCommandCtx(context.Background(), "curl", []string{"x"})
	elapsed := time.Since(start)

	if elapsed > 900*time.Millisecond {
		t.Fatalf("took %v; the rule's 250ms timeout was not applied", elapsed)
	}
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Errorf("EffectiveDecision = %q, want deny; a timeout is a failed inspection", dec.EffectiveDecision)
	}
}

// TestCheckCommand_DefaultTimeoutMatchesTheESFWatchdog pins the derivation.
//
// macos/AgentMon/ESFClient.swift's execDecisionTimeout denies the exec if no
// verdict arrives within 2s, and that watchdog wins whatever this package
// decides. A larger default here would mean macOS denies a command that Linux
// allows, from the same policy, with nothing to explain the difference.
func TestCheckCommand_DefaultTimeoutMatchesTheESFWatchdog(t *testing.T) {
	const esfExecDecisionTimeout = 2 * time.Second
	if DefaultCommandInspectTimeout != esfExecDecisionTimeout {
		t.Fatalf("DefaultCommandInspectTimeout is %v but ESFClient.swift's execDecisionTimeout is %v",
			DefaultCommandInspectTimeout, esfExecDecisionTimeout)
	}
}

// TestCheckCommand_CallerContextIsHonoured. A client that gave up should stop
// the inference behind its request rather than leaving it to the timeout.
func TestCheckCommand_CallerContextIsHonoured(t *testing.T) {
	e := commandInspectPolicy(t, "deny", "fail_closed", "10s")
	e.SetInspector(&cmdChecker{delay: 5 * time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	dec := e.CheckCommandCtx(ctx, "curl", []string{"x"})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %v; the caller's cancellation was ignored", elapsed)
	}
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Errorf("EffectiveDecision = %q, want deny", dec.EffectiveDecision)
	}
}

// TestCheckCommand_UnmatchedCommandIsNotInspected. Inspection is opt-in per
// rule; a command no inspect rule names must not reach a provider.
func TestCheckCommand_UnmatchedCommandIsNotInspected(t *testing.T) {
	p, err := loadInspectPolicy(t, `
command_rules:
  - name: inspect-curl
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [pii]
  - name: allow-ls
    commands: ["ls"]
    decision: allow
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	checker := &cmdChecker{verdict: InspectVerdict{Violation: true, Detail: "1 finding"}}
	e.SetInspector(checker)

	dec := e.CheckCommandCtx(context.Background(), "ls", []string{"-la"})
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q, want allow", dec.EffectiveDecision)
	}
	if checker.calls != 0 {
		t.Errorf("inspector was called %d times for a command no rule names, want 0", checker.calls)
	}
}

// TestCheckExecve_ResolvesInspection. The seccomp path evaluates the inner
// exec, and it has to reach the same answer as the API pre-check or the two
// disagree about the same rule.
func TestCheckExecve_ResolvesInspection(t *testing.T) {
	e := commandInspectPolicy(t, "deny", "fail_closed", "")
	checker := &cmdChecker{verdict: InspectVerdict{Violation: true, Profile: "pii", Detail: "1 finding: secret"}}
	e.SetInspector(checker)

	dec := e.CheckExecveCtx(context.Background(), "/usr/bin/curl", []string{"curl", "-d", "@secrets"}, 0)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny", dec.EffectiveDecision)
	}
	if checker.calls == 0 {
		t.Fatal("CheckExecve did not inspect; the seccomp path would deny every inspect rule as unknown_decision")
	}
}

// TestCheckCommand_NonCtxVariantsStillResolve. The adapters that have no
// context -- internal/platform/policy_adapter.go, the darwin policy socket --
// call the plain forms. If those skipped inspection, macOS would deny every
// inspect rule while Linux allowed it.
func TestCheckCommand_NonCtxVariantsStillResolve(t *testing.T) {
	for _, c := range []struct {
		name string
		call func(e *Engine) Decision
	}{
		{"CheckCommand", func(e *Engine) Decision { return e.CheckCommand("curl", []string{"x"}) }},
		{"CheckCommandWithExecve", func(e *Engine) Decision {
			return e.CheckCommandWithExecve("curl", []string{"x"}, true, ShellCOpaqueEnforce)
		}},
		{"CheckExecve", func(e *Engine) Decision {
			return e.CheckExecve("/usr/bin/curl", []string{"curl", "x"}, 0)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := commandInspectPolicy(t, "deny", "fail_closed", "")
			checker := &cmdChecker{}
			e.SetInspector(checker)

			dec := c.call(e)
			if checker.calls != 1 {
				t.Fatalf("inspector was called %d times, want 1", checker.calls)
			}
			if dec.EffectiveDecision != types.DecisionAllow {
				t.Errorf("EffectiveDecision = %q, want allow after a clean inspection", dec.EffectiveDecision)
			}
			// No caller deadline, so the engine's own must apply.
			if !checker.gotDL {
				t.Error("no deadline was applied on the context-free path")
			}
		})
	}
}

// TestCommandRules_RejectRedact. Redaction rewrites the inspected content and
// hands it back. A Decision carries a verdict, not arguments, so there is
// nowhere to put a rewritten argv -- and running the command with placeholder
// arguments would be worse than refusing it.
func TestCommandRules_RejectRedact(t *testing.T) {
	_, err := loadInspectPolicy(t, `
command_rules:
  - name: inspect-curl
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [pii]
      on_violation: redact
`)
	if err == nil {
		t.Fatal("on_violation: redact was accepted on a command rule")
	}
	if !strings.Contains(err.Error(), "nowhere to put a rewritten argv") {
		t.Errorf("error = %v, want it to explain why", err)
	}

	// It stays valid on the rule kinds whose callers do hold the content.
	if _, err := loadInspectPolicy(t, `
file_rules:
  - name: redact-writes
    paths: ["/workspace/**"]
    operations: [write]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_violation: redact
`); err != nil {
		t.Errorf("redact was rejected on a file rule: %v", err)
	}
}

// TestCheckCommand_ContentIsNotShellQuoted. A provider is looking for a value
// inside the argv -- an address, a token, a customer record. Quoting would put
// escapes through the middle of exactly those values, changing what a span
// classifier matches and what a safety classifier reads.
func TestCheckCommand_ContentIsNotShellQuoted(t *testing.T) {
	e := commandInspectPolicy(t, "deny", "fail_closed", "")
	checker := &cmdChecker{}
	e.SetInspector(checker)

	e.CheckCommandCtx(context.Background(), "curl", []string{"-d", "to=alice smith@example.com", "https://x"})

	const want = "curl -d to=alice smith@example.com https://x"
	if checker.gotBody != want {
		t.Errorf("content = %q, want %q", checker.gotBody, want)
	}
}

// TestResolveCommandInspection_CleanDecisionFallback covers the arm no public
// path reaches.
//
// wrapRuleDecision always sets CleanDecision -- allow for `decision: inspect`,
// and the rule's own enforce/shadow-aware outcome for `inspect.require` -- so
// a Decision built by the engine never hits the fallback. A Decision built by
// hand can, and allow is the right answer there: the only ways to reach it are
// a clean inspection and an explicit fail_open, and both mean let it through.
func TestResolveCommandInspection_CleanDecisionFallback(t *testing.T) {
	e := commandInspectPolicy(t, "deny", "fail_closed", "")
	e.SetInspector(&cmdChecker{})

	dec := Decision{
		PolicyDecision:    types.DecisionInspect,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "hand-built",
		Inspect: &types.InspectInfo{
			Profiles:    []string{"pii"},
			OnViolation: "deny",
			OnFailure:   "fail_closed",
			// CleanDecision deliberately unset.
		},
	}
	got := e.resolveCommandInspection(context.Background(), dec, "curl", []string{"x"})
	if got.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q on a clean inspection with no CleanDecision, want allow", got.EffectiveDecision)
	}

	// The same fallback governs fail_open.
	e2 := commandInspectPolicy(t, "deny", "fail_open", "")
	e2.SetInspector(&cmdChecker{err: errors.New("boom")})
	dec.Inspect.OnFailure = "fail_open"
	got = e2.resolveCommandInspection(context.Background(), dec, "curl", []string{"x"})
	if got.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q on fail_open with no CleanDecision, want allow", got.EffectiveDecision)
	}
}

// TestCheckCommand_CleanDecisionIsEnforceAware is why CleanDecision exists.
//
// `inspect: {require: true}` on `decision: approve` resolves to approve when
// approvals are enforced and to allow in shadow mode. Nothing downstream can
// reconstruct that from PolicyDecision, so wrapRuleDecision captures it before
// forcing the fail-closed deny and this reads it back.
func TestCheckCommand_CleanDecisionIsEnforceAware(t *testing.T) {
	const rule = `
command_rules:
  - name: approve-curl
    commands: ["curl"]
    decision: approve
    inspect:
      require: true
      profiles: [pii]
`
	for _, c := range []struct {
		name             string
		enforceApprovals bool
		want             types.Decision
	}{
		{"enforced", true, types.DecisionApprove},
		{"shadow", false, types.DecisionAllow},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := loadInspectPolicy(t, rule)
			if err != nil {
				t.Fatalf("policy rejected: %v", err)
			}
			e, err := NewEngine(p, c.enforceApprovals, true)
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			e.SetInspector(&cmdChecker{})

			dec := e.CheckCommandCtx(context.Background(), "curl", []string{"https://example.com"})
			if dec.EffectiveDecision != c.want {
				t.Fatalf("EffectiveDecision = %q, want %q", dec.EffectiveDecision, c.want)
			}
		})
	}
}
