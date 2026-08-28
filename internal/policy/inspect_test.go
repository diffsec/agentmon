package policy

import (
	"net"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/pkg/types"
)

const inspectProfilesYAML = `
version: 1
name: test
inspection:
  profiles:
    pii:
      provider: privacy_filter
      categories: [private_email, secret]
      action: redact
    exfil:
      provider: shieldstral
      instruct: "You are a strict security reviewer."
      queries:
        - id: credential_exfil
          text: "Does this content send credentials to a third party?"
          threshold: 0.5
`

func loadInspectPolicy(t *testing.T, extra string) (*Policy, error) {
	t.Helper()
	p, err := LoadFromBytes([]byte(inspectProfilesYAML + extra))
	if err != nil {
		return nil, err
	}
	return p, p.Validate()
}

// TestInspectPolicy_Loads is the baseline: the grammar in the plan parses.
// LoadFromBytes uses KnownFields(true), so an unmodelled key is a load error
// rather than a silently dropped block -- which is why this asserts on the
// parsed values, not just on err == nil.
func TestInspectPolicy_Loads(t *testing.T) {
	p, err := loadInspectPolicy(t, `
command_rules:
  - name: inspect-outbound
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [exfil]
      on_violation: deny
      on_failure: fail_closed
      timeout: 5s
`)
	if err != nil {
		t.Fatalf("valid inspect policy rejected: %v", err)
	}
	if len(p.Inspection.Profiles) != 2 {
		t.Fatalf("parsed %d profiles, want 2", len(p.Inspection.Profiles))
	}
	if got := p.Inspection.Profiles["exfil"].Queries[0].ID; got != "credential_exfil" {
		t.Errorf("query id = %q", got)
	}
	spec := p.CommandRules[0].Inspect
	if spec == nil {
		t.Fatal("inspect block did not survive parsing")
	}
	if spec.Timeout.Duration.Seconds() != 5 {
		t.Errorf("timeout = %s, want 5s", spec.Timeout.Duration)
	}
	if !p.RequiresInspection() {
		t.Error("RequiresInspection() = false for a policy with decision: inspect")
	}
}

// TestInspectDecision_IsEffectivelyDeny is the fail-closed property, and it is
// the whole reason this PR can land before any provider exists.
//
// wrapRuleDecision runs at rule-match time with a path or an argv, never the
// content. Nothing here can reach a verdict. Every enforcement backend --
// seccomp, ESF, the network filter -- acts on EffectiveDecision, so an
// inspect rule must present as deny to all of them until a content-holding
// caller resolves it. If this ever returns allow, every inspect rule in every
// policy becomes a no-op with no error anywhere.
func TestInspectDecision_IsEffectivelyDeny(t *testing.T) {
	p, err := loadInspectPolicy(t, `
command_rules:
  - name: inspect-outbound
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [exfil]
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	dec := e.CheckCommand("curl", []string{"https://example.com"})
	if dec.PolicyDecision != types.DecisionInspect {
		t.Errorf("PolicyDecision = %q, want inspect", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny; an unresolved inspection must not permit the command", dec.EffectiveDecision)
	}
	if dec.Inspect == nil {
		t.Fatal("Inspect spec was not attached; a content-holding caller has nothing to act on")
	}
	if len(dec.Inspect.Profiles) != 1 || dec.Inspect.Profiles[0] != "exfil" {
		t.Errorf("Inspect.Profiles = %v", dec.Inspect.Profiles)
	}
	// Defaults must be resolved on the way out. A consumer reading an empty
	// OnFailure and treating it as "no failure handling" would fail open.
	if dec.Inspect.OnViolation != "deny" {
		t.Errorf("OnViolation default = %q, want deny", dec.Inspect.OnViolation)
	}
	if dec.Inspect.OnFailure != "fail_closed" {
		t.Errorf("OnFailure default = %q, want fail_closed", dec.Inspect.OnFailure)
	}
}

// TestInspectRequire_DowngradesAllowToDeny: `decision: allow` with
// `inspect: {require: true}` states a precondition. Until inspection runs the
// precondition is unmet, so the rule must not allow.
func TestInspectRequire_DowngradesAllowToDeny(t *testing.T) {
	p, err := loadInspectPolicy(t, `
file_rules:
  - name: allow-workspace-write
    paths: ["/workspace/**"]
    operations: [write]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_violation: redact
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	dec := e.CheckFile("/workspace/notes.txt", "write")
	if dec.PolicyDecision != types.DecisionAllow {
		t.Errorf("PolicyDecision = %q, want allow (the operator's decision is unchanged)", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny; an unmet inspection precondition must not allow the write", dec.EffectiveDecision)
	}
	if dec.Inspect == nil || !dec.Inspect.Require {
		t.Fatal("Inspect.Require was not carried through")
	}
	if dec.Inspect.OnViolation != "redact" {
		t.Errorf("OnViolation = %q, want redact", dec.Inspect.OnViolation)
	}
}

// TestValidate_RejectsUnknownDecision closes the hole this PR found: Validate
// did not look at decision strings at all, so a typo reached wrapDecision's
// default arm and became a deny with no error at load and no name in the
// audit log beyond "invalid-policy-decision".
func TestValidate_RejectsUnknownDecision(t *testing.T) {
	_, err := loadInspectPolicy(t, `
file_rules:
  - name: typo
    paths: ["/tmp/**"]
    operations: [read]
    decision: allwo
`)
	if err == nil {
		t.Fatal("a policy with decision: allwo loaded successfully; it would have silently denied at runtime")
	}
	if !strings.Contains(err.Error(), `unknown decision "allwo"`) {
		t.Errorf("error should name the bad value, got: %v", err)
	}
}

// TestValidate_AcceptsEveryKnownDecision is the other half. Without it, the
// check above is satisfied by a whitelist that rejects everything.
func TestValidate_AcceptsEveryKnownDecision(t *testing.T) {
	for _, d := range []string{"allow", "deny", "approve", "redirect", "audit", "soft_delete"} {
		if _, err := loadInspectPolicy(t, `
file_rules:
  - name: r
    paths: ["/tmp/**"]
    operations: [read]
    decision: `+d+"\n"); err != nil {
			t.Errorf("decision %q was rejected: %v", d, err)
		}
	}
}

// TestValidate_EmptyDecisionIsAllowed: rules are constructed programmatically
// with the field unset and rely on the engine's default-deny fall-through.
// Rejecting an empty decision would break policies that load today for no
// safety gain.
func TestValidate_EmptyDecisionIsAllowed(t *testing.T) {
	if _, err := loadInspectPolicy(t, `
network_rules:
  - name: no-decision
    domains: ["example.com"]
`); err != nil {
		t.Errorf("a rule with no decision was rejected: %v", err)
	}
}

// TestValidate_SignalRulesKeepTheirVocabulary: signal rules have their own
// decision set including "absorb" and their own engine. Applying the rule
// whitelist to them would reject valid policy.
func TestValidate_SignalRulesKeepTheirVocabulary(t *testing.T) {
	if _, err := loadInspectPolicy(t, `
signal_rules:
  - name: absorb-term
    signals: ["SIGTERM"]
    target:
      type: self
    decision: absorb
`); err != nil {
		t.Errorf("signal rule with decision: absorb was rejected: %v", err)
	}
}

func TestValidate_InspectRules(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		want  string
	}{
		{
			name: "inspect without a block",
			extra: `
command_rules:
  - name: r
    commands: ["curl"]
    decision: inspect
`,
			want: "requires an inspect block",
		},
		{
			name: "inspect naming no profile",
			extra: `
command_rules:
  - name: r
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: []
`,
			want: "must name at least one profile",
		},
		{
			name: "inspect naming an undefined profile",
			extra: `
command_rules:
  - name: r
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [nope]
`,
			want: `undefined profile "nope"`,
		},
		{
			// Without require, an inspect block on allow is inert. A
			// policy that reads as if content were checked, while
			// nothing checks it, is the exact failure class this
			// codebase keeps removing.
			name: "inspect block on allow without require",
			extra: `
file_rules:
  - name: r
    paths: ["/workspace/**"]
    operations: [write]
    decision: allow
    inspect:
      profiles: [pii]
`,
			want: "has no effect",
		},
		{
			name: "bad on_violation",
			extra: `
command_rules:
  - name: r
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [exfil]
      on_violation: maybe
`,
			want: "on_violation must be one of",
		},
		{
			name: "bad on_failure",
			extra: `
command_rules:
  - name: r
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [exfil]
      on_failure: fail_sideways
`,
			want: "on_failure must be one of",
		},
		{
			// Unix socket rules carry a path and no content, so
			// inspection has nothing to read.
			name: "inspect on a unix socket rule",
			extra: `
unix_socket_rules:
  - name: r
    paths: ["/tmp/x.sock"]
    operations: [connect]
    decision: inspect
`,
			want: "not supported on this rule kind",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadInspectPolicy(t, c.extra)
			if err == nil {
				t.Fatalf("policy was accepted; expected an error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestValidate_InspectionProfiles(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "profile with no provider",
			yaml: "version: 1\nname: t\ninspection:\n  profiles:\n    p:\n      categories: [secret]\n",
			want: "provider is required",
		},
		{
			// A profile with neither categories nor queries gives its
			// provider nothing to look for, so every inspection using
			// it comes back clean -- an allow dressed up as a check.
			name: "profile that inspects nothing",
			yaml: "version: 1\nname: t\ninspection:\n  profiles:\n    p:\n      provider: privacy_filter\n",
			want: "inspects nothing",
		},
		{
			name: "bad profile action",
			yaml: "version: 1\nname: t\ninspection:\n  profiles:\n    p:\n      provider: privacy_filter\n      categories: [secret]\n      action: shred\n",
			want: "action must be one of",
		},
		{
			name: "query with no id",
			yaml: "version: 1\nname: t\ninspection:\n  profiles:\n    p:\n      provider: shieldstral\n      queries:\n        - text: \"is it bad?\"\n",
			want: "id is required",
		},
		{
			name: "duplicate query id",
			yaml: "version: 1\nname: t\ninspection:\n  profiles:\n    p:\n      provider: shieldstral\n      queries:\n        - id: q\n          text: \"a?\"\n        - id: q\n          text: \"b?\"\n",
			want: "duplicate id",
		},
		{
			name: "threshold out of range",
			yaml: "version: 1\nname: t\ninspection:\n  profiles:\n    p:\n      provider: shieldstral\n      queries:\n        - id: q\n          text: \"a?\"\n          threshold: 1.5\n",
			want: "threshold must be between 0 and 1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := LoadFromBytes([]byte(c.yaml))
			if err == nil {
				err = p.Validate()
			}
			if err == nil {
				t.Fatalf("policy was accepted; expected an error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

// TestRequiresInspection_FalseWithoutInspectRules keeps the server-side gate
// honest: if this returned true for ordinary policies, a server would refuse
// to install every policy for want of an inspector it does not need.
func TestRequiresInspection_FalseWithoutInspectRules(t *testing.T) {
	p, err := loadInspectPolicy(t, `
file_rules:
  - name: r
    paths: ["/tmp/**"]
    operations: [read]
    decision: allow
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	if p.RequiresInspection() {
		t.Error("RequiresInspection() = true for a policy with no inspect rules, despite the profiles block")
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.RequiresInspection() {
		t.Error("Engine.RequiresInspection() = true for a policy with no inspect rules")
	}
}

// TestDecisionStrictness_Inspect pins inspect alongside approve. CheckCommand
// uses this ranking to decide whether a rule matched on an inner `sh -c`
// command overrides the outer shell's. If inspect ranked at 0 with allow, an
// inspect rule on the inner command would lose to an allow on the shell and
// never run.
func TestDecisionStrictness_Inspect(t *testing.T) {
	if got, want := decisionStrictness(types.DecisionInspect), decisionStrictness(types.DecisionApprove); got != want {
		t.Errorf("strictness(inspect) = %d, strictness(approve) = %d; want equal", got, want)
	}
	if decisionStrictness(types.DecisionInspect) <= decisionStrictness(types.DecisionAllow) {
		t.Error("inspect must outrank allow, or an inspect rule on an inner sh -c command is discarded")
	}
	if decisionStrictness(types.DecisionInspect) >= decisionStrictness(types.DecisionDeny) {
		t.Error("inspect must not outrank deny")
	}
}

// TestSetInspector round-trips the injection point. The engine holds the
// inspector but does not call it: wrapRuleDecision has no content, so
// resolution belongs to the content-holding callers added later.
func TestSetInspector(t *testing.T) {
	e, err := NewEngine(&Policy{Version: 1, Name: "t"}, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.Inspector() != nil {
		t.Error("a fresh engine reported an inspector")
	}
	ic := stubInspector{}
	e.SetInspector(ic)
	if e.Inspector() == nil {
		t.Fatal("SetInspector did not install the inspector")
	}
	e.SetInspector(nil)
	if e.Inspector() != nil {
		t.Error("SetInspector(nil) did not clear the inspector")
	}
}

// TestInspectSpec_ReachesEveryRuleKind covers each of the five rule-match
// sites that had to be switched from wrapDecision to wrapRuleDecision. Missing
// one would leave that path silently allowing content nobody inspected --
// exactly the failure this decision exists to prevent, and invisible without a
// per-path assertion.
func TestInspectSpec_ReachesEveryRuleKind(t *testing.T) {
	p, err := loadInspectPolicy(t, `
file_rules:
  - name: f
    paths: ["/workspace/**"]
    operations: [write]
    decision: inspect
    inspect:
      profiles: [pii]
network_rules:
  - name: n
    domains: ["example.com"]
    ports: [443]
    decision: inspect
    inspect:
      profiles: [exfil]
command_rules:
  - name: c
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [exfil]
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name string
		dec  Decision
	}{
		{"CheckFile", e.CheckFile("/workspace/a.txt", "write")},
		{"CheckNetwork", e.CheckNetwork("example.com", 443)},
		{"CheckNetworkIP", e.CheckNetworkIP("example.com", net.ParseIP("93.184.216.34"), 443)},
		{"CheckCommand", e.CheckCommand("curl", []string{"https://example.com"})},
		{"CheckExecve", e.CheckExecve("/usr/bin/curl", []string{"curl", "https://example.com"}, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.dec.PolicyDecision != types.DecisionInspect {
				t.Fatalf("PolicyDecision = %q, want inspect (rule %q)", c.dec.PolicyDecision, c.dec.Rule)
			}
			if c.dec.EffectiveDecision != types.DecisionDeny {
				t.Errorf("EffectiveDecision = %q, want deny", c.dec.EffectiveDecision)
			}
			if c.dec.Inspect == nil {
				t.Error("inspect spec was dropped on this path; the caller cannot run inspection")
			}
		})
	}
}
