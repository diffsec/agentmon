package policy

import (
	"strings"
	"testing"

	"github.com/diffsec/agentmon/pkg/types"
)

// TestCheckMCPTool_NoRuleAllows pins the one place this rule kind departs from
// every other Check* in the engine.
//
// mcp_inspect_rules select what is inspected. They do not decide whether a
// tool may be called: that is mcp_rules / sandbox.mcp, evaluated by
// mcpinspect.PolicyEvaluator, which fails closed on its own under
// `tool_policy: allowlist`. A default deny here would mean an operator who
// adds one inspection rule silently blocks every tool call the rule does not
// name -- in a deployment where MCP was working a moment earlier.
func TestCheckMCPTool_NoRuleAllows(t *testing.T) {
	p, err := loadInspectPolicy(t, `
mcp_inspect_rules:
  - name: inspect-fetch-args
    tools: ["web_fetch"]
    decision: inspect
    inspect:
      profiles: [pii]
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	dec := e.CheckMCPTool("files", "read_file")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("EffectiveDecision = %q for an unmatched tool, want allow; a deny here blocks every unnamed tool call", dec.EffectiveDecision)
	}
	if dec.Inspect != nil {
		t.Error("an unmatched tool carries an inspection spec; nothing should be inspected")
	}
}

// TestCheckMCPTool_MatchIsEffectivelyDeny is the fail-closed half. A matched
// rule must present as deny until a caller holding the arguments resolves it,
// exactly like every other inspect-bearing decision.
func TestCheckMCPTool_MatchIsEffectivelyDeny(t *testing.T) {
	p, err := loadInspectPolicy(t, `
mcp_inspect_rules:
  - name: inspect-fetch-args
    servers: ["web*"]
    tools: ["web_fetch"]
    decision: inspect
    inspect:
      profiles: [pii]
      on_violation: redact
      timeout: 3s
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	dec := e.CheckMCPTool("websearch", "web_fetch")
	if dec.PolicyDecision != types.DecisionInspect {
		t.Errorf("PolicyDecision = %q, want inspect", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny; an unresolved inspection must not permit the call", dec.EffectiveDecision)
	}
	if dec.Inspect == nil {
		t.Fatal("no inspection spec attached")
	}
	if dec.Inspect.OnViolation != "redact" {
		t.Errorf("OnViolation = %q, want redact", dec.Inspect.OnViolation)
	}
	if dec.Inspect.OnFailure != "fail_closed" {
		t.Errorf("OnFailure = %q, want the fail_closed default", dec.Inspect.OnFailure)
	}
	if dec.Inspect.TimeoutMS != 3000 {
		t.Errorf("TimeoutMS = %d, want 3000", dec.Inspect.TimeoutMS)
	}
	if dec.Inspect.CleanDecision != types.DecisionAllow {
		t.Errorf("CleanDecision = %q, want allow; a clean inspection must let the call through", dec.Inspect.CleanDecision)
	}
}

// TestCheckMCPTool_Matching sweeps the selector. An empty Servers or Tools
// list means "every one of them": a rule listing only tools has to apply
// across servers, and getting that backwards would make such a rule match
// nothing while looking correct.
func TestCheckMCPTool_Matching(t *testing.T) {
	p, err := loadInspectPolicy(t, `
mcp_inspect_rules:
  - name: any-server-fetch
    tools: ["web_*"]
    decision: inspect
    inspect: {profiles: [pii]}
  - name: files-server-anything
    servers: ["files"]
    decision: inspect
    inspect: {profiles: [pii]}
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		server, tool string
		wantRule     string
	}{
		{"anything", "web_fetch", "any-server-fetch"},
		{"anything", "web_search", "any-server-fetch"},
		{"files", "read_file", "files-server-anything"},
		{"files", "web_fetch", "any-server-fetch"}, // first match wins
		{"other", "read_file", "no-mcp-inspect-rule"},
		// Server IDs and tool names come from whatever MCP server is
		// configured, and mcpinspect's own matcher is case-insensitive.
		// Two matchers over the same names disagreeing on case is a quiet
		// way for one to fire and the other not.
		{"FILES", "READ_FILE", "files-server-anything"},
		{"anything", "WEB_FETCH", "any-server-fetch"},
	}
	for _, c := range cases {
		dec := e.CheckMCPTool(c.server, c.tool)
		if dec.Rule != c.wantRule {
			t.Errorf("CheckMCPTool(%q, %q) matched rule %q, want %q", c.server, c.tool, dec.Rule, c.wantRule)
		}
	}
}

// TestMCPInspectRules_RejectAuthorisationDecisions. Accepting `decision: allow`
// would read as an allowlist, and because CheckMCPTool falls through to allow
// every tool the list did not name would still run. Rejecting the word is
// what stops the block from being written that way at all.
func TestMCPInspectRules_RejectAuthorisationDecisions(t *testing.T) {
	for _, decision := range []string{"allow", "deny", "approve", "audit", "redirect"} {
		_, err := loadInspectPolicy(t, `
mcp_inspect_rules:
  - name: r
    tools: ["*"]
    decision: `+decision+`
    inspect: {require: true, profiles: [pii]}
`)
		if err == nil {
			t.Errorf("decision %q was accepted on mcp_inspect_rules; it must be rejected", decision)
			continue
		}
		if !strings.Contains(err.Error(), "must be inspect") {
			t.Errorf("decision %q rejected with an unhelpful error: %v", decision, err)
		}
	}
}

// TestMCPInspectRules_Validation covers the rest of the load-time gate. Each
// of these reaching the engine instead would produce a rule that fails closed
// at the first tool call with nothing in the log to explain it.
func TestMCPInspectRules_Validation(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{
			name: "undefined profile",
			yaml: `
mcp_inspect_rules:
  - name: r
    decision: inspect
    inspect: {profiles: [nope]}
`,
			want: "undefined profile",
		},
		{
			name: "no profiles",
			yaml: `
mcp_inspect_rules:
  - name: r
    decision: inspect
    inspect: {profiles: []}
`,
			want: "at least one profile",
		},
		{
			name: "no inspect block",
			yaml: `
mcp_inspect_rules:
  - name: r
    decision: inspect
`,
			want: "requires an inspect block",
		},
		{
			name: "bad on_violation",
			yaml: `
mcp_inspect_rules:
  - name: r
    decision: inspect
    inspect: {profiles: [pii], on_violation: shrug}
`,
			want: "on_violation must be one of",
		},
		{
			name: "bad on_failure",
			yaml: `
mcp_inspect_rules:
  - name: r
    decision: inspect
    inspect: {profiles: [pii], on_failure: maybe}
`,
			want: "on_failure must be one of",
		},
		{
			name: "invalid glob",
			yaml: `
mcp_inspect_rules:
  - name: r
    tools: ["["]
    decision: inspect
    inspect: {profiles: [pii]}
`,
			want: "invalid glob",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadInspectPolicy(t, c.yaml)
			if err == nil {
				t.Fatal("policy was accepted; it must be rejected at load time")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestMCPInspectRules_CountedByInspectionAccounting. internal/server refuses
// to install a policy whose profiles the host cannot run
// (wireInspection). If mcp_inspect_rules are invisible to that accounting,
// such a policy installs and every MCP tool call it names fails closed at
// runtime instead of failing at startup where an operator would see it.
func TestMCPInspectRules_CountedByInspectionAccounting(t *testing.T) {
	p, err := loadInspectPolicy(t, `
mcp_inspect_rules:
  - name: r
    tools: ["web_fetch"]
    decision: inspect
    inspect: {profiles: [pii, exfil]}
`)
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	if !p.RequiresInspection() {
		t.Error("RequiresInspection() = false for a policy whose only inspect rule is an mcp_inspect_rule")
	}
	got := p.InspectionProfilesUsed()
	if len(got) != 2 || got[0] != "exfil" || got[1] != "pii" {
		t.Errorf("InspectionProfilesUsed() = %v, want [exfil pii]", got)
	}
}
