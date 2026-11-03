package pkgcheck

import (
	"testing"

	"github.com/diffsec/agentmon/internal/policy"
)

// TestComposeRules_CatchAllLast: agent-default ends with an allow for
// every finding. A stricter block_on must still block, so the catch-all moves
// after the block_on rules.
func TestComposeRules_CatchAllLast(t *testing.T) {
	policyRules := []policy.PackageRule{
		{Match: policy.PackageMatch{FindingType: "malware"}, Action: "block"},
		{Match: policy.PackageMatch{}, Action: "allow"},
	}
	// What config.CompileBlockOnRules gives for block_on.vulnerability=high.
	blockOn := []policy.PackageRule{
		{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
		{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "deny"},
	}
	rules := ComposeRules(policyRules, blockOn)
	if last := rules[len(rules)-1]; last.Action != "allow" || !IsCatchAllRule(last) {
		t.Fatalf("last rule = %+v, want the policy's catch-all allow", last)
	}

	e := NewEvaluator(rules)
	high := Finding{Type: FindingVulnerability, Severity: SeverityHigh,
		Package: PackageRef{Name: "x"}}
	if v := e.Evaluate([]Finding{high}, EcosystemPyPI); v.Action != VerdictBlock {
		t.Errorf("high vulnerability with block_on.vulnerability=high: %s, want block", v.Action)
	}
	license := Finding{Type: FindingLicense, Severity: SeverityInfo,
		Package: PackageRef{Name: "x"}}
	if v := e.Evaluate([]Finding{license}, EcosystemPyPI); v.Action != VerdictAllow {
		t.Errorf("license unknown: %s, want allow", v.Action)
	}
}

// TestComposeRules_NoCatchAll keeps a policy without a catch-all in
// order, so the evaluator's default deny still applies to it.
func TestComposeRules_NoCatchAll(t *testing.T) {
	policyRules := []policy.PackageRule{{Match: policy.PackageMatch{FindingType: "malware"}, Action: "block"}}
	blockOn := []policy.PackageRule{{Match: policy.PackageMatch{FindingType: "license"}, Action: "deny"}}
	rules := ComposeRules(policyRules, blockOn)
	if len(rules) != 2 || rules[0].Match.FindingType != "malware" || rules[1].Match.FindingType != "license" {
		t.Errorf("rules = %+v", rules)
	}
}
