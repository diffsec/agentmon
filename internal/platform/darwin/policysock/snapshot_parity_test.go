//go:build darwin

package policysock

import (
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/diffsec/agentmon/internal/policy"
)

func snapshotFor(t *testing.T, p *policy.Policy) PolicyResponse {
	t.Helper()
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	return NewPolicyAdapter(engine, nil).BuildPolicySnapshot("s1", 0)
}

func TestBuildPolicySnapshot_KeepsNetworkRulesWhole(t *testing.T) {
	resp := snapshotFor(t, &policy.Policy{Version: 1, NetworkRules: []policy.NetworkRule{
		{Name: "both", Domains: []string{"a.test", "b.test"}, CIDRs: []string{"10.0.0.0/8"}, Ports: []int{443}, Decision: "allow"},
		{Name: "port-only", Ports: []int{443}, Decision: "approve"},
	}})
	if len(resp.NetworkRules) != 2 {
		t.Fatalf("got %d network rules, want one for each policy rule: %+v", len(resp.NetworkRules), resp.NetworkRules)
	}
	both := resp.NetworkRules[0]
	if both.Name != "both" || len(both.Domains) != 2 || len(both.CIDRs) != 1 || len(both.Ports) != 1 {
		t.Errorf("rule with domains and CIDRs = %+v, want both lists in one rule", both)
	}
	portOnly := resp.NetworkRules[1]
	if portOnly.Name != "port-only" || portOnly.Action != "approve" || len(portOnly.Ports) != 1 {
		t.Errorf("port-only rule = %+v, want it kept", portOnly)
	}
}

func TestBuildPolicySnapshot_SendsTheEngineDefaults(t *testing.T) {
	resp := snapshotFor(t, &policy.Policy{Version: 1})
	if resp.Defaults == nil || resp.Defaults.File != "deny" || resp.Defaults.Network != "deny" {
		t.Fatalf("defaults = %+v, want file and network deny, as CheckFile and CheckNetworkIP decide", resp.Defaults)
	}
}

func TestBuildPolicySnapshot_VersionIncreases(t *testing.T) {
	p := &policy.Policy{Version: 1}
	first := snapshotFor(t, p).SnapshotVersion
	second := snapshotFor(t, p).SnapshotVersion
	if first <= 1 || second <= first {
		t.Fatalf("versions %d then %d, want each snapshot higher than the last", first, second)
	}
	if v := denyAllSnapshot("s1").SnapshotVersion; v <= second {
		t.Fatalf("deny-all snapshot version %d, want it higher than %d", v, second)
	}
}

// parityTable is testdata/policy_parity.json. The same cases run through the
// Swift matchers in scripts/test-swift-policy-parity.sh, so a decision that
// differs between Linux and macOS fails one of the two.
type parityTable struct {
	FileRules           []policy.FileRule    `json:"file_rules"`
	FileCases           []parityFileCase     `json:"file_cases"`
	FileCasesNoCatchAll []parityFileCase     `json:"file_cases_no_catch_all"`
	NetworkRules        []policy.NetworkRule `json:"network_rules"`
	NetworkCases        []parityNetworkCase  `json:"network_cases"`
}

type parityFileCase struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Want      string `json:"want"`
}

type parityNetworkCase struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Want string `json:"want"`
}

func loadParityTable(t *testing.T) parityTable {
	t.Helper()
	b, err := os.ReadFile("testdata/policy_parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var tab parityTable
	if err := json.Unmarshal(b, &tab); err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestPolicyParity_GoEngine(t *testing.T) {
	tab := loadParityTable(t)
	check := func(name string, rules []policy.FileRule, cases []parityFileCase) {
		engine, err := policy.NewEngine(&policy.Policy{Version: 1, FileRules: rules, NetworkRules: tab.NetworkRules}, false, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			if got := string(engine.CheckFile(c.Path, c.Operation).PolicyDecision); got != c.Want {
				t.Errorf("%s: file %s %s = %s, want %s", name, c.Operation, c.Path, got, c.Want)
			}
		}
	}
	check("file_cases", tab.FileRules, tab.FileCases)
	check("file_cases_no_catch_all", tab.FileRules[:len(tab.FileRules)-1], tab.FileCasesNoCatchAll)

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, NetworkRules: tab.NetworkRules}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tab.NetworkCases {
		domain := c.Host
		if domain == "" {
			domain = c.IP
		}
		if got := string(engine.CheckNetworkIP(domain, net.ParseIP(c.IP), c.Port).PolicyDecision); got != c.Want {
			t.Errorf("network %s (%s) port %d = %s, want %s", c.Host, c.IP, c.Port, got, c.Want)
		}
	}
}
