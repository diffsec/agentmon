package policy

import (
	"slices"
	"testing"
)

func TestStripVersionSuffix(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"python3.15", "python3"},
		{"pip3.15", "pip3"},
		{"perl5.34.1", "perl5"},
		{"python3", "python3"},
		{"node", "node"},
		{"bash.real", "bash.real"},
		{"tar.gz", "tar.gz"},
		{"1.2", "1.2"},
		{"v1.2", "v1"},
		{"x.", "x."},
		{".15", ".15"},
	} {
		if got := stripVersionSuffix(c.in); got != c.want {
			t.Errorf("stripVersionSuffix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCommandNameForms(t *testing.T) {
	if got := commandNameForms("python3.15"); !slices.Equal(got, []string{"python3.15", "python3"}) {
		t.Errorf("python3.15: %v", got)
	}
	if got := commandNameForms("bash.real"); !slices.Equal(got, []string{"bash.real", "bash"}) {
		t.Errorf("bash.real: %v", got)
	}
	if got := commandNameForms("git"); !slices.Equal(got, []string{"git"}) {
		t.Errorf("git: %v", got)
	}
}

// TestVersionedInterpreterMatchesRule covers SECENG-311. On macOS, ES
// reports the resolved executable. Homebrew's python3 resolves to
// .../bin/python3.15, which agent-default denied as default-deny-commands,
// so python3 died under `agentmon wrap`. A deny rule must match the
// versioned name too.
func TestVersionedInterpreterMatchesRule(t *testing.T) {
	p := &Policy{Version: 1, CommandRules: []CommandRule{
		{Name: "deny-perl", Commands: []string{"perl5"}, Decision: "deny"},
		{Name: "allow-python", Commands: []string{"python3"}, Decision: "allow"},
	}}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	const py = "/opt/homebrew/Cellar/python@3.15/3.15.0/bin/python3.15"
	for _, c := range []struct {
		name, cmd, rule, decision string
	}{
		{"CheckCommand", py, "allow-python", "allow"},
		{"CheckCommand", "/usr/bin/perl5.34", "deny-perl", "deny"},
	} {
		d := e.CheckCommand(c.cmd, []string{c.cmd})
		if d.Rule != c.rule || string(d.PolicyDecision) != c.decision {
			t.Errorf("CheckCommand(%s) = %s by %q, want %s by %q", c.cmd, d.PolicyDecision, d.Rule, c.decision, c.rule)
		}
	}
	if d := e.CheckExecve(py, []string{py}, 0); d.Rule != "allow-python" {
		t.Errorf("CheckExecve(%s) = %s by %q, want allow by allow-python", py, d.PolicyDecision, d.Rule)
	}
}
