package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/policy"
)

func TestRoot_WiresPolicyAndConfig(t *testing.T) {
	root := NewRoot("test")
	foundPolicy := false
	foundConfig := false
	for _, c := range root.Commands() {
		if c.Name() == "policy" {
			foundPolicy = true
		}
		if c.Name() == "config" {
			foundConfig = true
		}
	}
	if !foundPolicy {
		t.Fatalf("expected policy command to be registered")
	}
	if !foundConfig {
		t.Fatalf("expected config command to be registered")
	}
}

func TestPolicyValidate_PrintsDBWarnings(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	writeFile(t, policyPath, `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: x:1
    tls_mode: terminate_reissue
database_rules:
  - name: canonical-read
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    decision: allow
`)

	root := NewRoot("test")
	var out bytes.Buffer
	var errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"policy", "validate", policyPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "ok") {
		t.Fatalf("stdout = %q, want ok", out.String())
	}
	if !strings.Contains(errOut.String(), "warning[canonical_selector_without_resolution_guard]") {
		t.Fatalf("stderr = %q, want canonical selector warning", errOut.String())
	}
}

func TestMacOSPolicyWarnings(t *testing.T) {
	p := &policy.Policy{
		FileRules: []policy.FileRule{
			{Name: "redir", Decision: "redirect"},
			{Name: "soft", Decision: "soft_delete"},
			{Name: "ask", Decision: "approve"},
			{Name: "ok", Decision: "allow"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "net-redir", Decision: "redirect"},
			{Name: "net-ask", Decision: "approve"},
		},
		DnsRedirectRules: []policy.DnsRedirectRule{{Name: "dns"}},
		UnixRules: []policy.UnixSocketRule{
			{Name: "unix-ask", Decision: "approve", Operations: []string{"connect"}},
			{Name: "unix-sendto", Decision: "deny", Operations: []string{"connect", "sendto"}},
			{Name: "unix-ok", Decision: "deny", Operations: []string{"connect", "bind"}},
		},
		SignalRules: []policy.SignalRule{
			{Name: "sig-absorb", Decision: "absorb"},
			{Name: "sig-redirect", Decision: "redirect", Fallback: "deny"},
			{Name: "sig-deny", Decision: "deny"},
		},
	}
	got := strings.Join(macOSPolicyWarnings(p), "\n")
	for _, want := range []string{"rule=redir:", "rule=soft:", "rule=net-redir:", "rule=dns:",
		"rule=unix-ask:", "rule=unix-sendto: unix socket operation \"sendto\"", "rule=sig-absorb:",
		"rule=sig-redirect: signal decision \"redirect\" is not possible on macOS; the fallback \"deny\""} {
		if !strings.Contains(got, want) {
			t.Errorf("warnings miss %q:\n%s", want, got)
		}
	}
	// approve works on macOS, through the approval dialog.
	for _, notWant := range []string{"rule=ask:", "rule=ok:", "rule=net-ask:", "rule=unix-ok:", "rule=sig-deny:"} {
		if strings.Contains(got, notWant) {
			t.Errorf("warnings include %q:\n%s", notWant, got)
		}
	}
}

func TestMacOSResolverSocketWarning(t *testing.T) {
	sys := policy.UnixSocketRule{Name: "deny-system-sockets", Paths: []string{"/var/run/**"}, Operations: []string{"connect"}, Decision: "deny"}
	dns := policy.UnixSocketRule{Name: "allow-dns", Paths: []string{"/var/run/mDNSResponder"}, Operations: []string{"connect"}, Decision: "allow"}
	realPath := policy.UnixSocketRule{Name: "allow-dns-real", Paths: []string{"/private/var/run/mDNSResponder"}, Decision: "audit"}
	for _, c := range []struct {
		name  string
		rules []policy.UnixSocketRule
		want  string
	}{
		{"no socket rules", nil, ""},
		{"denied by a rule", []policy.UnixSocketRule{sys}, "rule=deny-system-sockets:"},
		{"denied by the default", []policy.UnixSocketRule{{Name: "tmp", Paths: []string{"/tmp/**"}, Decision: "allow"}}, "rule=default-deny-unix:"},
		{"allowed first", []policy.UnixSocketRule{dns, sys}, ""},
		{"allowed after the deny", []policy.UnixSocketRule{sys, dns}, "rule=deny-system-sockets:"},
		{"real path audited", []policy.UnixSocketRule{realPath, sys}, ""},
	} {
		got := macOSResolverSocketWarning(&policy.Policy{Version: 1, UnixRules: c.rules})
		if c.want == "" && got != "" || c.want != "" && !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: warning = %q, want prefix %q", c.name, got, c.want)
		}
	}
}

// The shipped agent-default policy must not trigger the warning.
func TestMacOSResolverSocketWarning_AgentDefault(t *testing.T) {
	p, err := policy.LoadFromFile(filepath.Join("..", "..", "configs", "policies", "agent-default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if w := macOSResolverSocketWarning(p); w != "" {
		t.Fatalf("agent-default: %s", w)
	}
}

func TestMacOSResourceLimitWarnings(t *testing.T) {
	got := strings.Join(macOSResourceLimitWarnings(policy.ResourceLimits{
		MaxMemoryMB: 512, CPUQuotaPercent: 50, PidsMax: 32,
	}), "\n")
	for _, want := range []string{"max_memory_mb is not enforced", "cpu_quota_percent is not enforced",
		"pids_max stops an exec on macOS, not a fork"} {
		if !strings.Contains(got, want) {
			t.Errorf("warnings miss %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "disk_read_bps_max") || strings.Contains(got, "net_bandwidth_mbps") {
		t.Errorf("warnings name a limit that the policy does not set:\n%s", got)
	}
	if w := macOSResourceLimitWarnings(policy.ResourceLimits{}); len(w) != 0 {
		t.Errorf("no limits gave warnings: %v", w)
	}
}
