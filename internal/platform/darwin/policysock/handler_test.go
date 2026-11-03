//go:build darwin

package policysock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/pkgcheck"
	"github.com/diffsec/agentmon/internal/policy"
)

func TestPolicyAdapter_CheckFile_Allow(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}

	adapter := NewPolicyAdapter(engine, nil)
	allow, rule := adapter.CheckFile("/test/file.txt", "read")

	if !allow {
		t.Error("expected allow=true")
	}
	if rule != "allow-all" {
		t.Errorf("rule: got %q, want %q", rule, "allow-all")
	}
}

func TestPolicyAdapter_CheckFile_Deny(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "deny-secrets", Paths: []string{"/etc/passwd"}, Operations: []string{"*"}, Decision: "deny"},
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}

	adapter := NewPolicyAdapter(engine, nil)
	allow, rule := adapter.CheckFile("/etc/passwd", "read")

	if allow {
		t.Error("expected allow=false")
	}
	if rule != "deny-secrets" {
		t.Errorf("rule: got %q, want %q", rule, "deny-secrets")
	}
}

func TestPolicyAdapter_CheckNetwork(t *testing.T) {
	t.Run("allow with domain", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			NetworkRules: []policy.NetworkRule{
				{Name: "allow-example", Domains: []string{"example.com"}, Ports: []int{443}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckNetwork("1.2.3.4", 443, "example.com")

		if !allow {
			t.Error("expected allow=true")
		}
		if rule != "allow-example" {
			t.Errorf("rule: got %q, want %q", rule, "allow-example")
		}
	})

	t.Run("allow with IP (no domain)", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			NetworkRules: []policy.NetworkRule{
				{Name: "allow-ip", CIDRs: []string{"10.0.0.0/8"}, Ports: []int{80}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckNetwork("10.1.2.3", 80, "")

		if !allow {
			t.Error("expected allow=true")
		}
		if rule != "allow-ip" {
			t.Errorf("rule: got %q, want %q", rule, "allow-ip")
		}
	})

	t.Run("domain takes precedence over IP", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			NetworkRules: []policy.NetworkRule{
				{Name: "allow-domain", Domains: []string{"api.example.com"}, Ports: []int{443}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		// Even with an IP, domain should be used for matching
		allow, rule := adapter.CheckNetwork("93.184.216.34", 443, "api.example.com")

		if !allow {
			t.Error("expected allow=true when domain matches")
		}
		if rule != "allow-domain" {
			t.Errorf("rule: got %q, want %q", rule, "allow-domain")
		}
	})
}

func TestPolicyAdapter_CheckCommand(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "allow-ls", Commands: []string{"ls"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckCommand("ls", []string{"-la"})

		if !allow {
			t.Error("expected allow=true")
		}
		if rule != "allow-ls" {
			t.Errorf("rule: got %q, want %q", rule, "allow-ls")
		}
	})

	t.Run("deny", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckCommand("rm", []string{"-rf", "/"})

		if allow {
			t.Error("expected allow=false")
		}
		if rule != "deny-rm" {
			t.Errorf("rule: got %q, want %q", rule, "deny-rm")
		}
	})
}

func TestPolicyAdapter_CheckExec(t *testing.T) {
	t.Run("allow_returns_continue", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "allow-ls", Commands: []string{"ls"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("ls", []string{"-la"}, 1234, 1, "session-1", ExecContext{})

		if result.Decision != "allow" {
			t.Errorf("decision: got %q, want %q", result.Decision, "allow")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q", result.Action, "continue")
		}
		if result.Rule != "allow-ls" {
			t.Errorf("rule: got %q, want %q", result.Rule, "allow-ls")
		}
	})

	t.Run("deny_returns_deny", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("rm", []string{"-rf", "/"}, 5678, 1, "session-1", ExecContext{})

		if result.Decision != "deny" {
			t.Errorf("decision: got %q, want %q", result.Decision, "deny")
		}
		if result.Action != "deny" {
			t.Errorf("action: got %q, want %q", result.Action, "deny")
		}
		if result.Rule != "deny-rm" {
			t.Errorf("rule: got %q, want %q", result.Rule, "deny-rm")
		}
	})

	t.Run("redirect_enforced_returns_redirect", func(t *testing.T) {
		// Redirect policy with enforceRedirects=true: both PolicyDecision and
		// EffectiveDecision are "redirect", so action = "redirect".
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "redirect-git", Commands: []string{"git"}, Decision: "redirect"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("git", []string{"push"}, 9999, 1, "session-1", ExecContext{})

		if result.Decision != "redirect" {
			t.Errorf("decision: got %q, want %q", result.Decision, "redirect")
		}
		if result.Action != "redirect" {
			t.Errorf("action: got %q, want %q (enforceRedirects=true)", result.Action, "redirect")
		}
		if result.Rule != "redirect-git" {
			t.Errorf("rule: got %q, want %q", result.Rule, "redirect-git")
		}
	})

	t.Run("audit_returns_continue", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "audit-curl", Commands: []string{"curl"}, Decision: "audit"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("curl", []string{"https://example.com"}, 2222, 1, "session-1", ExecContext{})

		if result.Decision != "audit" {
			t.Errorf("decision: got %q, want %q", result.Decision, "audit")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q", result.Action, "continue")
		}
		if result.Rule != "audit-curl" {
			t.Errorf("rule: got %q, want %q", result.Rule, "audit-curl")
		}
	})

	t.Run("approve_shadow_mode_returns_continue", func(t *testing.T) {
		// In shadow mode (enforceApprovals=false), PolicyDecision is "approve"
		// but EffectiveDecision is "allow", so the action should be "continue".
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("sudo", []string{"ls"}, 3333, 1, "session-1", ExecContext{})

		if result.Decision != "approve" {
			t.Errorf("decision: got %q, want %q", result.Decision, "approve")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q (shadow mode should continue, not redirect)", result.Action, "continue")
		}
		if result.Rule != "approve-sudo" {
			t.Errorf("rule: got %q, want %q", result.Rule, "approve-sudo")
		}
	})

	t.Run("approve_enforced_without_approvals_denies", func(t *testing.T) {
		// In enforced mode (enforceApprovals=true), both PolicyDecision and
		// EffectiveDecision are "approve". With no approval manager, nobody
		// can approve, so the exec is denied, as the Go engine does.
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, true, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("sudo", []string{"ls"}, 3333, 1, "session-1", ExecContext{})

		if result.Decision != "approve" {
			t.Errorf("decision: got %q, want %q", result.Decision, "approve")
		}
		if result.Action != "deny" {
			t.Errorf("action: got %q, want %q", result.Action, "deny")
		}
		if result.Rule != "approve-sudo" {
			t.Errorf("rule: got %q, want %q", result.Rule, "approve-sudo")
		}
	})
}

// mockSessionResolver implements SessionResolver for testing.
type mockSessionResolver struct {
	sessions map[int32]string
}

func (m *mockSessionResolver) SessionForPID(pid int32) string {
	if m.sessions == nil {
		return ""
	}
	return m.sessions[pid]
}

func (m *mockSessionResolver) LatestSession() (string, int32) {
	for pid, sid := range m.sessions {
		return sid, pid
	}
	return "", 0
}

func (m *mockSessionResolver) RootPIDForSession(sessionID string) int32 {
	for pid, sid := range m.sessions {
		if sid == sessionID {
			return pid
		}
	}
	return 0
}

func (m *mockSessionResolver) RootPIDsForSession(sessionID string) []int32 {
	if pid := m.RootPIDForSession(sessionID); pid != 0 {
		return []int32{pid}
	}
	return nil
}

func (m *mockSessionResolver) NoteSnapshotDelivered(string, []int32) {}

func (m *mockSessionResolver) ActiveSessions() []string {
	seen := make(map[string]struct{}, len(m.sessions))
	var out []string
	for _, sid := range m.sessions {
		if _, dup := seen[sid]; dup {
			continue
		}
		seen[sid] = struct{}{}
		out = append(out, sid)
	}
	return out
}

func TestPolicyAdapter_ResolveSession(t *testing.T) {
	t.Run("nil resolver returns empty", func(t *testing.T) {
		adapter := NewPolicyAdapter(nil, nil)
		session := adapter.ResolveSession(1234)

		if session != "" {
			t.Errorf("expected empty session, got %q", session)
		}
	})

	t.Run("mock resolver returns session", func(t *testing.T) {
		resolver := &mockSessionResolver{
			sessions: map[int32]string{
				1234: "session-abc",
				5678: "session-xyz",
			},
		}
		adapter := NewPolicyAdapter(nil, resolver)

		session := adapter.ResolveSession(1234)
		if session != "session-abc" {
			t.Errorf("session: got %q, want %q", session, "session-abc")
		}

		session = adapter.ResolveSession(5678)
		if session != "session-xyz" {
			t.Errorf("session: got %q, want %q", session, "session-xyz")
		}

		// Unknown PID returns empty
		session = adapter.ResolveSession(9999)
		if session != "" {
			t.Errorf("expected empty session for unknown PID, got %q", session)
		}
	})
}

// TestPolicyAdapter_NilEngine pins the fail-closed behaviour from AUDIT H5.
// This test previously asserted the opposite -- that a nil engine allowed
// everything -- which is what let the bug survive. A daemon with no policy
// installed must not wave through the system extension's checks.
//
// Denying is safe because the extension only asks about processes inside a
// tracked session: ESFClient guards its AUTH handlers on
// hasActiveSessions/sessionForPID, and SessionPolicyCache returns .allow for
// PIDs it does not know. A nil engine therefore blocks the sandboxed agent,
// not the machine.
func TestPolicyAdapter_NilEngine(t *testing.T) {
	adapter := NewPolicyAdapter(nil, nil)

	checks := []struct {
		name string
		call func() (bool, string)
	}{
		{"CheckFile", func() (bool, string) { return adapter.CheckFile("/any/path", "read") }},
		{"CheckNetwork", func() (bool, string) { return adapter.CheckNetwork("1.2.3.4", 443, "example.com") }},
		{"CheckCommand", func() (bool, string) { return adapter.CheckCommand("rm", []string{"-rf", "/"}) }},
	}
	for _, c := range checks {
		t.Run(c.name+" denies", func(t *testing.T) {
			allow, rule := c.call()
			if allow {
				t.Error("expected allow=false with nil engine (fail closed)")
			}
			if rule != "no-policy-fail-closed" {
				t.Errorf("rule: got %q, want %q", rule, "no-policy-fail-closed")
			}
		})
	}

	t.Run("ResolveSession returns empty", func(t *testing.T) {
		session := adapter.ResolveSession(1234)
		if session != "" {
			t.Errorf("expected empty session, got %q", session)
		}
	})

	t.Run("CheckExec denies", func(t *testing.T) {
		result := adapter.CheckExec("/usr/bin/ls", []string{"-la"}, 1234, 1, "session-1", ExecContext{})
		if result.Decision != "deny" {
			t.Errorf("decision: got %q, want %q", result.Decision, "deny")
		}
		if result.Action != "deny" {
			t.Errorf("action: got %q, want %q", result.Action, "deny")
		}
		if result.Rule != "no-policy-fail-closed" {
			t.Errorf("rule: got %q, want %q", result.Rule, "no-policy-fail-closed")
		}
	})
}

// TestBuildPolicySnapshot_FailsClosed pins the snapshot half of AUDIT H5.
//
// The live checks in PolicyAdapter fail closed when no policy is available, but
// BuildPolicySnapshot used to return an empty allow-everything snapshot, so the
// extension cached "permit all" for the session and stopped asking. The deny is
// carried in Defaults, which is what SessionPolicyCache actually consults --
// the top-level Allow field is never read on the Swift side.
func TestBuildPolicySnapshot_FailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		adapter *PolicyAdapter
	}{
		{"nil engine", NewPolicyAdapter(nil, nil)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := c.adapter.BuildPolicySnapshot("session-1", 0)

			if resp.Allow {
				t.Error("snapshot reports Allow=true with no policy available")
			}
			if resp.Defaults == nil {
				t.Fatal("snapshot has no Defaults; the extension would fall through to allow")
			}
			for name, got := range map[string]string{
				"file":    resp.Defaults.File,
				"network": resp.Defaults.Network,
				"dns":     resp.Defaults.DNS,
				"exec":    resp.Defaults.Exec,
			} {
				if got != "deny" {
					t.Errorf("Defaults.%s = %q, want \"deny\" -- anything else lets the extension allow", name, got)
				}
			}
			if len(resp.FileRules) != 0 || len(resp.ExecRules) != 0 || len(resp.NetworkRules) != 0 {
				t.Error("fail-closed snapshot should carry no rules; the defaults do the work")
			}
		})
	}
}

// fakePackageChecker returns one verdict and records what it was asked.
type fakePackageChecker struct {
	verdict  *pkgcheck.Verdict
	err      error
	command  string
	args     []string
	workDir  string
	deadline time.Duration
}

func (f *fakePackageChecker) CheckForPolicy(ctx context.Context, _ []policy.PackageRule, command string, args []string, workDir string) (*pkgcheck.Verdict, error) {
	f.command, f.args, f.workDir = command, args, workDir
	if d, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(d)
	}
	return f.verdict, f.err
}

// TestCheckExec_PackageInstall: an exec that the command rules allow is then
// package-checked. ES reports a script's interpreter as the executable, so
// `pip3 install x` must be classified from argv[1].
func TestCheckExec_PackageInstall(t *testing.T) {
	p := &policy.Policy{Version: 1, CommandRules: []policy.CommandRule{
		{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
	}}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	const py = "/opt/homebrew/Cellar/python@3.15/3.15.0/bin/python3.15"
	argv := []string{py, "/opt/homebrew/bin/pip3", "install", "evil"}
	ec := ExecContext{CWDPath: "/tmp/ws", Script: "/opt/homebrew/Cellar/python@3.15/3.15.0/bin/pip3", Deadline: 10 * time.Second}

	for _, c := range []struct {
		name       string
		checker    *fakePackageChecker
		wantAction string
		wantRule   string
	}{
		{"block", &fakePackageChecker{verdict: &pkgcheck.Verdict{Action: pkgcheck.VerdictBlock, Summary: "evil is malware"}}, "deny", "package-check"},
		{"allow", &fakePackageChecker{verdict: &pkgcheck.Verdict{Action: pkgcheck.VerdictAllow}}, "continue", "allow-all"},
		{"warn", &fakePackageChecker{verdict: &pkgcheck.Verdict{Action: pkgcheck.VerdictWarn}}, "continue", "allow-all"},
		{"not an install", &fakePackageChecker{}, "continue", "allow-all"},
		{"error", &fakePackageChecker{err: errors.New("pip dry-run failed")}, "deny", "package-check"},
		{"approve without approvals", &fakePackageChecker{verdict: &pkgcheck.Verdict{Action: pkgcheck.VerdictApprove}}, "deny", "package-check"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := NewPolicyAdapter(engine, nil)
			a.SetPackageChecker(c.checker)
			got := a.CheckExec(py, argv, 100, 1, "s1", ec)
			if got.Action != c.wantAction || got.Rule != c.wantRule {
				t.Errorf("CheckExec = %s by %q (%s), want %s by %q", got.Action, got.Rule, got.Message, c.wantAction, c.wantRule)
			}
			if c.checker.command != "/opt/homebrew/bin/pip3" || len(c.checker.args) != 2 || c.checker.workDir != "/tmp/ws" {
				t.Errorf("checked %s %v in %s, want /opt/homebrew/bin/pip3 [install evil] in /tmp/ws",
					c.checker.command, c.checker.args, c.checker.workDir)
			}
			if c.checker.deadline <= 0 || c.checker.deadline > 10*time.Second-packageCheckMargin {
				t.Errorf("check deadline = %s, want under %s", c.checker.deadline, 10*time.Second-packageCheckMargin)
			}
		})
	}
}

// TestCheckExec_PackageCheckSkippedOnDeny: an exec that the command rules
// deny is not package-checked.
func TestCheckExec_PackageCheckSkippedOnDeny(t *testing.T) {
	engine, err := policy.NewEngine(&policy.Policy{Version: 1}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePackageChecker{verdict: &pkgcheck.Verdict{Action: pkgcheck.VerdictAllow}}
	a := NewPolicyAdapter(engine, nil)
	a.SetPackageChecker(f)
	got := a.CheckExec("/usr/bin/pip3", []string{"/usr/bin/pip3", "install", "x"}, 100, 1, "s1", ExecContext{})
	if got.Action != "deny" || f.command != "" {
		t.Errorf("CheckExec = %s, checker asked for %q; want deny with no package check", got.Action, f.command)
	}
}

func TestInstallCommand(t *testing.T) {
	cmd, args := installCommand("/usr/local/bin/uv", []string{"uv", "pip", "install", "x"}, "")
	if cmd != "/usr/local/bin/uv" || len(args) != 3 {
		t.Errorf("binary: %s %v", cmd, args)
	}
	cmd, args = installCommand("/usr/bin/python3", []string{"python3", "/usr/local/bin/pip3", "install", "x"}, "/usr/local/bin/pip3")
	if cmd != "/usr/local/bin/pip3" || len(args) != 2 {
		t.Errorf("script: %s %v", cmd, args)
	}
}
