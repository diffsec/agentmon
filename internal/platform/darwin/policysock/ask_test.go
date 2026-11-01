//go:build darwin

package policysock

import (
	"context"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/approvals"
	"github.com/diffsec/agentmon/internal/policy"
)

// askFixture is an adapter with an approve rule for each kind, and an
// approval manager whose dialog sends each request to launched.
func askFixture(t *testing.T) (*PolicyAdapter, *approvals.Manager, chan approvals.Request) {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "approve-secrets", Paths: []string{"/w/secret/**"}, Operations: []string{"write"}, Decision: "approve"},
			{Name: "allow-w", Paths: []string{"/w/**"}, Decision: "allow"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "approve-https", Ports: []int{443}, Decision: "approve"},
			{Name: "deny-rest", Domains: []string{"**"}, Decision: "deny"},
		},
		CommandRules: []policy.CommandRule{
			{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
		},
	}
	engine, err := policy.NewEngine(p, true, true)
	if err != nil {
		t.Fatal(err)
	}
	m := approvals.New("gui", 5*time.Second, nil)
	launched := make(chan approvals.Request, 8)
	m.SetLauncher(func(_ context.Context, req approvals.Request) error {
		launched <- req
		return nil
	})
	m.SetGrantTTL(time.Minute)
	a := NewPolicyAdapter(engine, nil)
	a.SetApprovals(m)
	return a, m, launched
}

func expectDialog(t *testing.T, launched chan approvals.Request) approvals.Request {
	t.Helper()
	select {
	case r := <-launched:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("no dialog opened")
		return approvals.Request{}
	}
}

func expectNoDialog(t *testing.T, launched chan approvals.Request) {
	t.Helper()
	select {
	case r := <-launched:
		t.Fatalf("a dialog opened for %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
}

// waitGranted waits for the grant that follows an approval.
func waitGranted(t *testing.T, m *approvals.Manager, kind, target, op string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !m.Granted("s1", kind, target, op) {
		if time.Now().After(deadline) {
			t.Fatalf("no grant for %s %s %s", kind, target, op)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAskApproval_FileGrantReachesTheSnapshotFirst(t *testing.T) {
	a, m, launched := askFixture(t)
	path := "/w/secret/a*b.txt"

	resp := a.AskApproval(&PolicyRequest{Type: RequestTypeRequestApproval, Kind: "file", SessionID: "s1", Path: path, Operation: "write", PID: 42})
	if !resp.Success {
		t.Fatalf("AskApproval = %+v", resp)
	}
	req := expectDialog(t, launched)
	if req.Kind != "file" || req.Target != path || req.Rule != "approve-secrets" || req.Fields["operation"] != "write" || req.Fields["pid"] != "42" {
		t.Fatalf("dialog request = %+v", req)
	}
	m.Resolve(req.ID, true, "approved")
	waitGranted(t, m, "file", path, "write")

	snap := a.BuildPolicySnapshot("s1", 0)
	if len(snap.FileRules) == 0 {
		t.Fatal("snapshot has no file rules")
	}
	first := snap.FileRules[0]
	if first.Pattern != `/w/secret/a\*b.txt` || first.Action != "allow" || len(first.Operations) != 1 || first.Operations[0] != "write" {
		t.Fatalf("first file rule = %+v, want the escaped grant", first)
	}
	// The policy's own rules follow, unchanged.
	if snap.FileRules[1].Pattern != "/w/secret/**" {
		t.Fatalf("second file rule = %+v", snap.FileRules[1])
	}
}

func TestAskApproval_NetworkGrantIsAnExactHostAndPort(t *testing.T) {
	a, m, launched := askFixture(t)

	a.AskApproval(&PolicyRequest{Kind: "network", SessionID: "s1", IP: "93.184.215.14", Port: 443, Domain: "Example.COM."})
	req := expectDialog(t, launched)
	if req.Target != "example.com:443" || req.Rule != "approve-https" {
		t.Fatalf("dialog request = %+v", req)
	}
	// The second address of the same host shares the dialog.
	a.AskApproval(&PolicyRequest{Kind: "network", SessionID: "s1", IP: "93.184.215.15", Port: 443, Domain: "example.com"})
	expectNoDialog(t, launched)

	m.Resolve(req.ID, true, "approved")
	waitGranted(t, m, "network", "example.com:443", "")

	snap := a.BuildPolicySnapshot("s1", 0)
	first := snap.NetworkRules[0]
	if first.Name != "approval-grant" || len(first.Domains) != 1 || first.Domains[0] != "example.com" ||
		len(first.Ports) != 1 || first.Ports[0] != 443 || first.Action != "allow" {
		t.Fatalf("first network rule = %+v", first)
	}
}

func TestAskApproval_IPOnlyFlowGrantsTheAddress(t *testing.T) {
	a, m, launched := askFixture(t)
	a.AskApproval(&PolicyRequest{Kind: "network", SessionID: "s1", IP: "2001:db8::1", Port: 443})
	req := expectDialog(t, launched)
	if req.Target != "[2001:db8::1]:443" {
		t.Fatalf("target = %q", req.Target)
	}
	m.Resolve(req.ID, true, "approved")
	waitGranted(t, m, "network", req.Target, "")
	first := a.BuildPolicySnapshot("s1", 0).NetworkRules[0]
	if len(first.CIDRs) != 1 || first.CIDRs[0] != "2001:db8::1/128" {
		t.Fatalf("first network rule = %+v", first)
	}
}

// The daemon checks the policy itself. An access that no approve rule
// matches gets no dialog and no grant.
func TestAskApproval_RefusesAccessWithNoApproveRule(t *testing.T) {
	a, _, launched := askFixture(t)
	cases := []*PolicyRequest{
		{Kind: "file", SessionID: "s1", Path: "/w/secret/a.txt", Operation: "read"},
		{Kind: "file", SessionID: "s1", Path: "/etc/passwd", Operation: "write"},
		{Kind: "network", SessionID: "s1", IP: "1.2.3.4", Port: 80},
		{Kind: "command", SessionID: "s1", Path: "/usr/bin/sudo"},
		{Kind: "file", Path: "/w/secret/a.txt", Operation: "write"},
	}
	for _, c := range cases {
		if resp := a.AskApproval(c); resp.Success {
			t.Errorf("AskApproval(%+v) = %+v, want a refusal", c, resp)
		}
	}
	expectNoDialog(t, launched)
}

func TestAskApproval_WithoutApprovalsActsAsDeny(t *testing.T) {
	a, _, _ := askFixture(t)
	a.SetApprovals(nil)
	resp := a.AskApproval(&PolicyRequest{Kind: "file", SessionID: "s1", Path: "/w/secret/a.txt", Operation: "write"})
	if resp.Success || resp.Allow {
		t.Fatalf("AskApproval = %+v", resp)
	}
	if files, nets := a.grantRules("s1"); files != nil || nets != nil {
		t.Fatal("grant rules without approvals")
	}
}

// An exec cannot wait for a person. The first one is denied and opens the
// dialog. After the approval, the retry runs.
func TestCheckExec_ApproveDeniesThenAllowsAfterApproval(t *testing.T) {
	a, m, launched := askFixture(t)

	first := a.CheckExec("/usr/bin/sudo", []string{"ls"}, 1, 0, "s1", ExecContext{})
	if first.Action != "deny" || first.Decision != "approve" {
		t.Fatalf("first exec = %+v", first)
	}
	req := expectDialog(t, launched)
	if req.Kind != "command" || req.Target != "/usr/bin/sudo" {
		t.Fatalf("dialog request = %+v", req)
	}
	m.Resolve(req.ID, true, "approved")
	waitGranted(t, m, "command", "/usr/bin/sudo", "exec")

	retry := a.CheckExec("/usr/bin/sudo", []string{"ls"}, 2, 0, "s1", ExecContext{})
	if retry.Action != "continue" {
		t.Fatalf("retry = %+v, want continue", retry)
	}
	// The grant is for this session only.
	other := a.CheckExec("/usr/bin/sudo", []string{"ls"}, 3, 0, "s2", ExecContext{})
	if other.Action != "deny" {
		t.Fatalf("other session = %+v, want deny", other)
	}
	expectDialog(t, launched)
}

func TestNetworkGrantRule_RejectsWildcardHosts(t *testing.T) {
	if _, ok := networkGrantRule("*.example.com:443"); ok {
		t.Fatal("a wildcard host became a grant")
	}
	if _, ok := networkGrantRule("example.com"); ok {
		t.Fatal("a target with no port became a grant")
	}
}

func TestServer_RoutesRequestApproval(t *testing.T) {
	a, _, launched := askFixture(t)
	s := NewServer("unused", a)
	req := &PolicyRequest{Type: RequestTypeRequestApproval, Kind: "file", SessionID: "s1", Path: "/w/secret/a.txt", Operation: "write"}

	if resp := s.handleRequest(req); resp.Success {
		t.Fatalf("without an asker = %+v, want a refusal", resp)
	}
	s.SetApprovalAsker(a)
	if resp := s.handleRequest(req); !resp.Success {
		t.Fatalf("with an asker = %+v", resp)
	}
	expectDialog(t, launched)

	// The approval dialog may not ask for approvals.
	if resp := s.handleRequestAs(roleApprovalDialog, req); resp.Success {
		t.Fatalf("dialog role = %+v, want a refusal", resp)
	}
}

// scripts/test-swift-file-rules.sh checks that the extension matches this
// escaped form only against the original path.
func TestEscapeGlob(t *testing.T) {
	if got := escapeGlob(`/w/a*b?[c].txt`); got != `/w/a\*b\?\[c].txt` {
		t.Fatalf("escapeGlob = %q", got)
	}
	if got := escapeGlob(`/w/back\slash`); got != `/w/back\\slash` {
		t.Fatalf("escapeGlob = %q", got)
	}
}
