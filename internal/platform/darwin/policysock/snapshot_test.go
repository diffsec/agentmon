//go:build darwin

package policysock

import (
	"encoding/json"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
	"golang.org/x/sys/unix"
)

func TestPolicySnapshotResponse_JSON(t *testing.T) {
	snap := PolicySnapshotResponse{
		Version:   1,
		SessionID: "session-abc",
		RootPID:   1234,
		FileRules: []SnapshotFileRule{
			{Pattern: "/home/user/project/**", Operations: []string{"read", "write", "create"}, Action: "allow"},
			{Pattern: "/etc/shadow", Operations: []string{"read"}, Action: "deny"},
		},
		NetworkRules: []SnapshotNetworkRule{
			{Name: "deny-evil", Domains: []string{"*.evil.com"}, CIDRs: []string{"10.0.0.0/8"}, Ports: []int{443}, Action: "deny"},
		},
		DNSRules: []SnapshotDNSRule{
			{Pattern: "*.evil.com", Action: "nxdomain"},
		},
		ExecRules: []SnapshotExecRule{
			{Pattern: "/usr/bin/git", Action: "redirect"},
			{Pattern: "/usr/bin/rm", Action: "deny"},
		},
		Defaults: &SnapshotDefaults{File: "allow", Network: "allow", DNS: "allow", Exec: "allow"},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicySnapshotResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 {
		t.Fatalf("expected version 1, got %d", decoded.Version)
	}
	if len(decoded.FileRules) != 2 {
		t.Fatalf("expected 2 file rules, got %d", len(decoded.FileRules))
	}
	if decoded.FileRules[1].Action != "deny" {
		t.Fatalf("expected deny, got %s", decoded.FileRules[1].Action)
	}
	if len(decoded.NetworkRules) != 1 || len(decoded.NetworkRules[0].Domains) != 1 ||
		len(decoded.NetworkRules[0].CIDRs) != 1 || decoded.NetworkRules[0].Ports[0] != 443 {
		t.Fatalf("network rule did not round-trip whole: %+v", decoded.NetworkRules)
	}
	if len(decoded.ExecRules) != 2 {
		t.Fatalf("expected 2 exec rules, got %d", len(decoded.ExecRules))
	}
	if decoded.ExecRules[0].Action != "redirect" {
		t.Fatalf("expected redirect, got %s", decoded.ExecRules[0].Action)
	}
	if decoded.RootPID != 1234 {
		t.Fatalf("expected root_pid 1234, got %d", decoded.RootPID)
	}
	if decoded.Defaults == nil || decoded.Defaults.DNS != "allow" {
		t.Fatalf("expected allow, got %v", decoded.Defaults)
	}
	if decoded.Defaults == nil || decoded.Defaults.Exec != "allow" {
		t.Fatalf("expected exec default allow, got %v", decoded.Defaults)
	}
}

func TestPolicySnapshotResponse_EmptyForMatchingVersion(t *testing.T) {
	snap := PolicySnapshotResponse{}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" {
		t.Fatal("expected valid JSON even for empty snapshot")
	}
	var decoded PolicySnapshotResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 0 {
		t.Fatalf("expected version 0, got %d", decoded.Version)
	}
}

func TestBuildPolicySnapshot_UnixSocketRules(t *testing.T) {
	p := &policy.Policy{Version: 1, UnixRules: []policy.UnixSocketRule{
		{Name: "dns", Paths: []string{"/var/run/mDNSResponder"}, Operations: []string{"Connect"}, Decision: "allow"},
		{Name: "sys", Paths: []string{"/var/run/**", "/private/var/run/**"}, Decision: "deny"},
	}}
	resp := snapshotFor(t, p)
	if len(resp.UnixSocketRules) != 3 {
		t.Fatalf("got %d unix socket rules, want one for each path: %+v", len(resp.UnixSocketRules), resp.UnixSocketRules)
	}
	dns := resp.UnixSocketRules[0]
	if dns.Name != "dns" || dns.Pattern != "/var/run/mDNSResponder" || len(dns.Operations) != 1 || dns.Operations[0] != "connect" || dns.Action != "allow" {
		t.Errorf("first rule = %+v", dns)
	}
	if r := resp.UnixSocketRules[2]; r.Pattern != "/private/var/run/**" || len(r.Operations) != 0 || r.Action != "deny" {
		t.Errorf("last rule = %+v, want every operation", r)
	}
	if got := snapshotFor(t, &policy.Policy{Version: 1}).UnixSocketRules; len(got) != 0 {
		t.Errorf("a policy with no unix socket rules sent %+v", got)
	}
}

func TestBuildPolicySnapshot_SignalRules(t *testing.T) {
	p := &policy.Policy{Version: 1, SignalRules: []policy.SignalRule{
		{Name: "fatal", Signals: []string{"@fatal", "SIGTERM"}, Target: policy.SignalTargetSpec{Type: "External"}, Decision: "deny"},
		{Name: "proc", Signals: []string{"HUP"}, Target: policy.SignalTargetSpec{Type: "process", Pattern: "node*"}, Decision: "absorb"},
		{Name: "redir", Signals: []string{"SIGINT"}, Target: policy.SignalTargetSpec{Type: "session"}, Decision: "redirect", RedirectTo: "SIGTERM", Fallback: "deny"},
		{Name: "range", Signals: []string{"15"}, Target: policy.SignalTargetSpec{Type: "pid_range", Min: 10, Max: 20}, Decision: "audit"},
	}}
	resp := snapshotFor(t, p)
	if len(resp.SignalRules) != 4 {
		t.Fatalf("got %d signal rules: %+v", len(resp.SignalRules), resp.SignalRules)
	}
	fatal := resp.SignalRules[0]
	want := []int{int(unix.SIGQUIT), int(unix.SIGABRT), int(unix.SIGKILL), int(unix.SIGTERM)}
	sort.Ints(want)
	if fatal.Target != "external" || fatal.Action != "deny" || !slices.Equal(fatal.Signals, want) {
		t.Errorf("fatal rule = %+v, want signals %v once each", fatal, want)
	}
	if r := resp.SignalRules[1]; r.Action != "deny" || r.Pattern != "node*" || !slices.Equal(r.Signals, []int{int(unix.SIGHUP)}) {
		t.Errorf("absorb rule = %+v, want deny", r)
	}
	if r := resp.SignalRules[2]; r.Action != "deny" {
		t.Errorf("redirect rule = %+v, want its fallback deny", r)
	}
	if r := resp.SignalRules[3]; r.Action != "audit" || r.Min != 10 || r.Max != 20 {
		t.Errorf("range rule = %+v", r)
	}
}

func TestMacOSSignalAction(t *testing.T) {
	for _, c := range []struct{ decision, fallback, want string }{
		{"allow", "", "allow"},
		{"audit", "", "audit"},
		{"deny", "audit", "deny"},
		{"absorb", "", "deny"},
		{"approve", "", "deny"},
		{"redirect", "", "audit"},
		{"redirect", "deny", "deny"},
		{"redirect", "allow", "allow"},
		{"redirect", "redirect", "audit"},
		{"unknown", "", "deny"},
	} {
		if got := macOSSignalAction(c.decision, c.fallback); got != c.want {
			t.Errorf("macOSSignalAction(%q, %q) = %q, want %q", c.decision, c.fallback, got, c.want)
		}
	}
}

// TestBuildPolicySnapshot_RootPIDs: the snapshot names every root of the
// session, and the tracker records that the extension received each one.
func TestBuildPolicySnapshot_RootPIDs(t *testing.T) {
	engine, err := policy.NewEngine(&policy.Policy{Version: 1}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	tracker := NewSessionTracker()
	tracker.RegisterProcess("s1", 100, 0)
	tracker.RegisterProcess("s1", 200, 0)

	resp := NewPolicyAdapter(engine, tracker).BuildPolicySnapshot("s1", 0)
	if resp.RootPID != 100 || !slices.Equal(resp.RootPIDs, []int32{100, 200}) {
		t.Errorf("root_pid = %d, root_pids = %v, want 100 and [100 200]", resp.RootPID, resp.RootPIDs)
	}
	if !tracker.AwaitRootDelivered("s1", 200, time.Millisecond) {
		t.Error("the tracker did not record that the snapshot named pid 200")
	}
}
