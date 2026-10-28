//go:build darwin

package server

import (
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/approvals"
)

func TestToPendingApproval_FlattensFieldsAndTimes(t *testing.T) {
	r := approvals.Request{
		ID:        "approval-1",
		Kind:      "network",
		Target:    "example.com:443",
		CreatedAt: time.Date(2026, 10, 28, 2, 0, 0, 5, time.UTC),
		ExpiresAt: time.Date(2026, 10, 28, 2, 5, 0, 5, time.UTC),
		Fields:    map[string]any{"port": 443, "args": []string{"-v"}},
	}
	p := toPendingApproval(r)
	if p.ID != "approval-1" || p.Kind != "network" || p.Target != "example.com:443" {
		t.Fatalf("pending = %+v", p)
	}
	if p.CreatedAt != "2026-10-28T02:00:00Z" || p.ExpiresAt != "2026-10-28T02:05:00Z" {
		t.Errorf("times = %q, %q", p.CreatedAt, p.ExpiresAt)
	}
	if p.Fields["port"] != "443" || p.Fields["args"] != "[-v]" {
		t.Errorf("fields = %v", p.Fields)
	}
}

func TestApprovalBroker_ResolvesThroughTheManager(t *testing.T) {
	m := approvals.New("api", time.Minute, nil)
	done := make(chan approvals.Resolution, 1)
	go func() {
		res, _ := m.RequestApproval(t.Context(), approvals.Request{SessionID: "s1", Kind: "command"})
		done <- res
	}()
	b := approvalBroker{mgr: m}
	var id string
	for i := 0; i < 100 && id == ""; i++ {
		if p := b.PendingApprovals(); len(p) == 1 {
			id = p[0].ID
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("the request never appeared as pending")
	}
	if !b.ResolveApproval(id, true, "approved") {
		t.Fatal("ResolveApproval returned false")
	}
	if res := <-done; !res.Approved {
		t.Fatalf("resolution = %+v", res)
	}
}
