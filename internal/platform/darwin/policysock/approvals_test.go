//go:build darwin

package policysock

import (
	"bytes"
	"encoding/json"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata golden files")

type fakeBroker struct {
	pending  []PendingApproval
	resolved []struct {
		id       string
		approved bool
		reason   string
	}
	known map[string]bool
}

func (b *fakeBroker) PendingApprovals() []PendingApproval { return b.pending }

func (b *fakeBroker) ResolveApproval(id string, approved bool, reason string) bool {
	if !b.known[id] {
		return false
	}
	b.resolved = append(b.resolved, struct {
		id       string
		approved bool
		reason   string
	}{id, approved, reason})
	delete(b.known, id)
	return true
}

func samplePending() []PendingApproval {
	return []PendingApproval{{
		ID:        "approval-1",
		Kind:      "command",
		Target:    "curl https://example.com",
		Rule:      "approve-curl-wget",
		Message:   "Agent wants to download: https://example.com",
		SessionID: "session-abc",
		CommandID: "cmd-1",
		CreatedAt: FormatApprovalTime(time.Date(2026, 10, 28, 2, 0, 0, 123456789, time.UTC)),
		ExpiresAt: FormatApprovalTime(time.Date(2026, 10, 28, 2, 5, 0, 987654321, time.UTC)),
		Fields:    map[string]string{"argv": "curl https://example.com", "cwd": "/workspace"},
	}}
}

func newApprovalServer(b ApprovalBroker) *Server {
	s := NewServer(filepath.Join(os.TempDir(), "unused.sock"), &testPolicyHandler{})
	if b != nil {
		s.SetApprovalBroker(b)
	}
	return s
}

func TestHandleRequestAs_DialogMayListAndResolve(t *testing.T) {
	b := &fakeBroker{pending: samplePending(), known: map[string]bool{"approval-1": true}}
	s := newApprovalServer(b)

	list := s.handleRequestAs(roleApprovalDialog, &PolicyRequest{Type: RequestTypeListApprovals})
	if !list.Success || len(list.PendingApprovals) != 1 || list.PendingApprovals[0].ID != "approval-1" {
		t.Fatalf("list = %+v", list)
	}

	res := s.handleRequestAs(roleApprovalDialog, &PolicyRequest{
		Type: RequestTypeResolveApproval, RequestID: "approval-1", Approved: true, Reason: "approved by ben",
	})
	if !res.Success {
		t.Fatalf("resolve = %+v", res)
	}
	if len(b.resolved) != 1 || !b.resolved[0].approved || b.resolved[0].reason != "approved by ben" {
		t.Fatalf("broker saw %+v", b.resolved)
	}
}

// TestHandleRequestAs_DialogMayDoNothingElse: the dialog's connection is
// admitted on its signature alone, so it must not reach the policy checks the
// system extension uses.
func TestHandleRequestAs_DialogMayDoNothingElse(t *testing.T) {
	s := newApprovalServer(&fakeBroker{})
	for _, typ := range []RequestType{
		RequestTypeFile, RequestTypeExecCheck, RequestTypeRegisterSession,
		RequestTypeFetchPolicySnapshot, RequestTypePNACLSubmit, RequestTypeMuteProcess,
	} {
		resp := s.handleRequestAs(roleApprovalDialog, &PolicyRequest{Type: typ, Path: "/etc/passwd"})
		if resp.Allow || resp.Success {
			t.Errorf("%s from the dialog = %+v, want a refusal", typ, resp)
		}
		if !strings.Contains(resp.Message, "only list and resolve") {
			t.Errorf("%s message = %q", typ, resp.Message)
		}
	}
}

// TestHandleRequestAs_OnlyTheDialogMayResolve: the system extension runs as
// root, and an unverified peer is any local process when no team ID is set.
// Neither may answer an approval.
func TestHandleRequestAs_OnlyTheDialogMayResolve(t *testing.T) {
	for _, role := range []peerRole{rolePrivileged, roleUnverified} {
		b := &fakeBroker{pending: samplePending(), known: map[string]bool{"approval-1": true}}
		s := newApprovalServer(b)
		for _, typ := range []RequestType{RequestTypeListApprovals, RequestTypeResolveApproval} {
			resp := s.handleRequestAs(role, &PolicyRequest{Type: typ, RequestID: "approval-1", Approved: true})
			if resp.Success || len(resp.PendingApprovals) != 0 {
				t.Errorf("role %d, %s = %+v, want a refusal", role, typ, resp)
			}
			// The refusal must come from the role gate, not from
			// handleRequest happening to have no case for these types.
			// Otherwise a later case added there would open approvals to
			// the extension and to every unverified peer.
			if !strings.Contains(resp.Message, "only by the signed approval dialog") {
				t.Errorf("role %d, %s message = %q, want the role gate's refusal", role, typ, resp.Message)
			}
		}
		if len(b.resolved) != 0 {
			t.Errorf("role %d resolved an approval: %+v", role, b.resolved)
		}
	}
}

func TestHandleRequestAs_OtherRolesKeepTheirAccess(t *testing.T) {
	s := newApprovalServer(nil)
	for _, role := range []peerRole{rolePrivileged, roleUnverified} {
		resp := s.handleRequestAs(role, &PolicyRequest{Type: RequestTypeFile, Path: "/tmp/x", Operation: "read"})
		if !resp.Allow {
			t.Errorf("role %d file check = %+v, want the handler's allow", role, resp)
		}
	}
}

func TestHandleApprovalRequest_ResolveErrors(t *testing.T) {
	b := &fakeBroker{known: map[string]bool{"approval-1": true}}
	s := newApprovalServer(b)

	if resp := s.handleApprovalRequest(&PolicyRequest{Type: RequestTypeResolveApproval}); resp.Success || !strings.Contains(resp.Message, "request_id") {
		t.Errorf("missing id = %+v", resp)
	}
	if resp := s.handleApprovalRequest(&PolicyRequest{Type: RequestTypeResolveApproval, RequestID: "nope"}); resp.Success || !strings.Contains(resp.Message, "no pending approval") {
		t.Errorf("unknown id = %+v", resp)
	}
	// A deny with no reason still records why, so the audit event is not blank.
	if resp := s.handleApprovalRequest(&PolicyRequest{Type: RequestTypeResolveApproval, RequestID: "approval-1"}); !resp.Success {
		t.Fatalf("deny = %+v", resp)
	}
	if b.resolved[0].approved || b.resolved[0].reason != "resolved in the approval dialog" {
		t.Errorf("resolved = %+v", b.resolved[0])
	}
}

func TestHandleApprovalRequest_NoBroker(t *testing.T) {
	s := newApprovalServer(nil)
	if resp := s.handleApprovalRequest(&PolicyRequest{Type: RequestTypeListApprovals}); !resp.Success || len(resp.PendingApprovals) != 0 {
		t.Errorf("list without a broker = %+v", resp)
	}
	if resp := s.handleApprovalRequest(&PolicyRequest{Type: RequestTypeResolveApproval, RequestID: "x"}); resp.Success {
		t.Errorf("resolve without a broker = %+v", resp)
	}
}

// TestHandleConn_DialogDoesNotCountAsTheExtension: ExtensionConnected decides
// whether macOS enforcement is live. An open approval window must not make a
// dead extension look alive.
func TestHandleConn_DialogDoesNotCountAsTheExtension(t *testing.T) {
	for _, tc := range []struct {
		role peerRole
		want bool
	}{{roleApprovalDialog, false}, {rolePrivileged, true}} {
		s := newApprovalServer(&fakeBroker{})
		client, server := net.Pipe()
		s.wg.Add(1)
		go s.handleConn(server, tc.role)

		enc := json.NewEncoder(client)
		dec := json.NewDecoder(client)
		if err := enc.Encode(PolicyRequest{Type: RequestTypeListApprovals}); err != nil {
			t.Fatalf("encode: %v", err)
		}
		var resp PolicyResponse
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		connected, last := s.ExtensionConnected()
		if connected != tc.want || last.IsZero() == tc.want {
			t.Errorf("role %d: connected=%v lastContact=%v, want connected=%v", tc.role, connected, last, tc.want)
		}
		client.Close()
		s.wg.Wait()
	}
}

func TestApprovalDialogRequirement_PinsTheIdentifier(t *testing.T) {
	r := approvalDialogRequirement("LWSYS6YTUZ")
	for _, want := range []string{`identifier "dev.diffsec.agentmon.approval-dialog"`, `leaf[subject.OU] = "LWSYS6YTUZ"`, "anchor apple generic"} {
		if !strings.Contains(r, want) {
			t.Errorf("requirement %q lacks %q", r, want)
		}
	}
	// The team requirement alone admits every binary the team signs,
	// including the agentmon CLI an agent can exec.
	if strings.Contains(teamRequirement("LWSYS6YTUZ"), "identifier") {
		t.Error("teamRequirement should not pin an identifier; it is the requirement for the system extension")
	}
}

func TestFormatApprovalTime_SecondPrecisionUTC(t *testing.T) {
	loc := time.FixedZone("AEDT", 11*3600)
	got := FormatApprovalTime(time.Date(2026, 10, 28, 13, 0, 0, 999999999, loc))
	if got != "2026-10-28T02:00:00Z" {
		t.Errorf("FormatApprovalTime = %q", got)
	}
}

// TestListApprovalsReply_Golden pins the wire format the dialog parses.
// scripts/test-swift-approval-client.sh feeds the same file to the Swift
// parser, so a renamed JSON tag fails on one side or the other.
func TestListApprovalsReply_Golden(t *testing.T) {
	got, err := json.MarshalIndent(PolicyResponse{Success: true, PendingApprovals: samplePending()}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "list_approvals_reply.json")
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("list_approvals reply changed; the Swift dialog parses this shape.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
