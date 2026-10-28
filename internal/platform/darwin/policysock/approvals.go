//go:build darwin

package policysock

import (
	"strings"
	"time"
)

// FormatApprovalTime renders a timestamp for PendingApproval.
func FormatApprovalTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// ApprovalDialogIdentifier is the code-signing identifier of the approval
// dialog app. It is the bundle ID Xcode signs the app with.
const ApprovalDialogIdentifier = "dev.diffsec.agentmon.approval-dialog"

// PendingApproval is one approval request as the dialog sees it.
type PendingApproval struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Target    string `json:"target,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Message   string `json:"message,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	CommandID string `json:"command_id,omitempty"`
	// CreatedAt and ExpiresAt are RFC 3339 at second precision. A time.Time
	// would marshal with nanoseconds, which Foundation's ISO8601DateFormatter
	// does not parse by default.
	CreatedAt string            `json:"created_at"`
	ExpiresAt string            `json:"expires_at"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// ApprovalBroker lists and resolves the daemon's pending approvals.
type ApprovalBroker interface {
	PendingApprovals() []PendingApproval
	ResolveApproval(id string, approved bool, reason string) bool
}

// SetApprovalBroker sets the source of approvals for the dialog. If it is not
// set, list_approvals returns nothing and resolve_approval fails.
func (s *Server) SetApprovalBroker(b ApprovalBroker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approvalBroker = b
}

func (s *Server) getApprovalBroker() ApprovalBroker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.approvalBroker
}

// peerRole is what a connection is allowed to ask for.
type peerRole int

const (
	// roleUnverified is a peer the server did not check, because no team ID
	// is configured or the build has no cgo. It keeps the access every peer
	// had before roles existed, minus approvals.
	roleUnverified peerRole = iota
	// rolePrivileged is a root peer that passed ValidatePeer: the system
	// extension.
	rolePrivileged
	// roleApprovalDialog is the signed approval dialog, running as the same
	// user as the daemon. It may list and resolve approvals and nothing else.
	roleApprovalDialog
)

func isApprovalRequest(t RequestType) bool {
	return t == RequestTypeListApprovals || t == RequestTypeResolveApproval
}

// handleRequestAs applies the connection's role before dispatching.
//
// Resolving an approval is the one request on this socket that grants an
// agent something it asked for. So only the dialog may send it, and the dialog
// may send nothing else. The system extension cannot resolve approvals either:
// it has no reason to, and a root peer that can approve its own requests is a
// bigger target than it needs to be.
func (s *Server) handleRequestAs(role peerRole, req *PolicyRequest) PolicyResponse {
	if role == roleApprovalDialog {
		if !isApprovalRequest(req.Type) {
			return PolicyResponse{Allow: false, Message: "the approval dialog may only list and resolve approvals"}
		}
		return s.handleApprovalRequest(req)
	}
	if isApprovalRequest(req.Type) {
		return PolicyResponse{Allow: false, Message: "approvals are listed and resolved only by the signed approval dialog"}
	}
	return s.handleRequest(req)
}

func (s *Server) handleApprovalRequest(req *PolicyRequest) PolicyResponse {
	b := s.getApprovalBroker()
	switch req.Type {
	case RequestTypeListApprovals:
		if b == nil {
			return PolicyResponse{Success: true}
		}
		return PolicyResponse{Success: true, PendingApprovals: b.PendingApprovals()}
	case RequestTypeResolveApproval:
		if b == nil {
			return PolicyResponse{Success: false, Message: "approvals are not enabled"}
		}
		id := strings.TrimSpace(req.RequestID)
		if id == "" {
			return PolicyResponse{Success: false, Message: "request_id is required"}
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "resolved in the approval dialog"
		}
		if !b.ResolveApproval(id, req.Approved, reason) {
			return PolicyResponse{Success: false, Message: "no pending approval with that id; it may have expired or been resolved already"}
		}
		return PolicyResponse{Success: true}
	}
	return PolicyResponse{Success: false, Message: "unknown request type"}
}
