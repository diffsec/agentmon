//go:build darwin

package server

import (
	"fmt"

	"github.com/diffsec/agentmon/internal/approvals"
	"github.com/diffsec/agentmon/internal/platform/darwin/policysock"
)

// approvalBroker exposes the approvals manager to the approval dialog over
// the policy socket.
type approvalBroker struct {
	mgr *approvals.Manager
}

func (b approvalBroker) PendingApprovals() []policysock.PendingApproval {
	pending := b.mgr.ListPending()
	out := make([]policysock.PendingApproval, 0, len(pending))
	for _, r := range pending {
		out = append(out, toPendingApproval(r))
	}
	return out
}

func (b approvalBroker) ResolveApproval(id string, approved bool, reason string) bool {
	return b.mgr.Resolve(id, approved, reason)
}

// toPendingApproval flattens Fields to strings. The dialog shows them as
// label and value rows, and a nested value would arrive in Swift as an
// untyped dictionary it can only print as Swift debug output.
func toPendingApproval(r approvals.Request) policysock.PendingApproval {
	var fields map[string]string
	if len(r.Fields) > 0 {
		fields = make(map[string]string, len(r.Fields))
		for k, v := range r.Fields {
			fields[k] = fmt.Sprint(v)
		}
	}
	return policysock.PendingApproval{
		ID:        r.ID,
		Kind:      r.Kind,
		Target:    r.Target,
		Rule:      r.Rule,
		Message:   r.Message,
		SessionID: r.SessionID,
		CommandID: r.CommandID,
		CreatedAt: policysock.FormatApprovalTime(r.CreatedAt),
		ExpiresAt: policysock.FormatApprovalTime(r.ExpiresAt),
		Fields:    fields,
	}
}
