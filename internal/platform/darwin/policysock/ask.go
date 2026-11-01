//go:build darwin

package policysock

import (
	"net"
	"strconv"
	"strings"

	"github.com/diffsec/agentmon/internal/approvals"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/pkg/types"
)

// ApprovalAsker handles request_approval from the system extension.
type ApprovalAsker interface {
	AskApproval(req *PolicyRequest) PolicyResponse
}

// SetApprovals gives the adapter the daemon's approval manager. The manager
// must have grants on (approvals.Manager.SetGrantTTL). Without a manager, an
// approve rule acts as deny, as it does in the Go engine.
func (a *PolicyAdapter) SetApprovals(m *approvals.Manager) {
	a.approvals = m
}

// isApprove reports whether the policy asks a person about this access.
// An approve rule in audit mode has an effective decision of allow, and needs
// no person.
func isApprove(dec policy.Decision) bool {
	return dec.PolicyDecision == types.DecisionApprove && dec.EffectiveDecision == types.DecisionApprove
}

// AskApproval starts an approval for a file operation or a flow that the
// extension denied. It returns at once. If the person approves, the access is
// granted for the grant period, and the session's next snapshot allows it.
//
// The daemon checks the access against the session's policy again. The
// extension is trusted, but a grant for an access that no approve rule
// matches must not exist.
func (a *PolicyAdapter) AskApproval(req *PolicyRequest) PolicyResponse {
	if a.approvals == nil {
		return PolicyResponse{Allow: false, Message: "approvals are not enabled; an approve rule acts as deny"}
	}
	if req.SessionID == "" {
		return PolicyResponse{Allow: false, Message: "session_id is required"}
	}
	engine := a.engineFor(req.SessionID)
	if engine == nil {
		return PolicyResponse{Allow: false, Message: "no policy for the session"}
	}

	ar := approvals.Request{SessionID: req.SessionID, Kind: req.Kind}
	switch req.Kind {
	case "file":
		if req.Path == "" || req.Operation == "" {
			return PolicyResponse{Allow: false, Message: "path and operation are required"}
		}
		dec := engine.CheckFile(req.Path, req.Operation)
		if !isApprove(dec) {
			return PolicyResponse{Allow: false, Message: "no approve rule matches this access"}
		}
		ar.Target = req.Path
		ar.Rule, ar.Message = dec.Rule, dec.Message
		ar.Fields = map[string]any{"operation": req.Operation}
	case "network":
		ip := net.ParseIP(req.IP)
		if ip == nil || req.Port <= 0 || req.Port > 65535 {
			return PolicyResponse{Allow: false, Message: "ip and port are required"}
		}
		// The domain is the hostname when there is one, and the address
		// otherwise, as the gateway passes it.
		domain := strings.TrimSuffix(strings.ToLower(req.Domain), ".")
		if domain == "" {
			domain = ip.String()
		}
		dec := engine.CheckNetworkIP(domain, ip, req.Port)
		if !isApprove(dec) {
			return PolicyResponse{Allow: false, Message: "no approve rule matches this flow"}
		}
		// The same target as the gateway's, so a TCP flow and a UDP flow to
		// the same host share one answer.
		ar.Target = net.JoinHostPort(domain, strconv.Itoa(req.Port))
		ar.Rule, ar.Message = dec.Rule, dec.Message
	default:
		return PolicyResponse{Allow: false, Message: "kind must be file or network"}
	}
	if req.PID > 0 {
		if ar.Fields == nil {
			ar.Fields = map[string]any{}
		}
		ar.Fields["pid"] = strconv.Itoa(int(req.PID))
	}
	a.approvals.Ask(ar)
	return PolicyResponse{Allow: false, Success: true, Message: "approval requested"}
}

// execApproval decides an exec that an approve rule matched. A grant from an
// earlier approval allows it. Otherwise the exec is denied, and an approval
// starts, so a retry in the grant period succeeds. An ES exec event cannot
// wait for a person.
func (a *PolicyAdapter) execApproval(sessionID, executable string, dec policy.Decision) string {
	if a.approvals == nil || sessionID == "" {
		return "deny"
	}
	if a.approvals.Granted(sessionID, "command", executable, "exec") {
		return "continue"
	}
	a.approvals.Ask(approvals.Request{
		SessionID: sessionID,
		Kind:      "command",
		Target:    executable,
		Rule:      dec.Rule,
		Message:   dec.Message,
		Fields:    map[string]any{"operation": "exec"},
	})
	return "deny"
}

// grantRules returns the session's grants as snapshot rules. They come first
// in the snapshot, because the first rule that matches decides.
func (a *PolicyAdapter) grantRules(sessionID string) ([]SnapshotFileRule, []SnapshotNetworkRule) {
	if a.approvals == nil {
		return nil, nil
	}
	var files []SnapshotFileRule
	var nets []SnapshotNetworkRule
	for _, g := range a.approvals.Grants(sessionID) {
		switch g.Kind {
		case "file":
			files = append(files, SnapshotFileRule{
				Pattern:    escapeGlob(g.Target),
				Operations: []string{g.Operation},
				Action:     string(types.DecisionAllow),
			})
		case "network":
			if r, ok := networkGrantRule(g.Target); ok {
				nets = append(nets, r)
			}
		}
	}
	return files, nets
}

// escapeGlob makes a path match only itself. The extension matches file
// patterns with fnmatch, which reads a backslash as an escape, or with a
// regex when the pattern has "**". An escaped path never has "**".
func escapeGlob(path string) string {
	var b strings.Builder
	for _, r := range path {
		switch r {
		case '\\', '*', '?', '[':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// networkGrantRule turns a "host:port" grant into an allow rule for that
// host and port only.
func networkGrantRule(target string) (SnapshotNetworkRule, bool) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return SnapshotNetworkRule{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return SnapshotNetworkRule{}, false
	}
	r := SnapshotNetworkRule{Name: "approval-grant", Ports: []int{port}, Action: string(types.DecisionAllow)}
	if ip := net.ParseIP(host); ip != nil {
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		r.CIDRs = []string{host + "/" + strconv.Itoa(bits)}
		return r, true
	}
	// A domain pattern treats "*" and "?" as wildcards and has no escape.
	// A real hostname has neither.
	if strings.ContainsAny(host, "*?") {
		return SnapshotNetworkRule{}, false
	}
	r.Domains = []string{host}
	return r, true
}
