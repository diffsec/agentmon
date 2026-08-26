//go:build darwin

package policysock

import (
	"log/slog"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/pkg/types"
)

// SessionResolver looks up session ID for a process.
type SessionResolver interface {
	SessionForPID(pid int32) string
	LatestSession() (sessionID string, rootPID int32)
	RootPIDForSession(sessionID string) int32
}

// PolicyAdapter adapts the policy.Engine to the PolicyHandler interface.
type PolicyAdapter struct {
	engine   *policy.Engine
	sessions SessionResolver
}

// NewPolicyAdapter creates a new policy adapter.
func NewPolicyAdapter(engine *policy.Engine, sessions SessionResolver) *PolicyAdapter {
	return &PolicyAdapter{
		engine:   engine,
		sessions: sessions,
	}
}

// noEngine reports that the adapter has no policy engine and returns the
// fail-closed answer. This is AUDIT H5: every check below used to return
// allow/"no-policy" when engine was nil, so a daemon that had not finished
// installing a policy -- or had failed to load one -- waved through every file
// open, connect and exec the system extension asked about.
//
// Denying is safe here because the extension only asks about processes inside a
// tracked agentmon session: ESFClient guards its AUTH handlers on
// hasActiveSessions/sessionForPID, and SessionPolicyCache.evaluateFile returns
// .allow for any PID it does not know. So a nil engine now blocks the sandboxed
// agent rather than the machine.
func (a *PolicyAdapter) noEngine(check string) (bool, string) {
	slog.Error("policy socket: no policy engine installed, denying (fail closed)",
		"check", check)
	return false, "no-policy-fail-closed"
}

// CheckFile evaluates file access policy.
func (a *PolicyAdapter) CheckFile(path, op string) (allow bool, rule string) {
	if a.engine == nil {
		return a.noEngine("file")
	}
	dec := a.engine.CheckFile(path, op)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// CheckNetwork evaluates network access policy.
func (a *PolicyAdapter) CheckNetwork(ip string, port int, domain string) (allow bool, rule string) {
	if a.engine == nil {
		return a.noEngine("network")
	}
	// Use domain if provided, otherwise use IP
	target := domain
	if target == "" {
		target = ip
	}
	dec := a.engine.CheckNetwork(target, port)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// CheckCommand evaluates command execution policy.
func (a *PolicyAdapter) CheckCommand(cmd string, args []string) (allow bool, rule string) {
	if a.engine == nil {
		return a.noEngine("command")
	}
	dec := a.engine.CheckCommand(cmd, args)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// ResolveSession looks up the session ID for a process.
func (a *PolicyAdapter) ResolveSession(pid int32) string {
	if a.sessions == nil {
		return ""
	}
	return a.sessions.SessionForPID(pid)
}

// CheckExec evaluates a command through the exec pipeline, returning
// the full decision and action for the ESF client to act on.
func (a *PolicyAdapter) CheckExec(executable string, args []string, pid int32, parentPID int32, sessionID string, _ ExecContext) ExecCheckResult {
	if a.engine == nil {
		slog.Error("policy socket: no policy engine installed, denying exec (fail closed)",
			"executable", executable, "pid", pid)
		return ExecCheckResult{
			Decision: "deny",
			Action:   "deny",
			Rule:     "no-policy-fail-closed",
		}
	}

	dec := a.engine.CheckCommand(executable, args)

	// Use PolicyDecision for audit logging (the raw policy intent)
	decision := string(dec.PolicyDecision)

	// Use EffectiveDecision for action mapping (what actually happens, respects shadow mode)
	effectiveDecision := dec.EffectiveDecision
	if effectiveDecision == "" {
		effectiveDecision = dec.PolicyDecision
	}

	var action string
	switch effectiveDecision {
	case types.DecisionAllow, types.DecisionAudit:
		action = "continue"
	case types.DecisionDeny:
		action = "deny"
	case types.DecisionApprove, types.DecisionRedirect:
		action = "redirect"
	case types.DecisionSoftDelete:
		// soft-delete is a file operation concept; for exec, treat as continue
		action = "continue"
	default:
		// Unknown decisions fail-closed to prevent accidental allows.
		slog.Warn("policysock: unknown effective decision in CheckExec, denying",
			"effective_decision", string(effectiveDecision),
			"policy_decision", decision,
			"cmd", executable,
		)
		action = "deny"
	}

	return ExecCheckResult{
		Decision: decision,
		Action:   action,
		Rule:     dec.Rule,
		Message:  dec.Message,
	}
}

// BuildPolicySnapshot projects the policy engine's rules into a flat snapshot
// format suitable for Swift-side local caching and evaluation.
//
// KNOWN GAP (remainder of AUDIT H5): the three early returns below still hand
// back an empty, allow-everything snapshot when no policy is available. The
// live checks above now fail closed, but this path cannot be fixed from Go
// alone. SessionPolicyCache evaluates a snapshot by scanning explicit deny
// rules and returning .allow when none match, and it never reads the top-level
// Allow field -- so setting Allow:false here would change nothing. Closing this
// properly needs a paired Swift change: a distinct "no policy available" state
// that denies for tracked sessions instead of falling through to allow.
func (a *PolicyAdapter) BuildPolicySnapshot(sessionID string, clientVersion uint64) PolicyResponse {
	if a.engine == nil {
		slog.Error("policy socket: snapshot requested with no policy engine; " +
			"returning an empty snapshot, which the extension treats as allow-all")
		return PolicyResponse{Allow: true, Rule: "no-policy"}
	}

	p := a.engine.Policy()
	if p == nil {
		slog.Error("policy socket: snapshot requested with no policy loaded; " +
			"returning an empty snapshot, which the extension treats as allow-all")
		return PolicyResponse{Allow: true, Rule: "no-policy"}
	}

	// If no session_id provided, look up the latest registered session.
	var rootPID int32
	if sessionID == "" && a.sessions != nil {
		sessionID, rootPID = a.sessions.LatestSession()
		if sessionID == "" {
			return PolicyResponse{Allow: true}
		}
	} else if a.sessions != nil {
		rootPID = a.sessions.RootPIDForSession(sessionID)
	}

	var fileRules []SnapshotFileRule
	for _, r := range p.FileRules {
		for _, path := range r.Paths {
			fileRules = append(fileRules, SnapshotFileRule{
				Pattern:    path,
				Operations: r.Operations,
				Action:     r.Decision,
			})
		}
	}

	var networkRules []SnapshotNetworkRule
	for _, r := range p.NetworkRules {
		for _, domain := range r.Domains {
			networkRules = append(networkRules, SnapshotNetworkRule{
				Pattern: domain,
				Ports:   r.Ports,
				Action:  r.Decision,
			})
		}
		for _, cidr := range r.CIDRs {
			networkRules = append(networkRules, SnapshotNetworkRule{
				Pattern: cidr,
				Ports:   r.Ports,
				Action:  r.Decision,
			})
		}
	}

	// DNS rules are derived from network rules with domain patterns.
	// The current policy model does not have separate DNS rules.
	var dnsRules []SnapshotDNSRule

	defaults := SnapshotDefaults{
		File:    string(types.DecisionAllow),
		Network: string(types.DecisionAllow),
		DNS:     string(types.DecisionAllow),
	}

	return PolicyResponse{
		Allow:           true,
		SessionID:       sessionID,
		RootPID:         rootPID,
		SnapshotVersion: 1, // Will be replaced by SessionVersions counter in Task 4
		FileRules:       fileRules,
		NetworkRules:    networkRules,
		DNSRules:        dnsRules,
		Defaults:        &defaults,
	}
}

// Compile-time interface checks
var _ PolicyHandler = (*PolicyAdapter)(nil)
var _ ExecHandler = (*PolicyAdapter)(nil)
