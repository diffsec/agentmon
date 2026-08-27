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
	ActiveSessions() []string
	NoteSnapshotDelivered(sessionID string)
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

// denyAllSnapshot returns a snapshot that denies everything for the session.
//
// This is the snapshot half of AUDIT H5. The live checks fail closed when no
// policy is available, but BuildPolicySnapshot used to answer with an empty,
// allow-everything snapshot -- so the extension cached "permit all" for the
// session and stopped asking.
//
// The deny is expressed through Defaults rather than the response's Allow
// field. SessionPolicyCache evaluates a snapshot by scanning its rules and then
// consulting cache.defaults ("if cache.defaults.file == \"deny\" { return .deny }"),
// and never reads the top-level Allow at all -- so setting Allow:false alone
// would have changed nothing. Emitting deny defaults with no rules is the
// representation the extension already understands, and needs no Swift change.
//
// Scoped to the session as usual: the extension only evaluates PIDs it has been
// told about, so this denies the sandboxed agent rather than the machine.
func denyAllSnapshot(sessionID string) PolicyResponse {
	deny := string(types.DecisionDeny)
	failClosed := false
	return PolicyResponse{
		Allow:     false,
		Rule:      "no-policy-fail-closed",
		SessionID: sessionID,
		Defaults: &SnapshotDefaults{
			File:    deny,
			Network: deny,
			DNS:     deny,
			Exec:    deny,
		},
		// The deny defaults above already make the extension's cache drop every
		// flow. These two carry the same intent into the paths the cache does
		// not decide, so a snapshot that means "deny everything" cannot be
		// undone by a policy-socket timeout.
		NetworkEnforcement: NetworkEnforcementBlock,
		NetworkFailOpen:    &failClosed,
	}
}

// Network enforcement modes carried in a snapshot. They set
// FilterDataProvider.blockingEnabled, which was hardcoded false and never
// assigned by anything.
const (
	// NetworkEnforcementBlock makes the provider consult the daemon
	// synchronously for flows its local cache cannot decide, and enforce proxy
	// bypass, rather than allowing them and reporting after the fact.
	NetworkEnforcementBlock = "block"
	// NetworkEnforcementAudit reports undecided flows and allows them.
	NetworkEnforcementAudit = "audit"
)

// networkEnforcement decides which mode a session's snapshot asks for.
//
// What this does and does not change is worth being precise about, because the
// name oversells it. A plain deny rule is already enforced without block mode:
// SessionPolicyCache.evaluateNetwork returns .deny and FilterDataProvider drops
// the flow before it ever reaches the blockingEnabled branch. Block mode governs
// the flows the cache hands back as undecided -- today, rules with decision
// "approve" -- plus proxy-bypass enforcement. In audit mode those are allowed
// and reported; in block mode the provider waits for the daemon's answer.
//
// So the rule is: if the policy expresses any intent about network access at
// all, the undecided cases go to the daemon rather than through. A policy with
// no network rules and an allow default has nothing to enforce, and paying a
// synchronous round trip per flow to be told "allow" is waste.
func networkEnforcement(p *policy.Policy) string {
	if p == nil {
		return NetworkEnforcementBlock
	}
	if len(p.NetworkRules) > 0 {
		return NetworkEnforcementBlock
	}
	return NetworkEnforcementAudit
}

// BuildPolicySnapshot projects the policy engine's rules into a flat snapshot
// format suitable for Swift-side local caching and evaluation.
func (a *PolicyAdapter) BuildPolicySnapshot(sessionID string, clientVersion uint64) PolicyResponse {
	if a.engine == nil {
		slog.Error("policy socket: snapshot requested with no policy engine, denying (fail closed)")
		return denyAllSnapshot(sessionID)
	}

	p := a.engine.Policy()
	if p == nil {
		slog.Error("policy socket: snapshot requested with no policy loaded, denying (fail closed)")
		return denyAllSnapshot(sessionID)
	}

	// If no session_id provided, look up the latest registered session.
	var rootPID int32
	if sessionID == "" && a.sessions != nil {
		sessionID, rootPID = a.sessions.LatestSession()
		if sessionID == "" {
			slog.Error("policy socket: snapshot requested but no session is registered, denying (fail closed)")
			return denyAllSnapshot("")
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

	// Every registered session, not just this one. Darwin notifications
	// coalesce, so the extension can be told "a session registered" once for
	// two registrations; it fetches the latest and would never learn about the
	// other. Handing back the full list lets it fetch what it is missing.
	var activeSessions []string
	if a.sessions != nil {
		activeSessions = a.sessions.ActiveSessions()
	}

	// The extension asked for this session's policy and is about to receive it,
	// so from here on it can enforce. wrap-init blocks on exactly this before
	// letting the agent start; without it the agent's first commands run before
	// the extension has any policy at all.
	if a.sessions != nil {
		a.sessions.NoteSnapshotDelivered(sessionID)
	}

	enforcement := networkEnforcement(p)
	// Fail closed whenever we are enforcing. The blocking path's fallback runs
	// when the policy socket times out or answers with something unrecognised,
	// and allowing there would mean a slow or dead daemon silently turns network
	// policy off -- the failure class AUDIT H5 was raised for. In audit mode the
	// flow is allowed regardless, so the flag is reported as fail-open to match
	// what actually happens rather than implying an enforcement we do not do.
	failOpen := enforcement != NetworkEnforcementBlock

	return PolicyResponse{
		Allow:              true,
		SessionID:          sessionID,
		RootPID:            rootPID,
		SnapshotVersion:    1, // Will be replaced by SessionVersions counter in Task 4
		FileRules:          fileRules,
		NetworkRules:       networkRules,
		DNSRules:           dnsRules,
		Defaults:           &defaults,
		NetworkEnforcement: enforcement,
		NetworkFailOpen:    &failOpen,
		ActiveSessions:     activeSessions,
	}
}

// Compile-time interface checks
var _ PolicyHandler = (*PolicyAdapter)(nil)
var _ ExecHandler = (*PolicyAdapter)(nil)
