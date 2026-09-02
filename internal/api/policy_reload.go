package api

import (
	"fmt"
	"log/slog"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/session"
)

// PolicyReloadResult records what a reload did to each running session.
//
// A pushed policy that reaches some sessions and not others is the kind of
// partial enforcement that reads as success, so the reload reports per
// session rather than returning a single error.
type PolicyReloadResult struct {
	// Updated lists sessions now enforcing the new document.
	Updated []string
	// Skipped lists sessions still enforcing the policy they started with,
	// keyed on session ID with the reason.
	Skipped map[string]string
}

// Skip reasons. They are values rather than free text so a caller can act on
// them and a test can assert on them.
const (
	// SkipNoSessionEngine means the session follows the process-global
	// engine, which the swap already replaced. Not a failure.
	SkipNoSessionEngine = "session follows the global engine, which was swapped"
	// SkipNoPolicyVars means the session has no record of the substitutions
	// its engine was compiled with, so it cannot be rebuilt faithfully.
	SkipNoPolicyVars = "no policy variables recorded for this session"
	// SkipDBProxyRunning means a database proxy is listening on sockets the
	// current engine's rules name.
	SkipDBProxyRunning = "a database proxy is running for this session; its rules are generated from db_services and cannot be replaced under a live connection"
	// SkipCompileFailed is prefixed to the compiler's own error.
	SkipCompileFailed = "recompiling the session engine failed"
)

// ReloadPolicy installs a new policy document across the whole process.
//
// It swaps the global engine and rebuilds every running session's engine from
// the same document with that session's own variables. Both halves are needed:
// SwapPolicy alone reaches only sessions that follow the global engine, and
// every session created through createSession holds its own -- so a pushed
// update used to reach sessions created after it and no others, on every
// enforcement path.
//
// Sessions that cannot be rebuilt keep the engine they have and are reported.
// Continuing past one is deliberate: a policy that reached nine sessions and
// not the tenth is worth knowing about, and refusing the whole reload would
// leave all ten on the old document.
func (a *App) ReloadPolicy(doc *policy.Policy) (PolicyReloadResult, error) {
	res := PolicyReloadResult{Skipped: map[string]string{}}
	if a == nil || doc == nil {
		return res, fmt.Errorf("policy reload: no document")
	}

	enforceApprovals := a.cfg != nil && a.cfg.Approvals.Enabled && a.cfg.Approvals.Mode != ""

	newGlobal, err := policy.NewEngine(doc, enforceApprovals, true)
	if err != nil {
		// Nothing has changed yet, so the whole reload fails and the
		// previous document stays in force everywhere.
		return res, fmt.Errorf("policy reload: build global engine: %w", err)
	}
	// The global engine is built at startup with its threat store and
	// inspector installed directly; a replacement gets them here.
	if store, action := a.Policy().ThreatStore(); store != nil {
		newGlobal.SetThreatStore(store, action)
	}
	if ic := a.Inspector(newGlobal); ic != nil {
		newGlobal.SetInspector(ic)
	}
	a.SwapPolicy(newGlobal)

	if a.sessions == nil {
		return res, nil
	}
	for _, s := range a.sessions.List() {
		if s == nil {
			continue
		}
		if reason, ok := a.reloadSessionPolicy(s, doc, enforceApprovals); ok {
			res.Updated = append(res.Updated, s.ID)
		} else {
			res.Skipped[s.ID] = reason
		}
	}
	return res, nil
}

// reloadSessionPolicy rebuilds one session's engine. It returns the skip
// reason and false when the session keeps the engine it has.
func (a *App) reloadSessionPolicy(s *session.Session, doc *policy.Policy, enforceApprovals bool) (string, bool) {
	old := s.PolicyEngine()
	if old == nil || old == a.Policy() {
		return SkipNoSessionEngine, false
	}

	vars := s.PolicyVars()
	if vars == nil {
		// Rebuilding without them would compile ${PROJECT_ROOT} rules
		// against an empty string, silently widening or narrowing every
		// path rule in the session. Keeping the old engine is the safe
		// answer, and saying so is what stops it being silent.
		return SkipNoPolicyVars, false
	}

	// A running DB proxy is listening on sockets that the session's current
	// rules name, and those rules are generated from the policy's db_services
	// (compileDBPolicyForSession). Recompiling from a document whose
	// db_services differ would produce rules pointing at sockets nothing
	// serves, so the session would lose database access with the reload
	// looking like a success. Rebuilding the proxy under a live connection is
	// a bigger decision than a policy reload should make on its own.
	if s.DBProxySocketDir() != "" {
		return SkipDBProxyRunning, false
	}

	fresh, err := policy.NewEngineWithVariables(doc, enforceApprovals, true, vars)
	if err != nil {
		return SkipCompileFailed + ": " + err.Error(), false
	}

	// Carry the session's Tor coordinator across before the services are
	// attached. A session put into Tor-deny has one of its own, and
	// attachSessionTor leaves an existing coordinator alone -- so copying it
	// first preserves a deny, while a session that only ever had the app-wide
	// one is indistinguishable either way.
	if tc := old.TorPolicy(); tc != nil {
		fresh.SetTorPolicy(tc)
	}

	a.installSessionEngine(s, fresh, vars)
	return "", true
}

// LogPolicyReload writes the outcome of a reload at a level matching whether
// anything was missed. A skipped session is not an error, but it is the
// difference between "the policy is live" and "the policy is live in most
// places", and an operator has to be able to tell.
func LogPolicyReload(res PolicyReloadResult, policyID string, version uint32) {
	if len(res.Skipped) == 0 {
		slog.Info("policy reload: applied to every running session",
			"policy_id", policyID, "policy_version", version, "sessions", len(res.Updated))
		return
	}
	for id, reason := range res.Skipped {
		slog.Warn("policy reload: session keeps its previous policy",
			"policy_id", policyID, "policy_version", version, "session_id", id, "reason", reason)
	}
	slog.Warn("policy reload: applied to some sessions",
		"policy_id", policyID, "policy_version", version,
		"updated", len(res.Updated), "skipped", len(res.Skipped))
}
