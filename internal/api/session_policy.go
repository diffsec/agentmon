package api

import (
	"context"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/session"
	"github.com/diffsec/agentmon/internal/tor"
)

// policyEngineFor returns the effective policy engine to consult for the given
// session. It prefers the session's own engine (compiled from the session's
// named policy file with per-session variable expansion) and falls back to the
// process-global engine (a.Policy()) when the session has no engine of its own
// or when s is nil.
//
// Reads the global engine via a.Policy() so a SwapPolicy by the WTP
// pushed-policy install hook is observed by every subsequent session.
//
// This exists to fix diffsec/agentmon#191: before this helper, the command
// precheck and wrap-time Landlock derivation paths used a.policy directly,
// which silently ignored custom rules authored in any non-default policy file.
// All new call sites that need to consult "the policy for this session" should
// use this helper rather than touching a.policy directly.
func (a *App) policyEngineFor(s *session.Session) *policy.Engine {
	if s != nil {
		if sp := s.PolicyEngine(); sp != nil {
			return sp
		}
	}
	return a.Policy()
}

// Policy returns the current process-global policy engine. Read under
// the App's RWMutex so a concurrent SwapPolicy doesn't race against
// the pointer assignment.
func (a *App) Policy() *policy.Engine {
	a.policyMu.RLock()
	defer a.policyMu.RUnlock()
	return a.policy
}

// SwapPolicy atomically replaces the process-global policy engine.
// Used by the WTP pushed-policy install hook after Manager.Reload
// produces a fresh *policy.Policy and NewEngine wraps it. Returns the
// previous engine so callers can decide whether to tear down
// engine-bound resources (none today, but kept for symmetry with the
// signal-handler integration roadmap).
//
// The network proxy, transparent TCP interceptor and DNS interceptor now
// observe this swap: they take an EngineFunc rather than capturing
// *policy.Engine at construction, and resolve it per decision. So do the
// command-time CheckCommand / CheckExecve / CheckFile paths, through
// a.policyEngineFor.
//
// What this does NOT reach is a session holding its own engine. Every
// session created through createSession gets one, compiled from the policy
// document with that session's own PROJECT_ROOT and GIT_ROOT (see
// compileDBPolicyForSession), and both policyEngineFor and the interceptors'
// policyEngine() prefer it. Replacing the process-global pointer therefore
// leaves a running session enforcing the policy it started with, on every
// path. Closing that means recompiling each session's engine from the new
// document with that session's variables, preserving its Tor coordinator and
// DB rule set -- separate work, not a wider getter.
func (a *App) SwapPolicy(eng *policy.Engine) *policy.Engine {
	a.policyMu.Lock()
	defer a.policyMu.Unlock()
	prev := a.policy
	a.policy = eng
	return prev
}

// execveEnforcementActive reports whether inner execve calls will be policed at
// runtime for sandboxed commands on this host: either seccomp execve
// interception is enabled, or a ptrace tracer is attached. Used to relax the
// opaque shell-c pre-deny (issue #375) — when true, CheckExecve enforces the
// command policy on every inner exec, so the static pre-deny is redundant.
func (a *App) execveEnforcementActive() bool {
	if a.ptraceTracer != nil {
		return true
	}
	// Seccomp execve enforcement is installed by the unix-socket notify
	// wrapper; without unix sockets the wrapper is skipped and inner execve
	// calls are NOT policed, so the opaque shell-c pre-deny must stay. Issue #375.
	return a.cfg.Sandbox.Seccomp.Execve.Enabled && unixSocketsConfigEnabled(a.cfg)
}

// shellCOpaqueMode resolves the operator's opaque shell-c handling mode from
// config (sandbox.seccomp.shellc.opaque) for command pre-checks. Issue #378.
func (a *App) shellCOpaqueMode() policy.ShellCOpaqueMode {
	return policy.ParseShellCOpaqueMode(a.cfg.Sandbox.Seccomp.Shellc.Opaque)
}

// attachSessionTor installs the shared Tor coordinator on a per-session engine.
// The process-global engine already carries it (set once at server start in
// server.go); sessions that compiled their own engine from a named policy file
// would otherwise have torChecker == nil, silently skipping the ptrace
// connect/execve Tor vectors. Guarded so the shared global engine is never
// re-written (SetTorPolicy is unsynchronized).
// attachEngineServices installs the process-wide services a freshly compiled
// engine does not carry.
//
// NewEngine and NewEngineWithVariables build an engine from a policy document
// and nothing else. The threat feed store, the Tor coordinator and the content
// inspector are all installed afterwards, and until now only on the
// process-global engine built at startup (internal/server/server.go and
// inspect_glue.go). Every session created through createSession gets its own
// engine, and every one of them was missing all three:
//
//   - no threat store, so a configured feed checked no domain in any session
//   - no inspector, so every `decision: inspect` command rule resolved through
//     on_failure and denied
//   - Tor was the one already handled, by attachSessionTor
//
// The inspector is resolved from the registry for THIS engine's policy rather
// than copied from the global one, because a different policy names different
// profiles. The threat store is process-wide and is copied.
//
// Call it through installSessionEngine rather than directly.
func (a *App) attachEngineServices(eng *policy.Engine) {
	if a == nil || eng == nil {
		return
	}
	// A session engine that IS the global one already has everything, and
	// re-attaching would be a no-op at best and a race at worst.
	if eng == a.Policy() {
		return
	}
	if store, action := a.Policy().ThreatStore(); store != nil {
		eng.SetThreatStore(store, action)
	}
	if ic := a.Inspector(eng); ic != nil {
		eng.SetInspector(ic)
	}
	a.attachSessionTor(eng)
}

// installSessionEngine attaches the process-wide services and installs the
// engine on the session.
//
// The two halves are one operation, and separating them is how a session ended
// up enforcing a policy with no threat store and no inspector: every creation
// path remembered SetPolicyEngine and none of them attached anything but Tor.
// TestSetPolicyEngineOnlyCalledViaInstall keeps the pairing from coming apart
// again.
func (a *App) installSessionEngine(s *session.Session, eng *policy.Engine) {
	if s == nil || eng == nil {
		return
	}
	a.attachEngineServices(eng)
	s.SetPolicyEngine(eng)
}

func (a *App) attachSessionTor(eng *policy.Engine) {
	if a == nil || a.torPolicy == nil || eng == nil {
		return
	}
	if eng == a.Policy() {
		return
	}
	// A coordinator already installed was installed deliberately, and the
	// only thing that does so is attachDenyTor putting this session into
	// Tor-deny. Replacing it with the app-wide policy would quietly lift that
	// deny -- which is what happened when installSessionEngine started
	// running this after attachDenyTor had already set its adapter, and what
	// TestApplyTorFailClosed_ProfileSession_DeniesTor caught.
	if eng.TorPolicy() != nil {
		return
	}
	eng.SetTorPolicy(&tor.PolicyAdapter{Policy: a.torPolicy})
}

// attachDenyTor makes a session enforce Tor deny (fail-closed). If the session
// already has its OWN engine, the deny coordinator is installed on it directly.
// Otherwise the session is using the shared global engine; we clone that
// engine's policy, attach deny-Tor to the clone, and install it per session —
// never mutating shared state. Returns true if a deny coordinator was installed.
func (a *App) attachDenyTor(s *session.Session, deny *tor.Policy) bool {
	if a == nil || s == nil || deny == nil {
		return false
	}
	adapter := &tor.PolicyAdapter{Policy: deny}
	if eng := s.PolicyEngine(); eng != nil && eng != a.Policy() {
		eng.SetTorPolicy(adapter)
		return true
	}
	base := a.Policy().Policy()
	clone := clonePolicy(base)
	enforceApprovals := a.cfg.Approvals.Enabled && a.cfg.Approvals.Mode != ""
	eng, err := policy.NewEngineWithVariables(clone, enforceApprovals, true, nil)
	if err != nil || eng == nil {
		return false
	}
	eng.SetTorPolicy(adapter)
	// Through installSessionEngine, not SetPolicyEngine: the clone is a
	// brand-new engine, so attaching deny-Tor to a session must not be the
	// thing that turns off its threat feed and content inspection.
	a.installSessionEngine(s, eng)
	return true
}

// applyTorFailClosed denies Tor for a session when the onion gateway is active
// in policy but could not be wired (proxy-env fallback or transparent disabled).
// No-op when the gateway is inactive or the interceptor came up (force-redirect
// handled it). Emits one session-level gateway event recording the outcome.
func (a *App) applyTorFailClosed(ctx context.Context, s *session.Session, interceptorUp bool) {
	if a == nil || s == nil {
		return
	}
	if a.torPolicy == nil || !a.torPolicy.GatewayActive() {
		return
	}
	// interceptorUp == true means the force-redirect path already handled this session.
	if gatewayBranchFor(true, interceptorUp) != gatewayFailClosed {
		return
	}
	deny, err := a.torPolicy.DenyModeClone()
	attached := false
	if err == nil {
		attached = a.attachDenyTor(s, deny)
	}
	enforced := attached && a.execveEnforcementActive()
	reason := "proxy_env_fallback"
	if !a.cfg.Sandbox.Network.Transparent.Enabled {
		reason = "transparent_disabled"
	}
	ev := tor.BuildGatewayEvent(s.ID, "deny", reason, enforced)
	_ = a.store.AppendEvent(ctx, ev)
	a.broker.Publish(ev)
}
