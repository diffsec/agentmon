package api

import (
	"testing"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/session"
	"github.com/diffsec/agentmon/internal/tor"
	"github.com/diffsec/agentmon/pkg/types"
)

// reloadDoc builds a policy whose one network rule takes the given decision,
// with a path rule keyed on ${PROJECT_ROOT} so a lost variable is visible.
func reloadDoc(t *testing.T, decision string) *policy.Policy {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(`
version: 1
name: reload
network_rules:
  - name: rule-` + decision + `
    domains: ["example.com"]
    ports: [443]
    decision: ` + decision + `
file_rules:
  - name: project-writes
    paths: ["${PROJECT_ROOT}/**"]
    operations: [write]
    decision: allow
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	return p
}

// reloadApp builds an App with a global engine and a session manager.
func reloadApp(t *testing.T) *App {
	t.Helper()
	global, err := policy.NewEngine(reloadDoc(t, "allow"), false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	return &App{
		policy:   global,
		cfg:      &config.Config{},
		sessions: session.NewManager(16),
	}
}

// sessionWithOwnEngine registers a session holding its own engine, compiled
// with its own PROJECT_ROOT.
func sessionWithOwnEngine(t *testing.T, a *App, id, projectRoot, decision string) *session.Session {
	t.Helper()
	vars := map[string]string{"PROJECT_ROOT": projectRoot, "GIT_ROOT": projectRoot, "HOME": "/home/agent"}
	eng, err := policy.NewEngineWithVariables(reloadDoc(t, decision), false, true, vars)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	s, err := a.sessions.CreateWithID(id, t.TempDir(), "reload")
	if err != nil {
		t.Fatalf("create session %s: %v", id, err)
	}
	a.installSessionEngine(s, eng, vars)
	return s
}

// TestReloadPolicy_ReachesRunningSessions is the property this exists for.
//
// App.SwapPolicy replaces only the process-global engine, and every session
// created through createSession holds its own. A pushed update therefore
// reached sessions created after it and no others -- on every enforcement
// path, not just the network ones.
func TestReloadPolicy_ReachesRunningSessions(t *testing.T) {
	a := reloadApp(t)
	s := sessionWithOwnEngine(t, a, "s1", "/w1", "allow")

	before := s.PolicyEngine()
	if dec := before.CheckNetwork("example.com", 443); dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("before the reload: %q, want allow", dec.EffectiveDecision)
	}

	res, err := a.ReloadPolicy(reloadDoc(t, "deny"))
	if err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if len(res.Updated) != 1 || res.Updated[0] != "s1" {
		t.Fatalf("Updated = %v, want [s1] (skipped: %v)", res.Updated, res.Skipped)
	}

	after := s.PolicyEngine()
	if after == before {
		t.Fatal("the session still holds the engine it started with")
	}
	if dec := after.CheckNetwork("example.com", 443); dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("after the reload: %q, want deny", dec.EffectiveDecision)
	}
	// And the global engine moved too, for sessions that follow it.
	if dec := a.Policy().CheckNetwork("example.com", 443); dec.EffectiveDecision != types.DecisionDeny {
		t.Errorf("the global engine still allows: %q", dec.EffectiveDecision)
	}
}

// TestReloadPolicy_KeepsEachSessionsOwnVariables. Sessions do not share a
// PROJECT_ROOT, so rebuilding them from one document must substitute each
// session's own. Getting this wrong silently widens or narrows every path rule
// in the session.
func TestReloadPolicy_KeepsEachSessionsOwnVariables(t *testing.T) {
	a := reloadApp(t)
	s1 := sessionWithOwnEngine(t, a, "s1", "/w1", "allow")
	s2 := sessionWithOwnEngine(t, a, "s2", "/w2", "allow")

	if _, err := a.ReloadPolicy(reloadDoc(t, "deny")); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	for _, c := range []struct {
		s    *session.Session
		root string
	}{{s1, "/w1"}, {s2, "/w2"}} {
		eng := c.s.PolicyEngine()
		if dec := eng.CheckFile(c.root+"/notes.txt", "write"); dec.EffectiveDecision != types.DecisionAllow {
			t.Errorf("%s: writing under its own root resolved to %q, want allow", c.s.ID, dec.EffectiveDecision)
		}
		other := "/w2"
		if c.root == "/w2" {
			other = "/w1"
		}
		if dec := eng.CheckFile(other+"/notes.txt", "write"); dec.EffectiveDecision == types.DecisionAllow {
			t.Errorf("%s: writing under the OTHER session's root was allowed; the variables were crossed", c.s.ID)
		}
	}
}

// TestReloadPolicy_SkipReasons. A session that cannot be rebuilt keeps the
// engine it has, and the reload says which and why. A pushed policy that
// reached some sessions and not others is the kind of partial enforcement that
// reads as success.
func TestReloadPolicy_SkipReasons(t *testing.T) {
	t.Run("no session engine", func(t *testing.T) {
		a := reloadApp(t)
		s, err := a.sessions.CreateWithID("s1", t.TempDir(), "reload")
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.ReloadPolicy(reloadDoc(t, "deny"))
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Skipped[s.ID]; got != SkipNoSessionEngine {
			t.Errorf("reason = %q, want %q", got, SkipNoSessionEngine)
		}
		if len(res.Updated) != 0 {
			t.Errorf("Updated = %v, want none", res.Updated)
		}
	})

	t.Run("no policy vars", func(t *testing.T) {
		a := reloadApp(t)
		s := sessionWithOwnEngine(t, a, "s1", "/w1", "allow")
		s.SetPolicyVars(nil)
		before := s.PolicyEngine()

		res, err := a.ReloadPolicy(reloadDoc(t, "deny"))
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Skipped[s.ID]; got != SkipNoPolicyVars {
			t.Errorf("reason = %q, want %q", got, SkipNoPolicyVars)
		}
		if s.PolicyEngine() != before {
			t.Error("the session engine was replaced despite having no variables to compile with")
		}
	})

	t.Run("db proxy running", func(t *testing.T) {
		a := reloadApp(t)
		s := sessionWithOwnEngine(t, a, "s1", "/w1", "allow")
		s.SetDBProxy("/run/agentmon/s1/db-services", func() error { return nil })
		before := s.PolicyEngine()

		res, err := a.ReloadPolicy(reloadDoc(t, "deny"))
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Skipped[s.ID]; got != SkipDBProxyRunning {
			t.Errorf("reason = %q, want %q", got, SkipDBProxyRunning)
		}
		if s.PolicyEngine() != before {
			t.Error("a session with a live DB proxy was rebuilt; its rules would name sockets nothing serves")
		}
	})
}

// TestReloadPolicy_OneSkipDoesNotStopTheRest. Refusing the whole reload
// because one session cannot be rebuilt would leave every session on the old
// document, which is worse than reaching most of them and saying so.
func TestReloadPolicy_OneSkipDoesNotStopTheRest(t *testing.T) {
	a := reloadApp(t)
	blocked := sessionWithOwnEngine(t, a, "s-blocked", "/w1", "allow")
	blocked.SetDBProxy("/run/agentmon/s-blocked/db-services", func() error { return nil })
	ok1 := sessionWithOwnEngine(t, a, "s-ok-1", "/w2", "allow")
	ok2 := sessionWithOwnEngine(t, a, "s-ok-2", "/w3", "allow")

	res, err := a.ReloadPolicy(reloadDoc(t, "deny"))
	if err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if len(res.Updated) != 2 {
		t.Fatalf("Updated = %v, want the two sessions that could be rebuilt", res.Updated)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %v, want just the DB session", res.Skipped)
	}
	for _, s := range []*session.Session{ok1, ok2} {
		if dec := s.PolicyEngine().CheckNetwork("example.com", 443); dec.EffectiveDecision != types.DecisionDeny {
			t.Errorf("%s: %q, want deny", s.ID, dec.EffectiveDecision)
		}
	}
}

// TestReloadPolicy_CarriesTheSessionsTorCoordinator.
//
// A session put into Tor-deny holds a coordinator of its own. Rebuilding its
// engine without carrying that across would lift the deny, and the reload
// would look like a success.
func TestReloadPolicy_CarriesTheSessionsTorCoordinator(t *testing.T) {
	a := reloadApp(t)
	a.torPolicy = newGatewayActiveTorPolicy(t) // app-wide policy would ALLOW
	s := sessionWithOwnEngine(t, a, "s1", "/w1", "allow")

	deny := &tor.PolicyAdapter{Policy: newDenyTorPolicy(t)}
	s.PolicyEngine().SetTorPolicy(deny)

	if _, err := a.ReloadPolicy(reloadDoc(t, "deny")); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	eng := s.PolicyEngine()
	if got := eng.TorPolicy(); got != deny {
		t.Fatal("the session's deny coordinator was not carried onto the rebuilt engine")
	}
	dec := eng.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Tor == nil || dec.Tor.Decision != "deny" {
		t.Fatalf("Tor verdict = %+v, want deny", dec.Tor)
	}
}

// TestReloadPolicy_RebuiltEnginesKeepTheirServices. A rebuilt engine goes
// through installSessionEngine, so it gets the threat store and inspector the
// same way a freshly created session does.
func TestReloadPolicy_RebuiltEnginesKeepTheirServices(t *testing.T) {
	a := reloadApp(t)
	a.policy.SetThreatStore(&fakeThreat{domain: "evil.example"}, "deny")
	s := sessionWithOwnEngine(t, a, "s1", "/w1", "allow")

	if _, err := a.ReloadPolicy(reloadDoc(t, "allow")); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	eng := s.PolicyEngine()
	if store, action := eng.ThreatStore(); store == nil || action != "deny" {
		t.Fatal("the rebuilt session engine has no threat store")
	}
	if dec := eng.CheckNetwork("evil.example", 443); dec.EffectiveDecision != types.DecisionDeny {
		t.Errorf("EffectiveDecision = %q for a listed domain, want deny", dec.EffectiveDecision)
	}
}

// TestReloadPolicy_NewGlobalEngineKeepsItsServices. The global engine is built
// at startup with its threat store installed directly; a replacement has to be
// given one, or a reload silently turns the feed off process-wide.
func TestReloadPolicy_NewGlobalEngineKeepsItsServices(t *testing.T) {
	a := reloadApp(t)
	a.policy.SetThreatStore(&fakeThreat{domain: "evil.example"}, "deny")

	if _, err := a.ReloadPolicy(reloadDoc(t, "allow")); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	if store, action := a.Policy().ThreatStore(); store == nil || action != "deny" {
		t.Fatal("the replacement global engine has no threat store")
	}
}

// TestReloadPolicy_BadDocumentChangesNothing. A document that will not compile
// must leave the previous one in force everywhere rather than tearing down the
// global engine first.
func TestReloadPolicy_BadDocumentChangesNothing(t *testing.T) {
	a := reloadApp(t)
	s := sessionWithOwnEngine(t, a, "s1", "/w1", "allow")
	beforeGlobal, beforeSession := a.Policy(), s.PolicyEngine()

	broken := &policy.Policy{
		Version:      1,
		Name:         "broken",
		NetworkRules: []policy.NetworkRule{{Name: "bad", Domains: []string{"["}, Decision: "deny"}},
	}
	if _, err := a.ReloadPolicy(broken); err == nil {
		t.Fatal("a policy that does not compile was accepted")
	}
	if a.Policy() != beforeGlobal {
		t.Error("the global engine was replaced by a document that does not compile")
	}
	if s.PolicyEngine() != beforeSession {
		t.Error("a session engine was replaced by a document that does not compile")
	}

	if _, err := a.ReloadPolicy(nil); err == nil {
		t.Error("a nil document was accepted")
	}
}
