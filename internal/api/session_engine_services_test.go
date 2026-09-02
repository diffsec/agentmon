package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/session"
	"github.com/diffsec/agentmon/internal/tor"
	"github.com/diffsec/agentmon/pkg/types"
)

// fakeThreat is a policy.ThreatChecker that flags one domain.
type fakeThreat struct{ domain string }

func (f *fakeThreat) Check(domain string) (policy.ThreatCheckResult, bool) {
	if domain != f.domain {
		return policy.ThreatCheckResult{}, false
	}
	return policy.ThreatCheckResult{
		FeedName:      "test-feed",
		MatchedDomain: domain,
	}, true
}

func inspectCommandPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(`
version: 1
name: t
inspection:
  profiles:
    pii:
      provider: regex
      categories: [secret]
command_rules:
  - name: inspect-curl
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [pii]
      on_violation: deny
      on_failure: fail_closed
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	return p
}

// TestAttachEngineServices_ThreatStoreReachesSessionEngines.
//
// The threat feed store is installed once, on the process-global engine, at
// server startup (internal/server/server.go). Every session created through
// createSession gets its own engine from NewEngineWithVariables, which carries
// no attachments -- so a feed the operator configured checked no domain in any
// session, and nothing said so.
func TestAttachEngineServices_ThreatStoreReachesSessionEngines(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "g"}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	global.SetThreatStore(&fakeThreat{domain: "evil.example"}, "deny")

	a := &App{policy: global}

	sessionEng, err := policy.NewEngineWithVariables(&policy.Policy{Version: 1, Name: "s"}, false, true, nil)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	if store, _ := sessionEng.ThreatStore(); store != nil {
		t.Fatal("a freshly built engine already had a threat store; this test proves nothing")
	}

	a.attachEngineServices(sessionEng)

	store, action := sessionEng.ThreatStore()
	if store == nil {
		t.Fatal("the session engine has no threat store; the configured feed checks nothing in this session")
	}
	if action != "deny" {
		t.Errorf("threat action = %q, want the process-wide deny", action)
	}
	dec := sessionEng.CheckNetwork("evil.example", 443)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Errorf("EffectiveDecision = %q for a listed domain, want deny", dec.EffectiveDecision)
	}
}

// TestAttachEngineServices_InspectorReachesSessionEngines.
//
// This one is a regression in the other direction: #42 made the engine resolve
// a command rule's inspection itself, which assumes the engine carries an
// inspector. Session engines did not, so every `decision: inspect` command rule
// resolved through on_failure and denied -- in exactly the sessions that
// enforce the policy. server.wireInspection refuses to start a policy the host
// cannot inspect for, which made the failure look impossible.
func TestAttachEngineServices_InspectorReachesSessionEngines(t *testing.T) {
	pol := inspectCommandPolicy(t)

	global, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{policy: global, inspectRegistry: testInspectRegistry(t)}

	sessionEng, err := policy.NewEngineWithVariables(pol, false, true, nil)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	if sessionEng.Inspector() != nil {
		t.Fatal("a freshly built engine already had an inspector; this test proves nothing")
	}

	a.attachEngineServices(sessionEng)

	if sessionEng.Inspector() == nil {
		t.Fatal("the session engine has no inspector; every inspect command rule denies through on_failure")
	}
	// A secret in the argv is what the regex provider is configured to find,
	// so the rule resolves to its on_violation rather than its on_failure.
	dec := sessionEng.CheckCommand("curl", []string{"-H", "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz012345"})
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny", dec.EffectiveDecision)
	}
	if !strings.Contains(dec.Message, "secret") {
		t.Errorf("message = %q, want the finding rather than an inspection failure", dec.Message)
	}
	if strings.Contains(dec.Message, "inspection failed") {
		t.Errorf("the rule failed closed instead of inspecting: %q", dec.Message)
	}

	// Clean argv passes, which is what proves the inspector actually ran
	// rather than the rule denying for some other reason.
	clean := sessionEng.CheckCommand("curl", []string{"https://example.com"})
	if clean.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q on clean argv, want allow (message %q)", clean.EffectiveDecision, clean.Message)
	}
}

// testInspectRegistry builds a registry over the in-process regex provider, so
// the test needs no model, no sidecar and no network.
func testInspectRegistry(t *testing.T) *inspect.Registry {
	t.Helper()
	rx, err := provider.NewRegex(nil)
	if err != nil {
		t.Fatalf("regex provider: %v", err)
	}
	return inspect.NewRegistry([]inspect.Provider{rx}, &inspect.PrivacyConfig{}, 0)
}

// TestAttachEngineServices_SkipsTheGlobalEngine. The global engine already has
// everything, and re-attaching would race the checks reading it.
func TestAttachEngineServices_SkipsTheGlobalEngine(t *testing.T) {
	global, err := policy.NewEngine(inspectCommandPolicy(t), false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{policy: global, torPolicy: newDenyTorPolicy(t), inspectRegistry: testInspectRegistry(t)}

	a.attachEngineServices(global)

	// Tor alone does not prove the outer guard fired: attachSessionTor has an
	// identical one. The inspector does, because nothing else skips it.
	if global.Inspector() != nil {
		t.Error("the global engine was given an inspector by attachEngineServices")
	}
	dec := global.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Tor != nil {
		t.Error("the global engine was decorated by attachEngineServices")
	}
}

// TestAttachEngineServices_StillAttachesTor. Tor was the one attachment a
// session engine already got, and folding it into the shared helper must not
// drop it.
func TestAttachEngineServices_StillAttachesTor(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "g"}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{policy: global, torPolicy: newDenyTorPolicy(t)}

	sessionEng, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "s"}, false, true)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	a.attachEngineServices(sessionEng)

	dec := sessionEng.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Tor == nil {
		t.Fatal("Tor was not attached")
	}
	if dec.Tor.Decision != "deny" {
		t.Errorf("Tor verdict = %q, want deny", dec.Tor.Decision)
	}
}

// TestAttachEngineServices_NoThreatStoreIsNotAnError. A daemon with no feed
// configured must not have every session engine given an empty one, which would
// set threatAction and change nothing but the audit trail.
func TestAttachEngineServices_NoThreatStoreIsNotAnError(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "g"}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{policy: global}

	sessionEng, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "s"}, false, true)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	a.attachEngineServices(sessionEng)

	if store, action := sessionEng.ThreatStore(); store != nil || action != "" {
		t.Errorf("ThreatStore() = (%v, %q), want empty", store, action)
	}
}

// TestAttachEngineServices_NilSafe. It runs on every session creation path, so
// a nil App or engine must be a no-op rather than a panic that fails the
// request.
func TestAttachEngineServices_NilSafe(t *testing.T) {
	var a *App
	a.attachEngineServices(nil)

	global, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "g"}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	(&App{policy: global}).attachEngineServices(nil)
}

// TestInstallSessionEngine_DoesBothHalves. The attach and the install are one
// operation; a path that did only the second is how sessions ended up
// enforcing a policy with no threat store and no inspector.
func TestInstallSessionEngine_DoesBothHalves(t *testing.T) {
	global, err := policy.NewEngine(inspectCommandPolicy(t), false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	global.SetThreatStore(&fakeThreat{domain: "evil.example"}, "deny")
	a := &App{policy: global, inspectRegistry: testInspectRegistry(t)}

	sessionEng, err := policy.NewEngineWithVariables(inspectCommandPolicy(t), false, true, nil)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	s := &session.Session{ID: "s1"}

	a.installSessionEngine(s, sessionEng, nil)

	got := s.PolicyEngine()
	if got != sessionEng {
		t.Fatal("the engine was not installed on the session")
	}
	if store, _ := got.ThreatStore(); store == nil {
		t.Error("the installed engine has no threat store")
	}
	if got.Inspector() == nil {
		t.Error("the installed engine has no inspector")
	}
}

func TestInstallSessionEngine_NilSafe(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "g"}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	a := &App{policy: global}
	a.installSessionEngine(nil, global, nil)
	a.installSessionEngine(&session.Session{ID: "s"}, nil, nil)
	if eng := (&session.Session{ID: "s"}).PolicyEngine(); eng != nil {
		t.Error("a nil engine was installed")
	}
}

// TestAttachDenyTor_CloneKeepsTheServices. attachDenyTor builds a brand-new
// engine from a clone of the global policy. Attaching deny-Tor to a session
// must not be the thing that turns off its threat feed and content inspection.
func TestAttachDenyTor_CloneKeepsTheServices(t *testing.T) {
	global, err := policy.NewEngine(inspectCommandPolicy(t), false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	global.SetThreatStore(&fakeThreat{domain: "evil.example"}, "deny")
	a := &App{policy: global, cfg: &config.Config{}, inspectRegistry: testInspectRegistry(t)}

	s := &session.Session{ID: "s1"}
	if !a.attachDenyTor(s, newDenyTorPolicy(t)) {
		t.Fatal("attachDenyTor did not install a coordinator")
	}

	eng := s.PolicyEngine()
	if eng == nil || eng == global {
		t.Fatalf("session engine = %v, want a clone", eng)
	}
	if store, action := eng.ThreatStore(); store == nil || action != "deny" {
		t.Error("the deny-Tor clone lost the threat store")
	}
	if eng.Inspector() == nil {
		t.Error("the deny-Tor clone lost the inspector")
	}
	if dec := eng.CheckExecve("/usr/bin/tor", []string{"tor"}, 0); dec.Tor == nil {
		t.Error("the clone lost its Tor coordinator")
	}
}

// TestSetPolicyEngineOnlyCalledViaInstall keeps the three halves from coming
// apart again.
//
// Every path that gives a session its own engine has to go through
// installSessionEngine, which attaches the services, records the policy
// variables and installs the engine. A unit test cannot reach the
// createSession call sites without a full store, broker and workspace harness,
// and mutations that swapped one back to a bare SetPolicyEngine, or dropped
// the SetPolicyVars beside it, survived every behavioural test here. Reading
// the source is what catches them.
func TestSetPolicyEngineOnlyCalledViaInstall(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			// A build-tagged file for another platform still parses; a
			// genuine syntax error is someone else's failing build.
			t.Fatalf("parse %s: %v", name, err)
		}

		var enclosing string
		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "SetPolicyEngine" && sel.Sel.Name != "SetPolicyVars") {
				return true
			}
			// proxy.Proxy has a method of the same name; only the session's
			// matters here.
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Name != "s" {
				return true
			}
			if enclosing != "installSessionEngine" {
				t.Errorf("%s: %s calls s.%s directly; go through installSessionEngine so the engine gets the threat store, the inspector and its policy variables",
					fset.Position(call.Pos()), enclosing, sel.Sel.Name)
			}
			return true
		})
	}
}

// nilVarsIsCorrect names the functions that legitimately install a session
// engine with no policy variables. attachDenyTor is the only one: its clone is
// compiled from the global document, which carries no substitutions either.
var nilVarsIsCorrect = map[string]bool{"attachDenyTor": true}

// TestInstallSessionEngineIsGivenTheVariables.
//
// A session installed with nil variables cannot be rebuilt when a policy is
// pushed: ReloadPolicy skips it with SkipNoPolicyVars and it keeps enforcing
// the document it started with. Passing nil at a createSession call site is a
// one-token mistake that no behavioural test in this package can reach, and a
// mutation doing exactly that survived every one of them.
func TestInstallSessionEngineIsGivenTheVariables(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		var enclosing string
		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "installSessionEngine" || len(call.Args) != 3 {
				return true
			}
			if nilVarsIsCorrect[enclosing] {
				return true
			}
			if id, ok := call.Args[2].(*ast.Ident); ok && id.Name == "nil" {
				t.Errorf("%s: %s installs a session engine with nil policy variables; that session cannot be rebuilt when a policy is pushed",
					fset.Position(call.Pos()), enclosing)
			}
			return true
		})
	}
}

// TestAttachSessionTor_DoesNotReplaceADenyCoordinator.
//
// attachDenyTor installs a session-specific deny coordinator and then installs
// the engine, which runs attachSessionTor. Without a guard, the app-wide Tor
// policy overwrites the deny one and the session silently stops being denied.
// That regression is what TestApplyTorFailClosed_ProfileSession_DeniesTor
// caught; this pins the guard directly.
func TestAttachSessionTor_DoesNotReplaceADenyCoordinator(t *testing.T) {
	global, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "g"}, false, true)
	if err != nil {
		t.Fatalf("global engine: %v", err)
	}
	// An app-wide policy that would ALLOW, so a replacement is visible.
	a := &App{policy: global, torPolicy: newGatewayActiveTorPolicy(t), cfg: &config.Config{}}

	sessionEng, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "s"}, false, true)
	if err != nil {
		t.Fatalf("session engine: %v", err)
	}
	deny := &tor.PolicyAdapter{Policy: newDenyTorPolicy(t)}
	sessionEng.SetTorPolicy(deny)

	a.attachSessionTor(sessionEng)

	if got := sessionEng.TorPolicy(); got != deny {
		t.Fatal("the session's deny coordinator was replaced by the app-wide policy")
	}
	dec := sessionEng.CheckExecve("/usr/bin/tor", []string{"tor"}, 0)
	if dec.Tor == nil || dec.Tor.Decision != "deny" {
		t.Fatalf("Tor verdict = %+v, want deny", dec.Tor)
	}
}
