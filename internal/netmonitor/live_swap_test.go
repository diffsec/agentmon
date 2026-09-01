package netmonitor

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/session"
	"github.com/diffsec/agentmon/pkg/types"
)

// swapEngine returns an EngineFunc backed by a pointer a test can replace,
// standing in for App.SwapPolicy.
type swapEngine struct {
	mu  sync.Mutex
	eng *policy.Engine
}

func (s *swapEngine) get() *policy.Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng
}

func (s *swapEngine) set(e *policy.Engine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eng = e
}

func networkEngine(t *testing.T, domain, decision string) *policy.Engine {
	t.Helper()
	yaml := "version: 1\nname: live\nnetwork_rules:\n  - name: rule-" + decision +
		"\n    domains: [\"" + domain + "\"]\n    ports: [443]\n    decision: " + decision + "\n"
	p, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	e, err := policy.NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// TestLiveSwap_ObservedByEveryNetworkPath is the regression test for the
// reason this change exists.
//
// StartProxy, StartTransparentTCP and StartDNS captured *policy.Engine at
// construction, so App.SwapPolicy -- the live install path in
// internal/server/wtp.go -- replaced the engine every command-time check read
// while these three went on enforcing the policy that was live when the
// session started. A live policy update that silently misses three
// enforcement paths looks exactly like one that worked.
func TestLiveSwap_ObservedByEveryNetworkPath(t *testing.T) {
	sw := &swapEngine{eng: networkEngine(t, "example.com", "allow")}
	ctx := context.Background()

	paths := map[string]func() policy.Decision{
		"proxy": func() policy.Decision {
			p := &Proxy{sessionID: "s", policy: sw.get, emit: &stubEmitter{}}
			return p.checkNetwork(ctx, "example.com", 443)
		},
		"dns": func() policy.Decision {
			d := &DNSInterceptor{sessionID: "s", policy: sw.get, emit: &stubEmitter{}}
			return d.policyDecision(ctx, "example.com", 443)
		},
	}

	for name, check := range paths {
		t.Run(name, func(t *testing.T) {
			if dec := check(); dec.EffectiveDecision != types.DecisionAllow {
				t.Fatalf("before the swap: EffectiveDecision = %q, want allow", dec.EffectiveDecision)
			}
		})
	}

	// The operator pushes a policy that denies what the old one allowed.
	sw.set(networkEngine(t, "example.com", "deny"))

	for name, check := range paths {
		t.Run(name+" after swap", func(t *testing.T) {
			dec := check()
			if dec.EffectiveDecision != types.DecisionDeny {
				t.Fatalf("EffectiveDecision = %q after a live swap, want deny; this path is still enforcing the previous policy", dec.EffectiveDecision)
			}
		})
	}
}

// TestDNSPrefersTheSessionEngine. Proxy and TransparentTCP have always
// preferred the session's own engine; DNS read the process-global one instead.
// A session created through api.createSession gets an engine compiled with its
// own PROJECT_ROOT and GIT_ROOT, so DNS was answering from a different policy
// than every other path in the same session.
func TestDNSPrefersTheSessionEngine(t *testing.T) {
	sw := &swapEngine{eng: networkEngine(t, "example.com", "allow")}
	sess := &session.Session{ID: "s1"}
	sess.SetPolicyEngine(networkEngine(t, "example.com", "deny"))

	d := &DNSInterceptor{sessionID: "s1", sess: sess, policy: sw.get, emit: &stubEmitter{}}

	dec := d.policyDecision(context.Background(), "example.com", 443)
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("EffectiveDecision = %q, want deny from the session's own engine", dec.EffectiveDecision)
	}
	if dec.Rule != "rule-deny" {
		t.Errorf("rule = %q, want the session engine's rule", dec.Rule)
	}
}

// TestSessionEngineStillWinsOverTheGetter pins the precedence the getter must
// not disturb. A session with its own engine is enforcing a policy compiled
// for it, and the process-global one must not override that.
//
// This is also where the remaining gap lives: App.SwapPolicy replaces only the
// global engine, so a session holding its own keeps enforcing the policy it
// started with -- on every path, not just these three. Closing that means
// recompiling each session's engine from the new document with that session's
// own variables, which is separate work.
func TestSessionEngineStillWinsOverTheGetter(t *testing.T) {
	sw := &swapEngine{eng: networkEngine(t, "example.com", "allow")}
	sess := &session.Session{ID: "s1"}
	sessionEngine := networkEngine(t, "example.com", "deny")
	sess.SetPolicyEngine(sessionEngine)

	for name, got := range map[string]*policy.Engine{
		"proxy": (&Proxy{sessionID: "s1", sess: sess, policy: sw.get}).policyEngine(),
		"dns":   (&DNSInterceptor{sessionID: "s1", sess: sess, policy: sw.get}).policyEngine(),
	} {
		if got != sessionEngine {
			t.Errorf("%s: resolved to the global engine, want the session's own", name)
		}
	}

	// And a global swap does not disturb that.
	sw.set(networkEngine(t, "example.com", "allow"))
	if got := (&Proxy{sessionID: "s1", sess: sess, policy: sw.get}).policyEngine(); got != sessionEngine {
		t.Error("a global swap overrode a session's own engine")
	}
}

// TestNilEngineFuncIsSafe. The getter is supplied by the caller, and a nil one
// must degrade to "no engine" rather than panicking inside a connection
// handler -- where the panic would take the interceptor down and remove
// enforcement entirely.
func TestNilEngineFuncIsSafe(t *testing.T) {
	if got := (&Proxy{sessionID: "s"}).policyEngine(); got != nil {
		t.Error("proxy: want nil")
	}
	if got := (&DNSInterceptor{sessionID: "s"}).policyEngine(); got != nil {
		t.Error("dns: want nil")
	}

	// A getter that itself returns nil is the same case.
	nilFunc := EngineFunc(func() *policy.Engine { return nil })
	d := &DNSInterceptor{sessionID: "s", policy: nilFunc, emit: &stubEmitter{}}
	dec := d.policyDecision(context.Background(), "example.com", 443)
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q with no engine, want the documented allow", dec.EffectiveDecision)
	}
}

// TestLiveSwap_ResolvedPerDecision. Resolving once and caching would
// reintroduce the bug for every connection the interceptor has already seen.
func TestLiveSwap_ResolvedPerDecision(t *testing.T) {
	calls := 0
	sw := &swapEngine{eng: networkEngine(t, "example.com", "allow")}
	counting := EngineFunc(func() *policy.Engine {
		calls++
		return sw.get()
	})
	p := &Proxy{sessionID: "s", policy: counting, emit: &stubEmitter{}}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		p.checkNetwork(ctx, "example.com", 443)
	}
	if calls < 3 {
		t.Fatalf("the getter was called %d times for 3 decisions; a cached engine would not see the next swap", calls)
	}
}

// TestLiveSwap_DNSRedirectPathObservesIt. The redirect check runs before the
// allow/deny decision and reads the engine separately, so it is its own path
// through this fix. A dns_redirects rule pushed in a policy update has to take
// effect on the next query, not the next session.
func TestLiveSwap_DNSRedirectPathObservesIt(t *testing.T) {
	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("udp listen not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer serverPC.Close()

	up := startUDPUpstream(t)
	defer up.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = up.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, _, e := up.ReadFrom(buf); e != nil {
				return
			}
		}
	}()

	// Before: a policy with no redirect rules.
	plain := networkEngine(t, "example.com", "allow")

	// After: the same rule plus a dns_redirects entry.
	withRedirect, err := policy.LoadFromBytes([]byte(`
version: 1
name: live
network_rules:
  - name: rule-allow
    domains: ["example.com"]
    ports: [443]
    decision: allow
dns_redirects:
  - name: pin-example
    match: "^example\\.com$"
    resolve_to: "127.0.0.53"
`))
	if err != nil {
		t.Fatalf("load redirect policy: %v", err)
	}
	if err := withRedirect.Validate(); err != nil {
		t.Fatalf("validate redirect policy: %v", err)
	}
	redirectEngine, err := policy.NewEngine(withRedirect, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	sw := &swapEngine{eng: plain}
	em := &captureEmitter{}
	d := &DNSInterceptor{
		sessionID: "s1",
		pc:        serverPC,
		upstream:  up.LocalAddr().String(),
		emit:      em,
		policy:    sw.get,
		dnsCache:  NewDNSCache(time.Minute),
	}

	client, err := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}

	_ = d.handle(client, makeDNSQuery(t, "example.com", 1))
	if countEvents(em.events, "dns_redirect") != 0 {
		t.Fatal("a redirect fired before the rule existed")
	}

	sw.set(redirectEngine)

	_ = d.handle(client, makeDNSQuery(t, "example.com", 2))
	if got := countEvents(em.events, "dns_redirect"); got != 1 {
		t.Fatalf("dns_redirect events = %d after the swap, want 1; the redirect path is still reading the previous policy", got)
	}
	if domain, ok := d.dnsCache.LookupByIP(net.ParseIP("127.0.0.53"), time.Now()); !ok || domain != "example.com" {
		t.Errorf("dns cache reverse lookup = %q (ok=%v), want example.com; the redirected address was not recorded", domain, ok)
	}
}

func countEvents(evs []types.Event, kind string) int {
	n := 0
	for _, e := range evs {
		if e.Type == kind {
			n++
		}
	}
	return n
}
