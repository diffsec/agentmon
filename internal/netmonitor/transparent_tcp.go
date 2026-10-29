package netmonitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diffsec/agentmon/internal/approvals"
	dbevents "github.com/diffsec/agentmon/internal/db/events"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/session"
	"github.com/diffsec/agentmon/internal/tor"
	"github.com/diffsec/agentmon/pkg/types"
	"github.com/google/uuid"
)

type TransparentTCP struct {
	sessionID string
	sess      *session.Session
	dnsCache  *DNSCache
	policy    EngineFunc
	approvals *approvals.Manager
	emit      Emitter
	dbBypass  atomic.Pointer[dbevents.BypassEmitter]

	torGW atomic.Pointer[torGatewayConfig]

	ln   net.Listener
	wg   sync.WaitGroup
	done chan struct{}
}

func (t *TransparentTCP) SetDBBypassEmitter(em *dbevents.BypassEmitter) {
	if t == nil {
		return
	}
	t.dbBypass.Store(em)
}

// gatewayFlow is one connection that the gateway decides and forwards.
type gatewayFlow struct {
	dstIP   net.IP
	dstPort int
	// domain is a hostname that the caller already checked against dstIP.
	// If it is empty, the gateway looks the address up in its DNS cache.
	domain string
	// accepted, if set, runs after the upstream dial succeeds and before any
	// bytes are forwarded. If it returns an error, the flow is dropped.
	accepted func() error
	// refused, if set, runs when the policy denies the flow or the upstream
	// dial fails.
	refused func(reason string)
}

func (f gatewayFlow) refuse(reason string) {
	if f.refused != nil {
		f.refused(reason)
	}
}

// serve decides one flow, dials the upstream, and forwards bytes in both
// directions. The Linux gateway gets the destination from SO_ORIGINAL_DST.
// The macOS gateway gets it from the system extension.
func (t *TransparentTCP) serve(conn net.Conn, flow gatewayFlow) error {
	defer conn.Close()
	dstIP, dstPort := flow.dstIP, flow.dstPort
	remote := net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", dstPort))

	commandID, pid := "", 0
	if t.sess != nil {
		commandID, pid = t.sess.CurrentCommandAttribution() // atomic snapshot; pid reused by the relay_ip/socks_port emit below
	}
	engine := t.policyEngine()

	if cfg, ok := t.torGatewayFor(dstPort); ok {
		return handleTorSocks(conn, cfg.upstream, cfg.pol, t.emit, t.sessionID, commandID, pid)
	}

	domain := flow.domain
	if domain == "" {
		domain = dstIP.String()
	}
	if flow.domain == "" && t.dnsCache != nil {
		if d, ok := t.dnsCache.LookupByIP(dstIP, time.Now().UTC()); ok && d != "" {
			domain = d
		}
	}

	redirectHostPort := net.JoinHostPort(domain, fmt.Sprintf("%d", dstPort))
	var redirectResult *policy.ConnectRedirectResult
	if engine != nil {
		result := engine.EvaluateConnectRedirect(redirectHostPort)
		if result.Matched {
			redirectResult = result
			if result.Visibility != "silent" {
				emitConnectRedirectEvent(context.Background(), t.emit, t.sessionID, commandID, domain, redirectHostPort, dstPort, result)
			}
		}
	}

	dec := t.checkConnectNetwork(context.Background(), commandID, domain, redirectHostPort, dstIP, dstPort, redirectResult)
	t.emitTorControl(commandID, pid, dec.Tor)
	eventFields := map[string]any{}
	if redirectResult != nil {
		if redirectResult.RedirectTo != "" {
			eventFields["redirect_to"] = redirectResult.RedirectTo
		}
		if redirectResult.RedirectToUnix != "" {
			eventFields["redirect_to_unix"] = redirectResult.RedirectToUnix
		}
		eventFields["redirect_tls"] = redirectResult.TLSMode
		if redirectResult.SNI != "" {
			eventFields["redirect_sni"] = redirectResult.SNI
		}
	}
	connectEv := t.netEvent("net_connect", commandID, domain, remote, dstPort, dec, eventFields)
	_ = t.emit.AppendEvent(context.Background(), connectEv)
	t.emit.Publish(connectEv)

	if dec.EffectiveDecision == types.DecisionDeny {
		t.emitDBBypassAttempt(context.Background(), commandID, pid, dec.Rule, dec.Message)
		flow.refuse("denied by policy rule " + dec.Rule)
		return nil
	}

	emitMCPConnectionIfMatched(context.Background(), t.sess, t.emit, t.sessionID, commandID, domain, remote, dstPort)

	dialTarget := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: remote,
		OriginalPort:     fmt.Sprintf("%d", dstPort),
		Redirect:         redirectResult,
	})
	up, err := net.DialTimeout(dialTarget.Network, dialTarget.Address, 20*time.Second)
	if err != nil {
		flow.refuse("dial " + dialTarget.Address + ": " + err.Error())
		return nil
	}
	defer up.Close()
	if flow.accepted != nil {
		if err := flow.accepted(); err != nil {
			return nil
		}
	}

	// conn->up = upBytes (sent), up->conn = downBytes (received).
	upBytes, downBytes := splice(conn, up)

	closeEv := t.netEvent("net_close", commandID, domain, remote, dstPort, dec, map[string]any{"bytes_sent": upBytes, "bytes_received": downBytes})
	_ = t.emit.AppendEvent(context.Background(), closeEv)
	t.emit.Publish(closeEv)
	return nil
}

// Close stops the listener, if there is one, and waits for its flows.
func (t *TransparentTCP) Close() error {
	if t == nil || t.ln == nil {
		return nil
	}
	close(t.done)
	err := t.ln.Close()
	t.wg.Wait()
	return err
}

func (t *TransparentTCP) policyDecision(domain string, ip net.IP, port int) policy.Decision {
	engine := t.policyEngine()
	if engine == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	return engine.CheckNetworkIP(domain, ip, port)
}

func (t *TransparentTCP) checkConnectNetwork(ctx context.Context, commandID string, domain string, hostPort string, ip net.IP, port int, redirect *policy.ConnectRedirectResult) policy.Decision {
	dec := t.policyDecision(domain, ip, port)
	if allowUnixRedirectForDBUnavoidability(t.policyEngine(), dec, redirect) {
		return allowConnectRedirectDecision(redirect)
	}
	dec = t.maybeApprove(ctx, commandID, dec, "network", hostPort)
	return dec
}

func (t *TransparentTCP) policyEngine() *policy.Engine {
	if t == nil {
		return nil
	}
	if t.sess != nil {
		if engine := t.sess.PolicyEngine(); engine != nil {
			return engine
		}
	}
	if t.policy == nil {
		return nil
	}
	return t.policy()
}

func (t *TransparentTCP) emitDBBypassAttempt(ctx context.Context, commandID string, pid int, ruleName string, reason string) {
	if t == nil {
		return
	}
	em := t.dbBypass.Load()
	if em == nil {
		return
	}
	em.EmitIfDBUnavoidabilityDeny(ctx, dbevents.BypassAttempt{
		Engine:          t.policyEngine(),
		SessionID:       t.sessionID,
		CommandID:       commandID,
		ProcessID:       pid,
		ProcessIdentity: dbBypassProcessIdentity(t.sessionID, commandID),
		RuleName:        ruleName,
		Reason:          reason,
	})
}

// emitTorControl publishes a tor_control event for a Tor verdict carried on a
// connect decision. pid is the session's current command-process PID (root of
// the running command's process tree), not necessarily the exact leaf caller.
func (t *TransparentTCP) emitTorControl(commandID string, pid int, tv *policy.TorVerdict) {
	if tv == nil || t.emit == nil {
		return
	}
	tev := tor.BuildControlEvent(t.sessionID, commandID, pid, tor.Verdict{
		Vector: tv.Vector, Mode: tv.Mode, Decision: tv.Decision, Target: tv.Target,
	})
	_ = t.emit.AppendEvent(context.Background(), tev)
	t.emit.Publish(tev)
}

func (t *TransparentTCP) maybeApprove(ctx context.Context, commandID string, dec policy.Decision, kind string, target string) policy.Decision {
	if dec.PolicyDecision != types.DecisionApprove || dec.EffectiveDecision != types.DecisionApprove {
		return dec
	}
	if t.approvals == nil {
		return dec
	}
	req := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: t.sessionID,
		CommandID: commandID,
		Kind:      kind,
		Target:    target,
		Rule:      dec.Rule,
		Message:   dec.Message,
	}
	res, err := t.approvals.RequestApproval(ctx, req)
	if dec.Approval != nil {
		dec.Approval.ID = req.ID
	}
	if err != nil || !res.Approved {
		dec.EffectiveDecision = types.DecisionDeny
	} else {
		dec.EffectiveDecision = types.DecisionAllow
	}
	return dec
}

func (t *TransparentTCP) netEvent(evType string, commandID string, domain string, remote string, port int, dec policy.Decision, fields map[string]any) types.Event {
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: t.sessionID,
		CommandID: commandID,
		Domain:    domain,
		Remote:    remote,
		Fields:    fields,
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
			Approval:          dec.Approval,
			ThreatFeed:        dec.ThreatFeed,
			ThreatMatch:       dec.ThreatMatch,
			ThreatAction:      dec.ThreatAction,
		},
	}
	return ev
}

type torGatewayConfig struct {
	pol        TorGatewayPolicy
	upstream   string
	socksPorts map[int]struct{}
}

// SetTorGateway enables (or, with nil/empty args, disables) Phase 2 onion
// gateway routing for connections whose original destination is a Tor SOCKS
// port. Safe to call concurrently.
func (t *TransparentTCP) SetTorGateway(pol TorGatewayPolicy, upstream string, socksPorts []int) {
	if t == nil {
		return
	}
	if pol == nil || upstream == "" || len(socksPorts) == 0 {
		t.torGW.Store(nil)
		return
	}
	ports := make(map[int]struct{}, len(socksPorts))
	for _, p := range socksPorts {
		ports[p] = struct{}{}
	}
	t.torGW.Store(&torGatewayConfig{pol: pol, upstream: upstream, socksPorts: ports})
}

// torGatewayFor returns the gateway config when it is active and port is a
// configured Tor SOCKS port.
func (t *TransparentTCP) torGatewayFor(port int) (*torGatewayConfig, bool) {
	cfg := t.torGW.Load()
	if cfg == nil || !cfg.pol.GatewayActive() {
		return nil, false
	}
	if _, ok := cfg.socksPorts[port]; !ok {
		return nil, false
	}
	return cfg, true
}
