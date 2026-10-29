package netmonitor

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/diffsec/agentmon/internal/approvals"
	dbevents "github.com/diffsec/agentmon/internal/db/events"
	"github.com/diffsec/agentmon/internal/session"
	"github.com/diffsec/agentmon/pkg/types"
)

// FlowRequest is one TCP flow that the macOS system extension captured with
// its transparent proxy.
type FlowRequest struct {
	// Host is the flow's remote endpoint: an IP address, or a hostname when
	// the app connected by name.
	Host string
	Port int
	// Hostname is the name that the app asked for, if the system knows it.
	// The app chooses it, so the gateway trusts it only if it resolves to
	// the address that the flow goes to.
	Hostname string
}

// flowLookupTimeout bounds each DNS lookup that the gateway makes for a flow.
const flowLookupTimeout = 5 * time.Second

// clientHelloTimeout bounds the wait for a TLS ClientHello. A client that
// waits for the server to speak first, such as an SMTP client, gets no
// hostname from it and keeps the decision that its address gave. Tests
// shorten it.
var clientHelloTimeout = 2 * time.Second

// NewFlowGateway returns a gateway for one session's flows from the macOS
// system extension. It has no listener: the policy socket server hands it
// each flow with ServeFlow. It applies the same policy checks, approvals,
// redirects and events as the Linux transparent gateway.
func NewFlowGateway(sessionID string, sess *session.Session, engine EngineFunc, approvalsMgr *approvals.Manager, emit Emitter, dbBypass *dbevents.BypassEmitter) *TransparentTCP {
	t := &TransparentTCP{
		sessionID: sessionID,
		sess:      sess,
		policy:    engine,
		approvals: approvalsMgr,
		emit:      emit,
	}
	t.SetDBBypassEmitter(dbBypass)
	return t
}

// lookupIP resolves a hostname. Tests replace it.
var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// ServeFlow decides one flow from the system extension and forwards it.
//
// The extension does not know the policy result, so the gateway reports it:
// accepted runs once the upstream connection is open, and refused runs if the
// policy denies the flow or the dial fails. ServeFlow closes conn.
//
// The flow's hostname comes from one of three places, in this order: the
// endpoint itself when the app connected by name, the name that the app
// asked for, or the SNI in the first TLS record. The last two are chosen by
// the app, so each one counts only if it resolves to the flow's address.
// Without that check, a client could name an allowed domain and connect to
// any address.
func (t *TransparentTCP) ServeFlow(conn net.Conn, req FlowRequest, accepted func() error, refused func(reason string)) error {
	flow := gatewayFlow{dstPort: req.Port, accepted: accepted, refused: refused}

	if ip := net.ParseIP(req.Host); ip != nil {
		flow.dstIP = ip
		if req.Hostname != "" && resolvesTo(req.Hostname, ip) {
			flow.domain = normalizeHost(req.Hostname)
		}
	} else {
		ips, err := lookupWithTimeout(req.Host)
		if err != nil || len(ips) == 0 {
			flow.refuse("resolve " + req.Host + ": no address")
			_ = conn.Close()
			return nil
		}
		flow.dstIP = preferIPv4(ips)
		flow.domain = normalizeHost(req.Host)
	}

	// An address alone is often not enough for a domain rule. Read the
	// ClientHello only when the address alone is denied, because a client
	// that waits for the server would otherwise wait for clientHelloTimeout.
	if flow.domain == "" && t.policyDecision(flow.dstIP.String(), flow.dstIP, flow.dstPort).EffectiveDecision == types.DecisionDeny {
		prefix, sni := peekClientHello(conn)
		if sni != "" && resolvesTo(sni, flow.dstIP) {
			flow.domain = normalizeHost(sni)
		}
		if len(prefix) > 0 {
			conn = &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
		}
	}

	return t.serve(conn, flow)
}

// preferIPv4 picks the first IPv4 address, because many networks have no
// IPv6 route. It falls back to the first address.
func preferIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return ips[0]
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func lookupWithTimeout(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), flowLookupTimeout)
	defer cancel()
	return lookupIP(ctx, host)
}

// resolvesTo reports whether host resolves to ip now.
func resolvesTo(host string, ip net.IP) bool {
	ips, err := lookupWithTimeout(host)
	if err != nil {
		return false
	}
	for _, candidate := range ips {
		if candidate.Equal(ip) {
			return true
		}
	}
	return false
}

// peekClientHello reads the first TLS record from conn and returns the bytes
// it read, which the caller must forward, and the SNI hostname, if any.
func peekClientHello(conn net.Conn) (prefix []byte, sni string) {
	var read bytes.Buffer
	_ = conn.SetReadDeadline(time.Now().Add(clientHelloTimeout))
	record, err := readTLSRecord(io.TeeReader(conn, &read))
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return read.Bytes(), ""
	}
	loc, err := findSNI(record)
	if err != nil {
		return read.Bytes(), ""
	}
	return read.Bytes(), string(record[loc.sniNameStart:loc.sniNameEnd])
}

// prefixConn replays bytes that the gateway already read before the rest of
// the connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite keeps the half-close that splice relies on.
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
