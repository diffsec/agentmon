package netmonitor

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

// flowTestGateway returns a gateway whose policy allows allowed.test on any
// port and denies everything else, and a fake resolver.
func flowTestGateway(t *testing.T, dns map[string]string) *TransparentTCP {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "flow-test",
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-test-domain", Domains: []string{"allowed.test"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	old := lookupIP
	lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		if ip, ok := dns[host]; ok {
			return []net.IP{net.ParseIP(ip)}, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { lookupIP = old })
	return NewFlowGateway("s1", nil, func() *policy.Engine { return engine }, nil, &captureEmitter{}, nil)
}

// upstream accepts one connection and returns what it reads.
func upstream(t *testing.T) (port int, got <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		ch <- b
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

type flowResult struct {
	accepted bool
	reason   string
}

// runFlow serves one flow and writes payload from the client side once the
// flow is accepted, or at once if sendFirst is set.
func runFlow(t *testing.T, gw *TransparentTCP, req FlowRequest, payload []byte, sendFirst bool) flowResult {
	t.Helper()
	client, server := net.Pipe()
	res := make(chan flowResult, 1)
	go func() {
		_ = gw.ServeFlow(server, req,
			func() error { res <- flowResult{accepted: true}; return nil },
			func(reason string) { res <- flowResult{reason: reason} })
	}()
	if sendFirst {
		go func() { _, _ = client.Write(payload) }()
	}
	select {
	case r := <-res:
		if r.accepted && !sendFirst {
			_, _ = client.Write(payload)
		}
		_ = client.Close()
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("ServeFlow gave no result")
		return flowResult{}
	}
}

func TestServeFlow_HostnameThatResolvesToTheAddressIsUsed(t *testing.T) {
	gw := flowTestGateway(t, map[string]string{"allowed.test": "127.0.0.1"})
	port, got := upstream(t)
	r := runFlow(t, gw, FlowRequest{Host: "127.0.0.1", Port: port, Hostname: "allowed.test"}, []byte("hello"), false)
	if !r.accepted {
		t.Fatalf("flow refused: %s", r.reason)
	}
	if b := <-got; string(b) != "hello" {
		t.Fatalf("upstream got %q, want hello", b)
	}
}

func TestServeFlow_HostnameThatResolvesElsewhereIsIgnored(t *testing.T) {
	gw := flowTestGateway(t, map[string]string{"allowed.test": "10.9.9.9"})
	old := clientHelloTimeout
	clientHelloTimeout = 50 * time.Millisecond
	t.Cleanup(func() { clientHelloTimeout = old })
	port, _ := upstream(t)
	r := runFlow(t, gw, FlowRequest{Host: "127.0.0.1", Port: port, Hostname: "allowed.test"}, nil, false)
	if r.accepted {
		t.Fatal("a hostname that does not resolve to the flow's address allowed the flow")
	}
}

func TestServeFlow_VerifiedSNIIsUsedAndForwarded(t *testing.T) {
	gw := flowTestGateway(t, map[string]string{"allowed.test": "127.0.0.1"})
	port, got := upstream(t)
	hello := buildClientHello("allowed.test")
	r := runFlow(t, gw, FlowRequest{Host: "127.0.0.1", Port: port}, hello, true)
	if !r.accepted {
		t.Fatalf("flow refused: %s", r.reason)
	}
	if b := <-got; string(b) != string(hello) {
		t.Fatalf("upstream got %d bytes, want the %d-byte ClientHello", len(b), len(hello))
	}
}

func TestServeFlow_SNIThatResolvesElsewhereIsIgnored(t *testing.T) {
	gw := flowTestGateway(t, map[string]string{"allowed.test": "10.9.9.9"})
	port, _ := upstream(t)
	r := runFlow(t, gw, FlowRequest{Host: "127.0.0.1", Port: port}, buildClientHello("allowed.test"), true)
	if r.accepted {
		t.Fatal("an SNI that does not resolve to the flow's address allowed the flow")
	}
}

func TestServeFlow_NameEndpointIsResolvedAndChecked(t *testing.T) {
	gw := flowTestGateway(t, map[string]string{"allowed.test": "127.0.0.1", "other.test": "127.0.0.1"})
	port, got := upstream(t)
	r := runFlow(t, gw, FlowRequest{Host: "allowed.test", Port: port}, []byte("x"), false)
	if !r.accepted {
		t.Fatalf("flow refused: %s", r.reason)
	}
	<-got
	r = runFlow(t, gw, FlowRequest{Host: "other.test", Port: port}, nil, false)
	if r.accepted {
		t.Fatal("a name that no rule allows was allowed")
	}
}

func TestServeFlow_ServerFirstProtocolIsDecidedByAddress(t *testing.T) {
	gw := flowTestGateway(t, nil)
	old := clientHelloTimeout
	clientHelloTimeout = 50 * time.Millisecond
	t.Cleanup(func() { clientHelloTimeout = old })
	start := time.Now()
	r := runFlow(t, gw, FlowRequest{Host: "127.0.0.1", Port: 1}, nil, false)
	if r.accepted {
		t.Fatal("an address that no rule allows was allowed")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the ClientHello wait did not time out")
	}
}

func TestServeFlow_AddressAllowedSkipsTheClientHelloWait(t *testing.T) {
	p := &policy.Policy{Version: 1, NetworkRules: []policy.NetworkRule{
		{Name: "allow-loopback", CIDRs: []string{"127.0.0.0/8"}, Decision: "allow"},
	}}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	gw := NewFlowGateway("s1", nil, func() *policy.Engine { return engine }, nil, &captureEmitter{}, nil)
	old := clientHelloTimeout
	clientHelloTimeout = time.Hour
	t.Cleanup(func() { clientHelloTimeout = old })
	port, got := upstream(t)
	r := runFlow(t, gw, FlowRequest{Host: "127.0.0.1", Port: port}, []byte("banner-first"), false)
	if !r.accepted {
		t.Fatalf("flow refused: %s", r.reason)
	}
	<-got
}
