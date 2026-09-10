package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func (p *testPKI) pool() *x509.CertPool {
	pl := x509.NewCertPool()
	pl.AddCert(p.ca)
	return pl
}

// mtlsHTTPServer stands up the shape internal/server builds when
// server.tls.ca_file is set: TLS with RequireAndVerifyClientCert.
func mtlsHTTPServer(t *testing.T, p *testPKI, requireClientCert bool) *httptest.Server {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(p.serverCert, p.serverKey)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if requireClientCert {
		cfg.ClientCAs = p.pool()
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestHTTPClient_ReachesAnMTLSServer is the point of the change: before it,
// internal/client built its http.Client with no TLS options at all, so nothing
// in this tree could satisfy a daemon that requires client certificates.
func TestHTTPClient_ReachesAnMTLSServer(t *testing.T) {
	p := newTestPKI(t)
	srv := mtlsHTTPServer(t, p, true)

	opts := CLIOptions{
		HTTPBaseURL: srv.URL,
		Transport:   "http",
		TLS: TLSOptions{
			CACertFile:     p.caFile,
			ClientCertFile: p.clientCert,
			ClientKeyFile:  p.clientKey,
		},
	}
	c, err := NewForCLI(opts)
	if err != nil {
		t.Fatalf("NewForCLI: %v", err)
	}
	if _, err := c.ListSessions(context.Background()); err != nil {
		t.Fatalf("a client with a valid certificate was refused: %v", err)
	}
}

func TestHTTPClient_WithoutAClientCertificateIsRefused(t *testing.T) {
	p := newTestPKI(t)
	srv := mtlsHTTPServer(t, p, true)

	c, err := NewForCLI(CLIOptions{
		HTTPBaseURL: srv.URL,
		Transport:   "http",
		TLS:         TLSOptions{CACertFile: p.caFile},
	})
	if err != nil {
		t.Fatalf("NewForCLI: %v", err)
	}
	if _, err := c.ListSessions(context.Background()); err == nil {
		t.Fatal("a client presenting no certificate reached the server")
	}
}

func TestHTTPClient_WithoutTheCAIsRefused(t *testing.T) {
	p := newTestPKI(t)
	srv := mtlsHTTPServer(t, p, false)

	// TLS on, but verifying against the system roots, which do not include
	// this private CA.
	c, err := NewForCLI(CLIOptions{
		HTTPBaseURL: srv.URL,
		Transport:   "http",
		TLS:         TLSOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewForCLI: %v", err)
	}
	_, err = c.ListSessions(context.Background())
	if err == nil {
		t.Fatal("a server signed by an untrusted CA was accepted")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("error = %v, want a certificate failure", err)
	}
}

func TestHTTPClient_SkipVerifyConnectsAnyway(t *testing.T) {
	p := newTestPKI(t)
	srv := mtlsHTTPServer(t, p, false)

	c, err := NewForCLI(CLIOptions{
		HTTPBaseURL: srv.URL,
		Transport:   "http",
		TLS:         TLSOptions{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("NewForCLI: %v", err)
	}
	if _, err := c.ListSessions(context.Background()); err != nil {
		t.Fatalf("--tls-insecure-skip-verify did not skip verification: %v", err)
	}
}

// TestHTTPClient_PlainHTTPWithTLSOptionsIsRefused.
//
// Attaching a tls.Config to an http:// client does nothing, so dropping it
// silently would send every request in the clear while the operator believed
// --tls-ca had been honoured.
func TestHTTPClient_PlainHTTPWithTLSOptionsIsRefused(t *testing.T) {
	p := newTestPKI(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer plain.Close()

	_, err := NewForCLI(CLIOptions{
		HTTPBaseURL: plain.URL,
		Transport:   "http",
		TLS:         TLSOptions{CACertFile: p.caFile},
	})
	if err == nil {
		t.Fatal("tls options with an http:// server were accepted")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error = %v, want it to name the fix", err)
	}
}

// TestNewForCLI_GRPCLegGetsTheTLSConfig drives the whole path a CLI command
// takes: --transport grpc with --tls-* flags against a daemon that requires
// client certificates. The http:// base URL is the documented default for the
// endpoints gRPC does not carry, and the tls flags belong to the gRPC leg.
func TestNewForCLI_GRPCLegGetsTheTLSConfig(t *testing.T) {
	p := newTestPKI(t)
	addr := grpcTLSServer(t, p, true)

	c, err := NewForCLI(CLIOptions{
		HTTPBaseURL: "http://127.0.0.1:18080",
		GRPCAddr:    addr,
		Transport:   "grpc",
		TLS: TLSOptions{
			CACertFile:     p.caFile,
			ClientCertFile: p.clientCert,
			ClientKeyFile:  p.clientKey,
		},
	})
	if err != nil {
		t.Fatalf("NewForCLI: %v", err)
	}
	h, ok := c.(*HybridClient)
	if !ok {
		t.Fatalf("client is %T, want *HybridClient", c)
	}
	defer h.grpc.conn.Close()

	// Passing nil to the gRPC leg dials plaintext, which never reaches an
	// mTLS server, so this is what proves the config was handed over.
	if code := status.Code(invoke(t, h.grpc)); code != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented: the gRPC leg did not get the TLS config", code)
	}
}

// TestHTTPClient_BadTLSMaterialFailsWhateverTheTransport: an unreadable CA is
// an error even over plain http, because a flag that cannot be honoured is
// worth stopping for.
func TestHTTPClient_BadTLSMaterialFailsWhateverTheTransport(t *testing.T) {
	_, err := NewForCLI(CLIOptions{
		HTTPBaseURL: "http://127.0.0.1:18080",
		Transport:   "http",
		TLS:         TLSOptions{CACertFile: "/nonexistent/ca.pem"},
	})
	if err == nil {
		t.Fatal("an unreadable CA file was accepted")
	}
	if !strings.Contains(err.Error(), "ca file") {
		t.Errorf("error = %v", err)
	}
}

func TestHTTPClient_UnixSocketRefusesTLSOptions(t *testing.T) {
	_, err := NewWithOptions("unix:///tmp/agentmon.sock", "", 0, &tls.Config{MinVersion: tls.VersionTLS12})
	if err == nil {
		t.Fatal("tls options were accepted for a unix socket, where they cannot apply")
	}
	if !strings.Contains(err.Error(), "does not use TLS") {
		t.Errorf("error = %v", err)
	}
}

// grpcTLSServer registers no services, so an authenticated call is
// Unimplemented and an unauthenticated one never reaches a handler.
func grpcTLSServer(t *testing.T, p *testPKI, requireClientCert bool) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(p.serverCert, p.serverKey)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if requireClientCert {
		cfg.ClientCAs = p.pool()
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return ln.Addr().String()
}

type emptyMessage struct{}

func (m *emptyMessage) Reset()         {}
func (m *emptyMessage) String() string { return "" }
func (m *emptyMessage) ProtoMessage()  {}

func invoke(t *testing.T, c *GRPCClient) error {
	t.Helper()
	return c.conn.Invoke(context.Background(), "/agentmon.v1.Probe/Ping", &emptyMessage{}, &emptyMessage{})
}

// TestGRPCClient_ReachesAnMTLSServer: NewGRPC dialed
// insecure.NewCredentials() unconditionally, so server.tls: true broke
// --transport grpc outright.
func TestGRPCClient_ReachesAnMTLSServer(t *testing.T) {
	p := newTestPKI(t)
	addr := grpcTLSServer(t, p, true)

	cfg, err := TLSOptions{
		CACertFile:     p.caFile,
		ClientCertFile: p.clientCert,
		ClientKeyFile:  p.clientKey,
	}.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	c, err := NewGRPCWithTLS(addr, "", cfg)
	if err != nil {
		t.Fatalf("NewGRPCWithTLS: %v", err)
	}
	defer c.conn.Close()

	if code := status.Code(invoke(t, c)); code != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented: an authorised client should reach the server", code)
	}
}

func TestGRPCClient_WithoutAClientCertificateIsRefused(t *testing.T) {
	p := newTestPKI(t)
	addr := grpcTLSServer(t, p, true)

	cfg, err := TLSOptions{CACertFile: p.caFile}.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	c, err := NewGRPCWithTLS(addr, "", cfg)
	if err != nil {
		t.Fatalf("NewGRPCWithTLS: %v", err)
	}
	defer c.conn.Close()

	if code := status.Code(invoke(t, c)); code == codes.Unimplemented {
		t.Fatal("a client with no certificate reached the gRPC server")
	}
}

func TestGRPCClient_PlaintextDialAgainstATLSServerFails(t *testing.T) {
	p := newTestPKI(t)
	addr := grpcTLSServer(t, p, false)

	// This is exactly what every CLI invocation did before the change.
	c, err := NewGRPC(addr, "")
	if err != nil {
		t.Fatalf("NewGRPC: %v", err)
	}
	defer c.conn.Close()

	if code := status.Code(invoke(t, c)); code == codes.Unimplemented {
		t.Fatal("a plaintext dial reached a TLS gRPC server")
	}
}

func TestGRPCClient_NilConfigStillDialsPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	go func() { _ = gs.Serve(ln) }()
	defer gs.Stop()

	// The default deployment is a loopback daemon with no TLS; requiring
	// certificates there would break every existing invocation.
	c, err := NewGRPCWithTLS(ln.Addr().String(), "", nil)
	if err != nil {
		t.Fatalf("NewGRPCWithTLS: %v", err)
	}
	defer c.conn.Close()
	if code := status.Code(invoke(t, c)); code != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented: a plaintext dial should reach a plaintext server", code)
	}
}
