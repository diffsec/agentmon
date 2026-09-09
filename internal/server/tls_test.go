package server

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/config"
)

func TestServerTLSConfig_NilWhenDisabled(t *testing.T) {
	cfg, err := serverTLSConfig(config.ServerTLSConfig{})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Error("TLS disabled produced a config; the listener must stay plaintext")
	}
}

func TestServerTLSConfig_CAWithoutTLSIsRefused(t *testing.T) {
	p := newTestPKI(t)
	_, err := serverTLSConfig(config.ServerTLSConfig{CAFile: p.caFile})
	if err == nil {
		t.Fatal("ca_file was accepted with tls disabled; it would authenticate nothing while looking like mTLS")
	}
	if !strings.Contains(err.Error(), "ca_file requires") {
		t.Errorf("error = %v", err)
	}
}

func TestServerTLSConfig_CertAndKeyRequired(t *testing.T) {
	p := newTestPKI(t)
	for _, tc := range []config.ServerTLSConfig{
		{Enabled: true},
		{Enabled: true, CertFile: p.serverCert},
		{Enabled: true, KeyFile: p.serverKey},
	} {
		if _, err := serverTLSConfig(tc); err == nil {
			t.Errorf("%+v was accepted", tc)
		}
	}
}

func TestServerTLSConfig_OneWayByDefault(t *testing.T) {
	p := newTestPKI(t)
	cfg, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey,
	})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v without ca_file, want NoClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("a client CA pool was installed without ca_file")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}

func TestServerTLSConfig_MutualTLSRequiresAndVerifies(t *testing.T) {
	p := newTestPKI(t)
	cfg, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey, CAFile: p.caFile,
	})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	// RequestClientCert and VerifyClientCertIfGiven both accept a client that
	// presents nothing, which is every client an attacker controls.
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("no client CA pool")
	}
}

func TestServerTLSConfig_RejectsACAFileWithNoCertificates(t *testing.T) {
	p := newTestPKI(t)
	empty := p.writePEM(t, "empty.pem", "NOT A CERTIFICATE", []byte("junk"))
	_, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey, CAFile: empty,
	})
	if err == nil {
		t.Fatal("a CA file with no certificates was accepted; the pool would verify nothing and reject every client")
	}
}

func TestServerTLSConfig_RejectsAMissingCAFile(t *testing.T) {
	p := newTestPKI(t)
	_, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey, CAFile: p.dir + "/absent.pem",
	})
	if err == nil {
		t.Fatal("a missing ca_file started an mTLS listener with no client CAs")
	}
	// Ignoring the read error also fails, on the empty pool, but it reports
	// "contains no certificates" and sends the operator looking at the file's
	// contents rather than at its path.
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %v, want it to name the missing file", err)
	}
}

// serveOnce accepts one connection, reads a byte and answers.
//
// A read is required, not just a handshake: under TLS 1.3 the client finishes
// its handshake before the server has verified the client certificate, so the
// rejection arrives as an alert on the first record rather than as a handshake
// error. A test that only called Handshake would pass against a server with no
// client verification at all.
func serveOnce(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("k"))
	}()
}

// dial completes a handshake and one round trip, so a TLS 1.3 client-certificate
// rejection is observed rather than missed.
func dial(t *testing.T, addr string, cfg *tls.Config) error {
	t.Helper()
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := conn.Handshake(); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("p")); err != nil {
		return err
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	return err
}

func mtlsListener(t *testing.T, p *testPKI) net.Listener {
	t.Helper()
	cfg, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey, CAFile: p.caFile,
	})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestMTLS_ClientWithAValidCertificateConnects(t *testing.T) {
	p := newTestPKI(t)
	ln := mtlsListener(t, p)
	serveOnce(t, ln)

	cert, err := tls.LoadX509KeyPair(p.clientCert, p.clientKey)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	if err := dial(t, ln.Addr().String(), &tls.Config{
		RootCAs:      p.pool(),
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}); err != nil {
		t.Fatalf("a client with a valid certificate was rejected: %v", err)
	}
}

func TestMTLS_ClientWithNoCertificateIsRejected(t *testing.T) {
	p := newTestPKI(t)
	ln := mtlsListener(t, p)
	serveOnce(t, ln)

	err := dial(t, ln.Addr().String(), &tls.Config{RootCAs: p.pool(), MinVersion: tls.VersionTLS12})
	if err == nil {
		t.Fatal("a client presenting no certificate completed the handshake")
	}
}

func TestMTLS_ClientFromAnotherCAIsRejected(t *testing.T) {
	p := newTestPKI(t)
	other := newTestPKI(t)
	ln := mtlsListener(t, p)
	serveOnce(t, ln)

	// A certificate that is perfectly valid, signed by a CA this server does
	// not trust. This is the case RequestClientCert would let through.
	cert, err := tls.LoadX509KeyPair(other.clientCert, other.clientKey)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	if err := dial(t, ln.Addr().String(), &tls.Config{
		RootCAs:      p.pool(),
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}); err == nil {
		t.Fatal("a client certificate from an untrusted CA completed the handshake")
	}
}

func TestOneWayTLS_ClientWithNoCertificateConnects(t *testing.T) {
	p := newTestPKI(t)
	cfg, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey,
	})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveOnce(t, ln)

	// Without ca_file the behaviour is unchanged: TLS, no client certificate.
	if err := dial(t, ln.Addr().String(), &tls.Config{RootCAs: p.pool(), MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatalf("one-way TLS rejected a client with no certificate: %v", err)
	}
}

func TestListenHTTP_UsesTheSharedTLSConfig(t *testing.T) {
	p := newTestPKI(t)
	cfg := &config.Config{}
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Auth.Type = "api_key"
	cfg.Server.TLS = config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey, CAFile: p.caFile,
	}

	ln, err := listenHTTP(cfg)
	if err != nil {
		t.Fatalf("listenHTTP: %v", err)
	}
	defer ln.Close()
	serveOnce(t, ln)

	// The HTTP listener used to build its own config from LoadX509KeyPair and
	// never read ca_file, so this connection would have succeeded.
	if err := dial(t, ln.Addr().String(), &tls.Config{RootCAs: p.pool(), MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("the HTTP listener accepted a client with no certificate under mtls")
	}
}

func TestListenHTTP_SurfacesATLSMisconfiguration(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Auth.Type = "api_key"
	cfg.Server.TLS = config.ServerTLSConfig{Enabled: true}
	if _, err := listenHTTP(cfg); err == nil {
		t.Fatal("listenHTTP started with tls enabled and no keypair")
	}
}

func TestServerTLSConfig_PoolHoldsOnlyTheConfiguredCA(t *testing.T) {
	p := newTestPKI(t)
	cfg, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey, CAFile: p.caFile,
	})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	// Seeding the pool from the system roots and appending would let any
	// publicly issued certificate authenticate, and no rejection test catches
	// that because a test CA is not in the system store either.
	if !cfg.ClientCAs.Equal(p.pool()) {
		t.Fatal("the client CA pool holds more than server.tls.ca_file")
	}
}
