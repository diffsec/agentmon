package server

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/diffsec/agentmon/internal/config"
)

// grpcMTLSServer starts a gRPC server with the same TLS config the daemon
// builds, registering no services: an authenticated call then fails with
// Unimplemented while an unauthenticated one never reaches a handler at all.
func grpcMTLSServer(t *testing.T, p *testPKI) string {
	t.Helper()
	tlsCfg, err := serverTLSConfig(config.ServerTLSConfig{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey, CAFile: p.caFile,
	})
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return ln.Addr().String()
}

func grpcCall(t *testing.T, addr string, tlsCfg *tls.Config) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Invoke(ctx, "/agentmon.v1.Probe/Ping", &emptyMessage{}, &emptyMessage{})
}

// emptyMessage is a proto message carrying nothing; the call is only ever used
// to force the transport to complete.
type emptyMessage struct{}

func (m *emptyMessage) Reset()         {}
func (m *emptyMessage) String() string { return "" }
func (m *emptyMessage) ProtoMessage()  {}

func TestGRPCMTLS_ValidClientCertificateReachesTheServer(t *testing.T) {
	p := newTestPKI(t)
	addr := grpcMTLSServer(t, p)

	cert, err := tls.LoadX509KeyPair(p.clientCert, p.clientKey)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	err = grpcCall(t, addr, &tls.Config{
		RootCAs: p.pool(), Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	// No service is registered, so reaching the server is Unimplemented.
	if code := status.Code(err); code != codes.Unimplemented {
		t.Fatalf("code = %v (%v), want Unimplemented: an authorised client should reach the server", code, err)
	}
}

func TestGRPCMTLS_NoClientCertificateIsRejected(t *testing.T) {
	p := newTestPKI(t)
	addr := grpcMTLSServer(t, p)

	// credentials.NewServerTLSFromFile, which this replaced, never read
	// ca_file, so this call used to land on the server.
	err := grpcCall(t, addr, &tls.Config{RootCAs: p.pool(), MinVersion: tls.VersionTLS12})
	if code := status.Code(err); code == codes.Unimplemented {
		t.Fatal("a client with no certificate reached the gRPC server")
	}
	if err == nil {
		t.Fatal("a client with no certificate got a successful response")
	}
}

func TestGRPCMTLS_ClientFromAnotherCAIsRejected(t *testing.T) {
	p := newTestPKI(t)
	other := newTestPKI(t)
	addr := grpcMTLSServer(t, p)

	cert, err := tls.LoadX509KeyPair(other.clientCert, other.clientKey)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	err = grpcCall(t, addr, &tls.Config{
		RootCAs: p.pool(), Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	if code := status.Code(err); code == codes.Unimplemented {
		t.Fatal("a client certificate from an untrusted CA reached the gRPC server")
	}
	if err == nil {
		t.Fatal("a client certificate from an untrusted CA got a successful response")
	}
}
