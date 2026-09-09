package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI is a self-contained CA with a server certificate for 127.0.0.1 and a
// client certificate, written to disk as PEM.
type testPKI struct {
	dir        string
	caFile     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string

	caTemplate *x509.Certificate
	caKey      ed25519.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{dir: t.TempDir()}

	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	p.caKey = caKey
	p.caTemplate = &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agentmon-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, p.caTemplate, p.caTemplate, caPub, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	p.caTemplate = caCert
	p.caFile = p.writePEM(t, "ca.pem", "CERTIFICATE", caDER)

	p.serverCert, p.serverKey = p.issue(t, "server", true)
	p.clientCert, p.clientKey = p.issue(t, "client", false)
	return p
}

// issue signs a leaf certificate with the CA. A server certificate carries
// 127.0.0.1 as a SAN so a real handshake against the test listener verifies.
func (p *testPKI) issue(t *testing.T, name string, server bool) (string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agentmon-test-" + name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caTemplate, pub, p.caKey)
	if err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal %s key: %v", name, err)
	}
	return p.writePEM(t, name+".pem", "CERTIFICATE", der),
		p.writePEM(t, name+"-key.pem", "PRIVATE KEY", keyDER)
}

func (p *testPKI) writePEM(t *testing.T, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(p.dir, name)
	body := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// pool returns the CA as a verification pool.
func (p *testPKI) pool() *x509.CertPool {
	pl := x509.NewCertPool()
	pl.AddCert(p.caTemplate)
	return pl
}
