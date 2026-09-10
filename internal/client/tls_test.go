package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testPKI is a CA plus a server certificate for 127.0.0.1 and a client
// certificate, written as PEM.
type testPKI struct {
	dir        string
	caFile     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
	ca         *x509.Certificate
	caKey      ed25519.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{dir: t.TempDir()}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	p.caKey = key
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agentmon-client-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	p.ca, _ = x509.ParseCertificate(der)
	p.caFile = p.write(t, "ca.pem", "CERTIFICATE", der)
	p.serverCert, p.serverKey = p.issue(t, "server", true)
	p.clientCert, p.clientKey = p.issue(t, "client", false)
	return p
}

func (p *testPKI) issue(t *testing.T, name string, server bool) (string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%s key: %v", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agentmon-" + name},
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.caKey)
	if err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal %s key: %v", name, err)
	}
	return p.write(t, name+".pem", "CERTIFICATE", der), p.write(t, name+"-key.pem", "PRIVATE KEY", keyDER)
}

func (p *testPKI) write(t *testing.T, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestTLSOptions_ZeroValueIsPlaintext(t *testing.T) {
	var o TLSOptions
	if o.Active() {
		t.Error("the zero value reported TLS active")
	}
	cfg, err := o.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	// Nil is what keeps every existing loopback invocation working.
	if cfg != nil {
		t.Error("the zero value produced a tls.Config")
	}
}

func TestTLSOptions_AnySettingActivates(t *testing.T) {
	cases := map[string]TLSOptions{
		"enabled":     {Enabled: true},
		"ca":          {CACertFile: "/ca.pem"},
		"cert":        {ClientCertFile: "/c.pem"},
		"key":         {ClientKeyFile: "/k.pem"},
		"server name": {ServerName: "daemon"},
		"skip verify": {InsecureSkipVerify: true},
	}
	for name, o := range cases {
		if !o.Active() {
			t.Errorf("%s did not activate TLS", name)
		}
	}
}

func TestTLSOptions_EnabledAloneUsesSystemRoots(t *testing.T) {
	enabled := TLSOptions{Enabled: true}
	cfg, err := enabled.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	// Nil RootCAs is how crypto/tls says "the system roots", which is the
	// case for a server with a publicly issued certificate.
	if cfg.RootCAs != nil {
		t.Error("a CA pool was installed without --tls-ca")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}

func TestTLSOptions_LoadsTheCAAndClientKeypair(t *testing.T) {
	p := newTestPKI(t)
	full := TLSOptions{
		CACertFile:     p.caFile,
		ClientCertFile: p.clientCert,
		ClientKeyFile:  p.clientKey,
	}
	cfg, err := full.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("no CA pool")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("client certificates = %d, want 1", len(cfg.Certificates))
	}
}

func TestTLSOptions_MissingCAIsAnErrorNotAFallback(t *testing.T) {
	absent := TLSOptions{CACertFile: filepath.Join(t.TempDir(), "absent.pem")}
	_, err := absent.Config()
	if err == nil {
		// Falling back to the system roots would connect happily to a server
		// the operator never meant to trust, and report nothing.
		t.Fatal("a missing CA file fell back to the system roots")
	}
	// Ignoring the read error also fails, on the empty pool, but reports
	// "contains no certificates" and sends the operator looking at the file's
	// contents rather than at its path.
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %v, want it to name the missing file", err)
	}
}

func TestTLSOptions_RejectsACAWithNoCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	junk := TLSOptions{CACertFile: path}
	if _, err := junk.Config(); err == nil {
		t.Fatal("a CA file with no certificates was accepted, so the pool would trust nothing")
	}
}

func TestTLSOptions_CertAndKeyTravelTogether(t *testing.T) {
	p := newTestPKI(t)
	certOnly := TLSOptions{ClientCertFile: p.clientCert}
	if _, err := certOnly.Config(); err == nil {
		t.Error("a client certificate without its key was accepted")
	}
	keyOnly := TLSOptions{ClientKeyFile: p.clientKey}
	if _, err := keyOnly.Config(); err == nil {
		t.Error("a client key without its certificate was accepted")
	}
}

func TestTLSOptions_CarriesServerNameAndSkipVerify(t *testing.T) {
	named := TLSOptions{ServerName: "daemon.internal", InsecureSkipVerify: true}
	cfg, err := named.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg.ServerName != "daemon.internal" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify was not carried through")
	}
}
