package cli

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestServeTLSConfig_PlaintextByDefault(t *testing.T) {
	cfg, err := serveTLSConfig("", "", "")
	if err != nil {
		t.Fatalf("serveTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Error("no certificate should mean a plaintext listener")
	}
}

func TestServeTLSConfig_ClientCAWithoutServerCertIsRefused(t *testing.T) {
	// Ignoring the flag would produce a plaintext listener that verifies
	// nothing while the operator believes mTLS is on.
	_, err := serveTLSConfig("", "", "/tmp/ca.pem")
	if err == nil {
		t.Fatal("--client-ca without --tls-cert was accepted")
	}
	if !strings.Contains(err.Error(), "--client-ca requires") {
		t.Errorf("error = %v", err)
	}
}

func TestServeTLSConfig_CertWithoutKeyIsRefused(t *testing.T) {
	if _, err := serveTLSConfig("/tmp/c.pem", "", ""); err == nil {
		t.Error("--tls-cert without --tls-key was accepted")
	}
	if _, err := serveTLSConfig("", "/tmp/k.pem", ""); err == nil {
		t.Error("--tls-key without --tls-cert was accepted")
	}
}

func TestServeTLSConfig_MTLSRequiresAndVerifies(t *testing.T) {
	certFile, keyFile, caFile := writeTestPKI(t)
	cfg, err := serveTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("serveTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		// RequestClientCert or VerifyClientCertIfGiven accept a client that
		// simply presents nothing, which is every client an attacker controls.
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("no client CA pool was installed")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}

func TestServeTLSConfig_RejectsCAFileWithNoCertificates(t *testing.T) {
	certFile, keyFile, _ := writeTestPKI(t)
	empty := writeTempFile(t, "not-a-certificate\n")
	if _, err := serveTLSConfig(certFile, keyFile, empty); err == nil {
		t.Fatal("a CA file containing no certificates was accepted, so mTLS would trust nobody and reject everyone")
	}
}
