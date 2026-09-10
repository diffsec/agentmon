package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// TLSOptions configures the client side of a TLS connection to the daemon.
//
// Every field is off by default, and with all of them off the clients behave
// exactly as before: plaintext gRPC, and HTTP whose scheme decides. That
// matters because the default deployment is a loopback daemon with no TLS at
// all, and quietly requiring certificates there would break every local
// invocation.
type TLSOptions struct {
	// Enabled forces TLS on the gRPC transport. Setting any other field
	// implies it, so this is only needed for a server whose certificate the
	// system roots already trust.
	//
	// The HTTP transport takes it from the URL scheme instead, which is
	// unambiguous in a way "host:port" is not.
	Enabled bool
	// CACertFile verifies the server. Empty uses the system roots.
	CACertFile string
	// ClientCertFile and ClientKeyFile answer a server that requires client
	// certificates -- server.tls.ca_file on the daemon side.
	ClientCertFile string
	ClientKeyFile  string
	// ServerName overrides the name checked against the certificate. Needed
	// when connecting by IP to a certificate issued for a hostname.
	ServerName string
	// InsecureSkipVerify disables verification of the server's certificate.
	InsecureSkipVerify bool
}

// Active reports whether any TLS setting was given.
func (o TLSOptions) Active() bool {
	return o.Enabled ||
		strings.TrimSpace(o.CACertFile) != "" ||
		strings.TrimSpace(o.ClientCertFile) != "" ||
		strings.TrimSpace(o.ClientKeyFile) != "" ||
		strings.TrimSpace(o.ServerName) != "" ||
		o.InsecureSkipVerify
}

// Config builds the tls.Config, or nil when no TLS setting was given.
//
// A missing or unreadable file is an error rather than a fallback to the
// system roots. Falling back would connect successfully to a server the
// operator never meant to trust, and report nothing.
func (o TLSOptions) Config() (*tls.Config, error) {
	if !o.Active() {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca := strings.TrimSpace(o.CACertFile); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("tls ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls ca file %s contains no certificates", ca)
		}
		cfg.RootCAs = pool
	}
	certFile := strings.TrimSpace(o.ClientCertFile)
	keyFile := strings.TrimSpace(o.ClientKeyFile)
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("tls client certificate and key must be given together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("tls client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if o.ServerName != "" {
		cfg.ServerName = o.ServerName
	}
	cfg.InsecureSkipVerify = o.InsecureSkipVerify
	return cfg, nil
}
