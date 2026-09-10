package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetenvBool(t *testing.T) {
	cases := map[string]bool{
		"1": true, "true": true, "TRUE": true, "yes": true, "on": true,
		"": false, "0": false, "false": false, "no": false, "maybe": false, " ": false,
	}
	for in, want := range cases {
		t.Setenv("AGENTMON_TEST_BOOL", in)
		if got := getenvBool("AGENTMON_TEST_BOOL"); got != want {
			// A typo must disable the setting, not enable it. For
			// --tls-insecure-skip-verify that is the difference between a
			// checked certificate and an unchecked one.
			t.Errorf("getenvBool(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestClientConfig_TLSOptionsCarryEveryFlag(t *testing.T) {
	cfg := &clientConfig{
		tlsEnabled:    true,
		tlsCACert:     "/ca.pem",
		tlsCert:       "/c.pem",
		tlsKey:        "/k.pem",
		tlsServerName: "daemon.internal",
		tlsSkipVerify: true,
	}
	o := cfg.tlsOptions()
	if !o.Enabled || o.CACertFile != "/ca.pem" || o.ClientCertFile != "/c.pem" ||
		o.ClientKeyFile != "/k.pem" || o.ServerName != "daemon.internal" || !o.InsecureSkipVerify {
		t.Fatalf("tlsOptions() = %+v", o)
	}
}

func TestClientConfig_CLIOptionsCarryTimeoutAndTLS(t *testing.T) {
	cfg := &clientConfig{
		serverAddr:    "https://daemon:18080",
		grpcAddr:      "daemon:9090",
		apiKey:        "k",
		transport:     "grpc",
		clientTimeout: "45s",
		tlsCACert:     "/ca.pem",
	}
	o := cfg.cliOptions()
	if o.HTTPBaseURL != "https://daemon:18080" || o.GRPCAddr != "daemon:9090" ||
		o.APIKey != "k" || o.Transport != "grpc" {
		t.Fatalf("cliOptions() = %+v", o)
	}
	// Several commands built CLIOptions inline and passed no ClientTimeout, so
	// --client-timeout did nothing on approve, attach and the session
	// commands. One constructor is what stops that recurring.
	if o.ClientTimeout.String() != "45s" {
		t.Errorf("ClientTimeout = %v, want 45s", o.ClientTimeout)
	}
	if o.TLS.CACertFile != "/ca.pem" {
		t.Errorf("TLS options were not carried: %+v", o.TLS)
	}
}

// TestNoInlineCLIOptions is a source check: 30 call sites used to assemble the
// options themselves, and they had already drifted on ClientTimeout.
func TestNoInlineCLIOptions(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Skipf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "root.go" {
			continue // root.go is the one place that builds it
		}
		body, rerr := os.ReadFile(f)
		if rerr != nil {
			continue
		}
		if strings.Contains(string(body), "client.CLIOptions{") {
			t.Errorf("%s assembles client.CLIOptions inline; use cfg.cliOptions()", f)
		}
	}
}
