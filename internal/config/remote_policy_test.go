package config

import (
	"strings"
	"testing"
	"time"
)

func TestRemotePolicy_DisabledWithoutURL(t *testing.T) {
	c := RemotePolicyConfig{}
	if c.Enabled() {
		t.Error("no url must mean disabled")
	}
	// A disabled remote must not be validated against the signing mode; that
	// would make signing.mode: off illegal for every local deployment.
	if err := c.Validate("off"); err != nil {
		t.Errorf("a disabled remote failed validation: %v", err)
	}
}

func TestRemotePolicy_RequiresSigningEnforce(t *testing.T) {
	c := RemotePolicyConfig{URL: "https://policy.example/v1/policy"}
	for _, mode := range []string{"off", "warn", ""} {
		err := c.Validate(mode)
		if err == nil {
			t.Errorf("signing mode %q was accepted with a remote source", mode)
			continue
		}
		if !strings.Contains(err.Error(), "enforce") {
			t.Errorf("mode %q: error = %v", mode, err)
		}
	}
	if err := c.Validate("enforce"); err != nil {
		t.Errorf("enforce was rejected: %v", err)
	}
}

func TestRemotePolicy_RejectsBadURLs(t *testing.T) {
	for _, u := range []string{"ftp://policy.example/p", "policy.example/p", "https://"} {
		c := RemotePolicyConfig{URL: u}
		if err := c.Validate("enforce"); err == nil {
			t.Errorf("url %q was accepted", u)
		}
	}
}

func TestRemotePolicy_AuthHeaderAndTokenTravelTogether(t *testing.T) {
	base := func() RemotePolicyConfig {
		return RemotePolicyConfig{URL: "https://policy.example/v1/policy"}
	}
	c := base()
	c.AuthHeader = "Authorization"
	if err := c.Validate("enforce"); err == nil {
		t.Error("auth_header without auth_token_env was accepted; the token would have to live in config")
	}
	c = base()
	c.AuthTokenEnv = "TOKEN"
	if err := c.Validate("enforce"); err == nil {
		t.Error("auth_token_env without auth_header was accepted")
	}
	c = base()
	c.AuthHeader, c.AuthTokenEnv = "Authorization", "TOKEN"
	if err := c.Validate("enforce"); err != nil {
		t.Errorf("both set: %v", err)
	}
}

func TestRemotePolicy_ClientCertAndKeyTravelTogether(t *testing.T) {
	c := RemotePolicyConfig{URL: "https://policy.example/v1/policy"}
	c.TLS.ClientCertFile = "/tmp/c.pem"
	if err := c.Validate("enforce"); err == nil {
		t.Error("a client certificate without its key was accepted")
	}
	c.TLS.ClientKeyFile = "/tmp/k.pem"
	if err := c.Validate("enforce"); err != nil {
		t.Errorf("both set: %v", err)
	}
}

func TestRemotePolicy_RejectsBadDurationsAndSizes(t *testing.T) {
	c := RemotePolicyConfig{URL: "https://policy.example/v1/policy", PollInterval: "half an hour"}
	if err := c.Validate("enforce"); err == nil {
		t.Error("an unparseable poll_interval was accepted")
	}
	c = RemotePolicyConfig{URL: "https://policy.example/v1/policy", PollInterval: "-1m"}
	if err := c.Validate("enforce"); err == nil {
		t.Error("a negative poll_interval was accepted")
	}
	c = RemotePolicyConfig{URL: "https://policy.example/v1/policy", LongPoll: "later"}
	if err := c.Validate("enforce"); err == nil {
		t.Error("an unparseable long_poll was accepted")
	}
	c = RemotePolicyConfig{URL: "https://policy.example/v1/policy", MaxBytes: -1}
	if err := c.Validate("enforce"); err == nil {
		t.Error("a negative max_bytes was accepted")
	}
}

func TestRemotePolicy_Defaults(t *testing.T) {
	c := RemotePolicyConfig{URL: "https://policy.example/v1/policy"}
	if got := c.ResolvedPollInterval(); got != DefaultRemotePolicyPollInterval {
		t.Errorf("poll interval = %v, want %v", got, DefaultRemotePolicyPollInterval)
	}
	if got := c.ResolvedLongPoll(); got != DefaultRemotePolicyLongPoll {
		t.Errorf("long poll = %v, want %v", got, DefaultRemotePolicyLongPoll)
	}
	if !c.CacheEnabled() {
		t.Error("the cache must default on; without it a server outage plus a restart is a daemon that will not start")
	}
	if !c.DecisionContextEnabled() {
		t.Error("the decision context must default on; a server binding on identity gets none otherwise")
	}

	// An explicit zero long-poll disables it rather than taking the default.
	c.LongPoll = "0s"
	if got := c.ResolvedLongPoll(); got != 0 {
		t.Errorf("long_poll: \"0s\" = %v, want 0", got)
	}
	c.PollInterval = "90s"
	if got := c.ResolvedPollInterval(); got != 90*time.Second {
		t.Errorf("poll interval = %v, want 90s", got)
	}

	off := false
	c.Cache, c.SendDecisionContext = &off, &off
	if c.CacheEnabled() || c.DecisionContextEnabled() {
		t.Error("explicit false was ignored")
	}
}

func TestValidateConfig_RejectsRemoteWithoutEnforce(t *testing.T) {
	cfg := Config{}
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"
	cfg.Policies.Remote.URL = "https://policy.example/v1/policy"
	cfg.Policies.Signing.Mode = "off"
	err := validateConfig(&cfg)
	if err == nil {
		t.Fatal("agentmon config validate accepted a remote source with signing off")
	}
	if !strings.Contains(err.Error(), "policies.remote.url") {
		t.Errorf("error = %v", err)
	}
}

func TestServerTLS_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ServerTLSConfig
		wantErr string
	}{
		{"disabled", ServerTLSConfig{}, ""},
		{"ca without tls", ServerTLSConfig{CAFile: "/ca.pem"}, "ca_file requires"},
		{"enabled without keypair", ServerTLSConfig{Enabled: true}, "cert_file/key_file"},
		{"cert without key", ServerTLSConfig{Enabled: true, CertFile: "/c.pem"}, "cert_file/key_file"},
		{"one-way", ServerTLSConfig{Enabled: true, CertFile: "/c.pem", KeyFile: "/k.pem"}, ""},
		{"mutual", ServerTLSConfig{Enabled: true, CertFile: "/c.pem", KeyFile: "/k.pem", CAFile: "/ca.pem"}, ""},
	}
	for _, c := range cases {
		err := c.cfg.Validate()
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error = %v, want %q", c.name, err, c.wantErr)
		}
	}
}

func TestServerTLS_MutualTLS(t *testing.T) {
	if (&ServerTLSConfig{CAFile: "/ca.pem"}).MutualTLS() {
		t.Error("ca_file with tls disabled reported mutual TLS")
	}
	if (&ServerTLSConfig{Enabled: true}).MutualTLS() {
		t.Error("tls with no ca_file reported mutual TLS")
	}
	if (&ServerTLSConfig{Enabled: true, CAFile: "  "}).MutualTLS() {
		t.Error("a whitespace ca_file reported mutual TLS")
	}
	if !(&ServerTLSConfig{Enabled: true, CAFile: "/ca.pem"}).MutualTLS() {
		t.Error("tls plus ca_file is mutual TLS")
	}
}

func TestValidateConfig_RejectsCAFileWithoutTLS(t *testing.T) {
	cfg := Config{}
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"
	cfg.Server.TLS.CAFile = "/etc/agentmon/clients-ca.pem"
	err := validateConfig(&cfg)
	if err == nil {
		t.Fatal("agentmon config validate accepted ca_file with tls disabled")
	}
	if !strings.Contains(err.Error(), "server.tls.ca_file") {
		t.Errorf("error = %v", err)
	}
}
