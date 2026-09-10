package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/decisionctx"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/policyserve"
)

// buildRemotePolicySource turns policies.remote into a Source the Manager can
// load from. It returns nil when no policy server is configured.
//
// The decision context is resolved once, here, rather than per fetch: it is
// process-level identity, and re-resolving it on every poll would let a
// transient tailscaled outage silently move the agent to a different binding.
func buildRemotePolicySource(ctx context.Context, cfg *config.Config, logger *slog.Logger) (policy.Source, error) {
	rc := &cfg.Policies.Remote
	if !rc.Enabled() {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	src, err := policy.NewRemoteSource(rc.URL)
	if err != nil {
		return nil, err
	}
	src.Wait = rc.ResolvedLongPoll()
	src.MaxBytes = rc.MaxBytes

	header := http.Header{}
	if rc.AuthHeader != "" {
		token := strings.TrimSpace(os.Getenv(rc.AuthTokenEnv))
		if token == "" {
			// Soft-fail matches requireAPIKey: the agent still fetches, and an
			// endpoint that needs the credential answers 401, which reaches
			// the log as a fetch failure rather than as a silent 403 loop.
			logger.Warn("policy source auth token is empty; fetching unauthenticated",
				"env", rc.AuthTokenEnv)
		} else {
			header.Set(rc.AuthHeader, token)
		}
	}
	if rc.DecisionContextEnabled() {
		dc := resolvePolicyDecisionContext(ctx, cfg)
		applyDecisionContextHeaders(header, dc)
		logger.Info("policy source: reporting decision context",
			"hostname", dc.Hostname, "tag_count", len(dc.Tags), "user_source", string(dc.User.Source))
	}
	if len(header) > 0 {
		src.Header = header
	}

	client, err := remotePolicyHTTPClient(rc)
	if err != nil {
		return nil, err
	}
	src.Client = client

	if !rc.CacheEnabled() {
		return src, nil
	}
	dir := strings.TrimSpace(rc.CacheDir)
	if dir == "" {
		dir = filepath.Join(cfg.ResolvedDataDir(), "policy-cache")
	}
	return policy.NewCachingSource(src, dir, logger), nil
}

// resolvePolicyDecisionContext reuses audit.watchtower.decision_context.
//
// The block is named for Watchtower, but it configures the identity an agent
// reports so a server can resolve its bound policy -- which is exactly what
// the policy server binds on. A second, parallel block under policies.remote
// could disagree with it, and then one agent would report one identity to
// Watchtower and a different one to the policy server.
func resolvePolicyDecisionContext(ctx context.Context, cfg *config.Config) decisionctx.DecisionContext {
	dcc := cfg.Audit.Watchtower.DecisionContext
	tsEnabled := true
	if dcc.Tailscale.Enabled != nil {
		tsEnabled = *dcc.Tailscale.Enabled
	}
	resolver := decisionctx.NewResolver(decisionctx.Config{
		Tags:             dcc.Tags,
		Extra:            dcc.Extra,
		TailscaleEnabled: tsEnabled,
		TailscaleSocket:  dcc.Tailscale.Socket,
	})
	dc, _ := resolver.Resolve(ctx)
	return dc
}

// applyDecisionContextHeaders writes the selector the policy server reads.
//
// Values are skipped rather than sent empty, so a signal that did not resolve
// leaves the field unset on the server and the binding treats it as
// unconstrained, rather than matching it against the empty string.
func applyDecisionContextHeaders(h http.Header, dc decisionctx.DecisionContext) {
	if dc.Hostname != "" {
		h.Set(policyserve.HeaderHostname, dc.Hostname)
	}
	if dc.User.Value != "" {
		h.Set(policyserve.HeaderUser, dc.User.Value)
	}
	if len(dc.Tags) > 0 {
		tags := append([]string(nil), dc.Tags...)
		sort.Strings(tags)
		h.Set(policyserve.HeaderTags, strings.Join(tags, ","))
	}
	if tenant := dc.Extra["tenant"]; tenant != "" {
		h.Set(policyserve.HeaderTenant, tenant)
	}
}

// remotePolicyHTTPClient builds the client, including the client half of mTLS.
func remotePolicyHTTPClient(rc *config.RemotePolicyConfig) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if rc.TLS.CACertFile != "" {
		pem, err := os.ReadFile(rc.TLS.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("policies.remote.tls.ca_cert_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("policies.remote.tls.ca_cert_file %s contains no certificates", rc.TLS.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}
	if rc.TLS.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(rc.TLS.ClientCertFile, rc.TLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("policies.remote.tls client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if rc.TLS.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
		slog.Warn("policies.remote.tls.insecure_skip_verify is set; the policy server's certificate is not checked")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg

	// A long poll is meant to be held open, so the client timeout must clear
	// the wait or every poll aborts at the deadline and the fetch never
	// completes. The remainder bounds the request itself.
	timeout := 60 * time.Second
	if w := rc.ResolvedLongPoll(); w > 0 {
		timeout = w + 60*time.Second
	}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}
