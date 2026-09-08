package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/policy/signing"
	"github.com/diffsec/agentmon/internal/policyserve"
)

const strictDoc = `version: 1
name: strict
file_rules:
  - name: deny-etc
    paths: ["/etc/**"]
    operations: [read]
    decision: deny
`

const baselineDoc = `version: 1
name: baseline
file_rules:
  - name: allow-tmp
    paths: ["/tmp/**"]
    operations: [read]
    decision: allow
`

type servedFixture struct {
	policyDir string
	trustDir  string
	priv      ed25519.PrivateKey
}

func newServedFixture(t *testing.T) *servedFixture {
	t.Helper()
	f := &servedFixture{policyDir: t.TempDir(), trustDir: t.TempDir()}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f.priv = priv
	kf := signing.PublicKeyFile{
		KeyID:     signing.KeyID(pub),
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	kb, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(filepath.Join(f.trustDir, kf.KeyID+".json"), kb, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return f
}

func (f *servedFixture) put(t *testing.T, name, body string) {
	t.Helper()
	path := filepath.Join(f.policyDir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	sig, err := signing.Sign([]byte(body), f.priv, "test")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sb, _ := json.MarshalIndent(sig, "", "  ")
	if err := os.WriteFile(path+".sig", sb, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
}

// TestE2E_ConfiguredRemoteSourceInstallsABoundPolicy runs the whole chain:
// config -> source -> Manager -> a real policy server, with the binding
// selecting on the decision context the agent sends.
func TestE2E_ConfiguredRemoteSourceInstallsABoundPolicy(t *testing.T) {
	f := newServedFixture(t)
	f.put(t, "strict.yaml", strictDoc)
	f.put(t, "baseline.yaml", baselineDoc)

	bindings := filepath.Join(t.TempDir(), "bindings.yaml")
	if err := os.WriteFile(bindings, []byte(`bindings:
  - name: prod
    policy: strict.yaml
    match:
      tags: ["prod"]
  - name: fallback
    policy: baseline.yaml
`), 0o600); err != nil {
		t.Fatalf("write bindings: %v", err)
	}

	store, err := policyserve.NewDirStore(policyserve.StoreConfig{
		PolicyDir: f.policyDir, BindingsPath: bindings, TrustStorePath: f.trustDir,
	})
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	srv := httptest.NewServer(policyserve.NewServer(store, nil).Handler())
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Policies.Signing.Mode = "enforce"
	cfg.Policies.Signing.TrustStore = f.trustDir
	cfg.Policies.Remote.URL = srv.URL + "/v1/policy"
	cfg.Policies.Remote.LongPoll = "0s"
	cfg.Policies.Remote.CacheDir = t.TempDir()
	cfg.Audit.Watchtower.DecisionContext.Tags = []string{"prod"}

	if err := cfg.Policies.Remote.Validate(cfg.Policies.Signing.SigningMode()); err != nil {
		t.Fatalf("config validation: %v", err)
	}
	src, err := buildRemotePolicySource(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("build source: %v", err)
	}

	m := policy.NewManager(t.TempDir(), "unused", nil, "", "")
	m.SetSigningConfig(cfg.Policies.Signing.SigningMode(), cfg.Policies.Signing.TrustStore)
	m.SetSource(src)

	p, err := m.Get()
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	// The prod tag came from audit.watchtower.decision_context and selected
	// the strict binding.
	if p.Name != "strict" {
		t.Fatalf("installed %q, want strict", p.Name)
	}

	// The cache holds what the server served, so a restart during an outage
	// comes up on this document.
	cached, err := os.ReadFile(filepath.Join(cfg.Policies.Remote.CacheDir, "policy.yaml"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if string(cached) != strictDoc {
		t.Errorf("cache holds %q", cached)
	}

	// Replace the served document; the next reload installs it with no restart.
	f.put(t, "strict.yaml", strictDoc+`  - name: deny-root
    paths: ["/root/**"]
    operations: [read]
    decision: deny
`)
	if err := store.Reload(); err != nil {
		t.Fatalf("server reload: %v", err)
	}
	updated, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(updated.FileRules) != 2 {
		t.Fatalf("file rules = %d, want the updated document", len(updated.FileRules))
	}

	// The server going down leaves the policy in force and reports the failure.
	srv.Close()
	stale, err := m.ReloadContext(context.Background())
	if err == nil {
		t.Fatal("a poll against a dead server reported success")
	}
	if stale == nil || len(stale.FileRules) != 2 {
		t.Fatal("the policy was withdrawn when the server went away")
	}
	if got, gerr := m.Get(); gerr != nil || len(got.FileRules) != 2 {
		t.Fatalf("Get() = (%v, %v) after the server died", got, gerr)
	}
}

// TestE2E_CachedBundleCarriesAStartupDuringAnOutage covers the restart case:
// nothing is loaded in memory and the server is unreachable.
func TestE2E_CachedBundleCarriesAStartupDuringAnOutage(t *testing.T) {
	f := newServedFixture(t)
	f.put(t, "base.yaml", baselineDoc)

	store, err := policyserve.NewDirStore(policyserve.StoreConfig{
		PolicyDir: f.policyDir, DefaultPolicy: "base.yaml", TrustStorePath: f.trustDir,
	})
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	srv := httptest.NewServer(policyserve.NewServer(store, nil).Handler())

	cacheDir := t.TempDir()
	newManager := func() *policy.Manager {
		cfg := &config.Config{}
		cfg.Policies.Signing.Mode = "enforce"
		cfg.Policies.Signing.TrustStore = f.trustDir
		cfg.Policies.Remote.URL = srv.URL + "/v1/policy"
		cfg.Policies.Remote.LongPoll = "0s"
		cfg.Policies.Remote.CacheDir = cacheDir
		src, berr := buildRemotePolicySource(context.Background(), cfg, nil)
		if berr != nil {
			t.Fatalf("build source: %v", berr)
		}
		m := policy.NewManager(t.TempDir(), "unused", nil, "", "")
		m.SetSigningConfig("enforce", f.trustDir)
		m.SetSource(src)
		return m
	}

	if _, err := newManager().Get(); err != nil {
		t.Fatalf("first daemon: %v", err)
	}
	srv.Close()

	// A second daemon starting against a dead server.
	p, err := newManager().Get()
	if err != nil {
		t.Fatalf("a restart during an outage failed to start: %v", err)
	}
	if p.Name != "baseline" {
		t.Errorf("installed %q, want the cached document", p.Name)
	}
}

// TestE2E_CacheIsVerifiedLikeAnyOtherBundle: a tampered cache must not load.
func TestE2E_TamperedCacheIsRefused(t *testing.T) {
	f := newServedFixture(t)
	f.put(t, "base.yaml", baselineDoc)

	store, err := policyserve.NewDirStore(policyserve.StoreConfig{
		PolicyDir: f.policyDir, DefaultPolicy: "base.yaml", TrustStorePath: f.trustDir,
	})
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	srv := httptest.NewServer(policyserve.NewServer(store, nil).Handler())

	cacheDir := t.TempDir()
	build := func() policy.Source {
		cfg := &config.Config{}
		cfg.Policies.Remote.URL = srv.URL + "/v1/policy"
		cfg.Policies.Remote.LongPoll = "0s"
		cfg.Policies.Remote.CacheDir = cacheDir
		src, berr := buildRemotePolicySource(context.Background(), cfg, nil)
		if berr != nil {
			t.Fatalf("build source: %v", berr)
		}
		return src
	}

	m := policy.NewManager(t.TempDir(), "unused", nil, "", "")
	m.SetSigningConfig("enforce", f.trustDir)
	m.SetSource(build())
	if _, err := m.Get(); err != nil {
		t.Fatalf("first load: %v", err)
	}
	srv.Close()

	// Rewrite the cached document, keeping the signature that covered the
	// original. The cache lives on disk under the daemon's own directory, so
	// this is the local-tampering case, and it must fail the same check a
	// served bundle fails.
	if err := os.WriteFile(filepath.Join(cacheDir, "policy.yaml"), []byte(strictDoc), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	m2 := policy.NewManager(t.TempDir(), "unused", nil, "", "")
	m2.SetSigningConfig("enforce", f.trustDir)
	m2.SetSource(build())
	if _, err := m2.Get(); err == nil {
		t.Fatal("a tampered cache loaded")
	}
}
