package policyserve_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"
	"encoding/base64"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/policy/signing"
	"github.com/diffsec/agentmon/internal/policyserve"
)

const policyA = `version: 1
name: a
file_rules:
  - name: allow-tmp
    paths: ["/tmp/**"]
    operations: [read]
    decision: allow
`

const policyB = `version: 1
name: b
file_rules:
  - name: allow-var
    paths: ["/var/**"]
    operations: [read]
    decision: allow
`

type signedFixture struct {
	policyDir  string
	trustDir   string
	privateKey ed25519.PrivateKey
}

func newFixture(t *testing.T, name, body string) *signedFixture {
	t.Helper()
	f := &signedFixture{policyDir: t.TempDir(), trustDir: t.TempDir()}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f.privateKey = priv
	kf := signing.PublicKeyFile{
		KeyID:     signing.KeyID(pub),
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	kb, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(filepath.Join(f.trustDir, kf.KeyID+".json"), kb, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	f.write(t, name, body)
	return f
}

func (f *signedFixture) write(t *testing.T, name, body string) {
	t.Helper()
	path := filepath.Join(f.policyDir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	sig, err := signing.Sign([]byte(body), f.privateKey, "test")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sb, _ := json.MarshalIndent(sig, "", "  ")
	if err := os.WriteFile(path+".sig", sb, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
}

// TestRoundTrip_ManagerInstallsAServedPolicy is the contract between the two
// halves: what the server writes, RemoteSource fetches and Manager verifies
// against the agent's own trust store with signing enforced.
func TestRoundTrip_ManagerInstallsAServedPolicy(t *testing.T) {
	f := newFixture(t, "base.yaml", policyA)
	store, err := policyserve.NewDirStore(policyserve.StoreConfig{
		PolicyDir: f.policyDir, DefaultPolicy: "base.yaml", TrustStorePath: f.trustDir,
	})
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	srv := httptest.NewServer(policyserve.NewServer(store, nil).Handler())
	defer srv.Close()

	src, err := policy.NewRemoteSource(srv.URL + "/v1/policy")
	if err != nil {
		t.Fatalf("NewRemoteSource: %v", err)
	}
	m := policy.NewManager(t.TempDir(), "unused", nil, "", "")
	m.SetSigningConfig("enforce", f.trustDir)
	m.SetSource(src)

	p, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("reload from the server: %v", err)
	}
	if p.Name != "a" {
		t.Fatalf("installed policy %q, want a", p.Name)
	}

	// The second fetch is conditional and the server answers 304; the manager
	// must keep the policy rather than treat that as a failure.
	if _, err := m.ReloadContext(context.Background()); err != nil {
		t.Fatalf("second reload: %v", err)
	}
	b, err := src.Fetch(context.Background())
	if err == nil || !errors.Is(err, policy.ErrNotModified) {
		t.Fatalf("third fetch returned (%v, %v), want ErrNotModified", b, err)
	}

	// Replace the served bundle; the next reload installs it with no restart.
	f.write(t, "base.yaml", policyB)
	if err := store.Reload(); err != nil {
		t.Fatalf("server reload: %v", err)
	}
	p, err = m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("reload after the server changed: %v", err)
	}
	if p.Name != "b" {
		t.Fatalf("installed policy %q, want b after the server swapped it", p.Name)
	}
}

// TestRoundTrip_UntrustedKeyIsRefused is the property the whole design rests
// on: the server is untrusted, so a bundle it signs with a key the agent does
// not trust must not install.
func TestRoundTrip_UntrustedKeyIsRefused(t *testing.T) {
	server := newFixture(t, "base.yaml", policyA)
	agent := newFixture(t, "unused.yaml", policyA) // a different trust store

	store, err := policyserve.NewDirStore(policyserve.StoreConfig{
		PolicyDir: server.policyDir, DefaultPolicy: "base.yaml", TrustStorePath: server.trustDir,
	})
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	srv := httptest.NewServer(policyserve.NewServer(store, nil).Handler())
	defer srv.Close()

	src, err := policy.NewRemoteSource(srv.URL + "/v1/policy")
	if err != nil {
		t.Fatalf("NewRemoteSource: %v", err)
	}
	m := policy.NewManager(t.TempDir(), "unused", nil, "", "")
	m.SetSigningConfig("enforce", agent.trustDir)
	m.SetSource(src)

	if _, err := m.ReloadContext(context.Background()); err == nil {
		t.Fatal("a policy signed with a key the agent does not trust was installed")
	}
}
