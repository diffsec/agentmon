package policyserve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/policy/signing"
	"github.com/diffsec/agentmon/pkg/hotreload"
)

// stageBundle writes a policy and its signature into .staging/, signature
// first, which is the order the watcher's promotion depends on.
func stageBundle(t *testing.T, pdir string, priv []byte, name, body string, sign bool) {
	t.Helper()
	staging := filepath.Join(pdir, ".staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	if sign {
		sig, err := signing.Sign([]byte(body), priv, "test")
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sb, _ := json.MarshalIndent(sig, "", "  ")
		if err := os.WriteFile(filepath.Join(staging, name+".sig"), sb, 0o600); err != nil {
			t.Fatalf("write staged sig: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(staging, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write staged policy: %v", err)
	}
}

func startWatcher(t *testing.T, pdir string, store *DirStore) {
	t.Helper()
	w, err := hotreload.NewPolicyWatcher(hotreload.WatcherConfig{
		PolicyDir:       pdir,
		Loader:          store,
		Debounce:        20 * time.Millisecond,
		StagingDebounce: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.Start(ctx); err != nil {
		cancel()
		t.Fatalf("watcher Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = w.Stop()
	})
}

func etagOf(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	return resp.Header.Get("ETag")
}

func TestWatch_StagedSignedBundleIsPublished(t *testing.T) {
	pdir, tdir, priv := signedDirKey(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()
	startWatcher(t, pdir, store)

	before := etagOf(t, srv.URL+"/v1/policy")

	stageBundle(t, pdir, priv, "base.yaml", otherPolicy, true)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if etagOf(t, srv.URL+"/v1/policy") != before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("a signed bundle staged into .staging/ was never published")
}

func TestWatch_TamperedStagedBundleIsNotPublished(t *testing.T) {
	pdir, tdir, priv := signedDirKey(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()
	startWatcher(t, pdir, store)

	before := etagOf(t, srv.URL+"/v1/policy")

	// Sign one document, stage a different one under the same signature.
	staging := filepath.Join(pdir, ".staging")
	stageBundle(t, pdir, priv, "base.yaml", samplePolicy, true)
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(staging, "base.yaml"), []byte(otherPolicy), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	time.Sleep(1500 * time.Millisecond)
	if got := etagOf(t, srv.URL+"/v1/policy"); got != before {
		t.Fatal("a bundle whose signature does not cover its bytes was published")
	}
	if _, err := os.Stat(filepath.Join(staging, "base.yaml")); err != nil {
		t.Error("the rejected bundle left staging")
	}
}

func TestStore_ValidateRejectsUnsignedWhenTrustStoreConfigured(t *testing.T) {
	pdir, tdir, _ := signedDirKey(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})

	unsigned := filepath.Join(t.TempDir(), "new.yaml")
	if err := os.WriteFile(unsigned, []byte(otherPolicy), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := store.Validate(unsigned); err == nil {
		t.Fatal("an unsigned bundle passed validation with a trust store configured")
	}
}

func TestStore_ValidateChecksTheBindingsFile(t *testing.T) {
	pdir, tdir, _ := signedDirKey(t, map[string]string{"base.yaml": samplePolicy})
	bindings := writeBindings(t, t.TempDir(), "bindings:\n  - name: all\n    policy: base.yaml\n")
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, BindingsPath: bindings, TrustStorePath: tdir})

	if err := store.Validate(bindings); err != nil {
		t.Fatalf("a good bindings file failed validation: %v", err)
	}
	// A bindings file must be validated as bindings, not verified as a signed
	// policy; the reverse would reject every bindings change.
	if err := os.WriteFile(bindings, []byte("bindings:\n  - name: broken\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := store.Validate(bindings); err == nil {
		t.Fatal("a bindings file with no policy passed validation")
	}
}
