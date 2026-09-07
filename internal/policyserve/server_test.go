package policyserve

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/policy/signing"
)

const samplePolicy = `version: 1
name: sample
file_rules:
  - name: allow-tmp
    paths: ["/tmp/**"]
    operations: [read]
    decision: allow
`

const otherPolicy = `version: 1
name: other
file_rules:
  - name: allow-var
    paths: ["/var/**"]
    operations: [read]
    decision: allow
`

// signedDir writes policies plus a trust store and returns (policyDir, trustDir).
func signedDir(t *testing.T, policies map[string]string) (string, string) {
	pdir, tdir, _ := signedDirKey(t, policies)
	return pdir, tdir
}

// signedDirKey is signedDir, also handing back the signing key so a test can
// replace a bundle in place with one the same trust store accepts.
func signedDirKey(t *testing.T, policies map[string]string) (string, string, ed25519.PrivateKey) {
	t.Helper()
	pdir := t.TempDir()
	tdir := t.TempDir()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyID := signing.KeyID(pub)
	kf := signing.PublicKeyFile{
		KeyID:     keyID,
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Label:     "test",
	}
	kb, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(filepath.Join(tdir, keyID+".json"), kb, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	for name, body := range policies {
		path := filepath.Join(pdir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write policy: %v", err)
		}
		sig, err := signing.Sign([]byte(body), priv, "test")
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sb, _ := json.MarshalIndent(sig, "", "  ")
		if err := os.WriteFile(path+".sig", sb, 0o600); err != nil {
			t.Fatalf("write sig: %v", err)
		}
	}
	return pdir, tdir, priv
}

// replaceSigned overwrites a bundle and re-signs it with the same key.
func replaceSigned(t *testing.T, pdir string, priv ed25519.PrivateKey, name, body string) {
	t.Helper()
	path := filepath.Join(pdir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("rewrite policy: %v", err)
	}
	sig, err := signing.Sign([]byte(body), priv, "test")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sb, _ := json.MarshalIndent(sig, "", "  ")
	if err := os.WriteFile(path+".sig", sb, 0o600); err != nil {
		t.Fatalf("rewrite sig: %v", err)
	}
}

func writeBindings(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "bindings.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write bindings: %v", err)
	}
	return p
}

func newTestStore(t *testing.T, cfg StoreConfig) *DirStore {
	t.Helper()
	s, err := NewDirStore(cfg)
	if err != nil {
		t.Fatalf("NewDirStore: %v", err)
	}
	return s
}

func TestServe_SignedBundleWithSignatureHeader(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/policy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if string(body[:n]) != samplePolicy {
		t.Errorf("body is not the signed bytes")
	}
	sig := resp.Header.Get(policy.SignatureHeader)
	if sig == "" {
		t.Fatal("no signature header")
	}
	// The header must verify against the same trust store, byte-for-byte
	// against the served body: that is the whole contract.
	ts, err := signing.LoadTrustStore(tdir, true)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}
	if _, err := signing.VerifyBytes(body[:n], []byte(sig), ts); err != nil {
		t.Fatalf("served bundle does not verify: %v", err)
	}
	if resp.Header.Get("ETag") == "" {
		t.Error("no ETag")
	}
}

func TestServe_ConditionalGetReturns304(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	first, err := http.Get(srv.URL + "/v1/policy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	first.Body.Close()
	etag := first.Header.Get("ETag")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/policy", nil)
	req.Header.Set("If-None-Match", etag)
	second, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("conditional get: %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", second.StatusCode)
	}
}

func TestServe_ETagIsContentAddressed(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"a.yaml": samplePolicy, "b.yaml": samplePolicy})
	bindings := writeBindings(t, t.TempDir(), `bindings:
  - name: a
    policy: a.yaml
    match:
      hostnames: ["host-a"]
  - name: b
    policy: b.yaml
`)
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, BindingsPath: bindings, TrustStorePath: tdir})

	a, _, ok := store.Lookup(Selector{Hostname: "host-a"})
	if !ok {
		t.Fatal("no binding for host-a")
	}
	b, _, ok := store.Lookup(Selector{Hostname: "host-z"})
	if !ok {
		t.Fatal("no catch-all binding")
	}
	// Identical documents under different names must share an ETag; a
	// per-file counter or mtime would force a redundant refetch.
	if a.Version != b.Version {
		t.Errorf("identical documents got different ETags: %s vs %s", a.Version, b.Version)
	}
}

func TestServe_NoBindingIs404NotEmptyPolicy(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"strict.yaml": samplePolicy})
	bindings := writeBindings(t, t.TempDir(), `bindings:
  - name: prod-only
    policy: strict.yaml
    match:
      tags: ["prod"]
`)
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, BindingsPath: bindings, TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/policy?tags=dev")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 so the agent keeps its current policy", resp.StatusCode)
	}
	if resp.Header.Get("ETag") != "" {
		t.Error("a 404 must not carry an ETag")
	}
}

func TestServe_LongPollWakesOnReload(t *testing.T) {
	pdir, tdir, priv := signedDirKey(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	first, err := http.Get(srv.URL + "/v1/policy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	first.Body.Close()
	etag := first.Header.Get("ETag")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/policy?wait=5s", nil)
	req.Header.Set("If-None-Match", etag)

	done := make(chan *http.Response, 1)
	go func() {
		r, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Errorf("long poll: %v", derr)
			done <- nil
			return
		}
		done <- r
	}()

	// Replace the bundle while the poll is in flight, then reload.
	time.Sleep(100 * time.Millisecond)
	replaceSigned(t, pdir, priv, "base.yaml", otherPolicy)
	if err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	select {
	case resp := <-done:
		if resp == nil {
			t.Fatal("long poll failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 on a changed policy", resp.StatusCode)
		}
		if resp.Header.Get("ETag") == etag {
			t.Error("ETag did not change across the reload")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("long poll did not wake on the reload")
	}
}

func TestServe_LongPollTimesOutWith304(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	first, _ := http.Get(srv.URL + "/v1/policy")
	first.Body.Close()
	etag := first.Header.Get("ETag")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/policy?wait=200ms", nil)
	req.Header.Set("If-None-Match", etag)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("long poll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("returned after %v, the wait was not honoured", elapsed)
	}
}

func TestParseWait_ClampsAndRejects(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"nonsense", 0},
		{"-5s", 0},
		{"0s", 0},
		{"30s", 30 * time.Second},
		{"1h", MaxWait},
	}
	for _, c := range cases {
		if got := parseWait(c.in); got != c.want {
			t.Errorf("parseWait(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStore_RefusesBundleThatFailsVerification(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	// Tamper after signing.
	if err := os.WriteFile(filepath.Join(pdir, "base.yaml"), []byte(otherPolicy), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_, err := NewDirStore(StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	if err == nil {
		t.Fatal("a tampered bundle was accepted for serving")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("error = %v, want a verification failure", err)
	}
}

func TestStore_RequiresTrustStoreUnlessAllowUnsigned(t *testing.T) {
	pdir, _ := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	_, err := NewDirStore(StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml"})
	if err == nil {
		t.Fatal("serving without a trust store was allowed by default")
	}
	// LoadTrustStore("") also fails, so the property survives without this
	// guard -- but it fails as "read trust store dir: no such file", which
	// sends an operator looking for a directory rather than at the flag.
	if !strings.Contains(err.Error(), "allow-unsigned") {
		t.Errorf("error = %v, want it to name the opt-out", err)
	}
	if _, err := NewDirStore(StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", AllowUnsigned: true}); err != nil {
		t.Fatalf("allow-unsigned should serve: %v", err)
	}
}

func TestStore_RefusesUnparseablePolicy(t *testing.T) {
	pdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pdir, "bad.yaml"), []byte("not: [a policy"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := NewDirStore(StoreConfig{PolicyDir: pdir, DefaultPolicy: "bad.yaml", AllowUnsigned: true})
	if err == nil {
		t.Fatal("an unparseable document was accepted for serving")
	}
}

func TestStore_FailedReloadKeepsTheServedSet(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	before, _, _ := store.Lookup(Selector{})

	if err := os.WriteFile(filepath.Join(pdir, "base.yaml"), []byte("not: [a policy"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("reload accepted a broken document")
	}
	after, _, ok := store.Lookup(Selector{})
	if !ok || after.Version != before.Version {
		t.Error("a failed reload withdrew the policy instead of keeping the last good one")
	}
	if store.LoadErr() == nil {
		t.Error("LoadErr is nil after a failed reload")
	}
}

func TestServe_HealthReportsDegradedAfterFailedReload(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	ok, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", ok.StatusCode)
	}

	_ = os.WriteFile(filepath.Join(pdir, "base.yaml"), []byte("not: [a policy"), 0o600)
	_ = store.Reload()

	bad, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer bad.Body.Close()
	if bad.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("healthz = %d after a failed reload, want 503", bad.StatusCode)
	}
}

func TestServe_RejectsNonGET(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/policy", "application/yaml", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestSelectorFrom_HeadersBeatQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy?tenant=q&hostname=qh&user=qu&tags=q1,q2", nil)
	req.Header.Set(HeaderTenant, "acme")
	req.Header.Set(HeaderHostname, "build-01")
	req.Header.Set(HeaderUser, "ci")
	req.Header.Set(HeaderTags, " prod , pci ")
	sel := selectorFrom(req)
	if sel.Tenant != "acme" || sel.Hostname != "build-01" || sel.User != "ci" {
		t.Fatalf("selector = %+v", sel)
	}
	if len(sel.Tags) != 2 || sel.Tags[0] != "prod" || sel.Tags[1] != "pci" {
		t.Fatalf("tags = %v, want [prod pci]", sel.Tags)
	}

	bare := httptest.NewRequest(http.MethodGet, "/v1/policy?tenant=q&tags=a,,b", nil)
	sel = selectorFrom(bare)
	if sel.Tenant != "q" {
		t.Errorf("query fallback failed: %+v", sel)
	}
	if len(sel.Tags) != 2 {
		t.Errorf("tags = %v, want the empty element dropped", sel.Tags)
	}
}

func TestServe_LongPollHonoursClientCancel(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	first, _ := http.Get(srv.URL + "/v1/policy")
	first.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/policy?wait=5s", nil)
	req.Header.Set("If-None-Match", first.Header.Get("ETag"))

	errCh := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		errCh <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("a cancelled long poll returned a response")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling the request did not release the long poll")
	}
}

func TestServe_LongPollIgnoresAReloadThatChangedNothing(t *testing.T) {
	pdir, tdir, _ := signedDirKey(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	srv := httptest.NewServer(NewServer(store, nil).Handler())
	defer srv.Close()

	first, _ := http.Get(srv.URL + "/v1/policy")
	first.Body.Close()
	etag := first.Header.Get("ETag")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/policy?wait=700ms", nil)
	req.Header.Set("If-None-Match", etag)
	done := make(chan *http.Response, 1)
	go func() {
		r, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Errorf("long poll: %v", derr)
			done <- nil
			return
		}
		done <- r
	}()

	// A reload triggered by some other tenant's policy leaves this bundle
	// alone. Answering 200 here would hand back the document the agent
	// already has, on every reload, for every agent.
	time.Sleep(100 * time.Millisecond)
	if err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	select {
	case resp := <-done:
		if resp == nil {
			t.Fatal("long poll failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotModified {
			t.Fatalf("status = %d, want 304: the bundle did not change", resp.StatusCode)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("long poll never returned")
	}
}

// countingHandler reports how many requests are inside the handler.
type countingHandler struct {
	inner  http.Handler
	active int64
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&c.active, 1)
	defer atomic.AddInt64(&c.active, -1)
	c.inner.ServeHTTP(w, r)
}

func TestServe_CancelledLongPollReleasesTheHandler(t *testing.T) {
	pdir, tdir, _ := signedDirKey(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	h := &countingHandler{inner: NewServer(store, nil).Handler()}
	srv := httptest.NewServer(h)
	defer srv.Close()

	first, _ := http.Get(srv.URL + "/v1/policy")
	first.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/policy?wait=30s", nil)
	req.Header.Set("If-None-Match", first.Header.Get("ETag"))
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		_ = err
	}()

	// Wait for the poll to be inside the handler, then cancel it. The client
	// gives up either way; what is asserted here is that the server stops
	// holding the request, which a client-side error alone does not show.
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt64(&h.active) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&h.active) == 0 {
		t.Fatal("the long poll never reached the handler")
	}
	cancel()

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&h.active) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the handler was still holding a cancelled long poll; it would hold it for the full wait")
}

func TestServe_SignatureHeaderIsSingleLine(t *testing.T) {
	pdir, tdir := signedDir(t, map[string]string{"base.yaml": samplePolicy})
	store := newTestStore(t, StoreConfig{PolicyDir: pdir, DefaultPolicy: "base.yaml", TrustStorePath: tdir})
	bundle, _, ok := store.Lookup(Selector{})
	if !ok {
		t.Fatal("no bundle")
	}
	// signing.SignFile writes indented JSON. An HTTP header value cannot hold
	// a newline, and Go rewrites one to a space on the way out -- valid JSON
	// only because JSON ignores whitespace. Compacting makes that deliberate.
	if strings.ContainsAny(string(bundle.Signature), "\r\n") {
		t.Errorf("signature header contains a newline: %q", bundle.Signature)
	}
	var probe map[string]any
	if err := json.Unmarshal(bundle.Signature, &probe); err != nil {
		t.Fatalf("compacted signature is not valid JSON: %v", err)
	}
	if probe["key_id"] == "" {
		t.Error("compaction dropped key_id")
	}
}
