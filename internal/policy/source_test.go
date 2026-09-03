package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const minimalPolicy = "version: 1\nname: served\n"

func writePolicyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(minimalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestFileSource_ReturnsDataAndSignature. The signature has to come back with
// the document: splitting fetch from verify is what lets one verification run
// over a file and over a served bundle, and it only works if a source hands
// back both.
func TestFileSource_ReturnsDataAndSignature(t *testing.T) {
	dir := writePolicyDir(t)
	if err := os.WriteFile(filepath.Join(dir, "p.yaml.sig"), []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := (&FileSource{Dir: dir, Name: "p"}).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(b.Data) != minimalPolicy {
		t.Errorf("Data = %q", b.Data)
	}
	if string(b.Signature) != `{"version":1}` {
		t.Errorf("Signature = %q", b.Signature)
	}
	if !strings.HasSuffix(b.Name, "p.yaml") {
		t.Errorf("Name = %q, want the path", b.Name)
	}
}

// TestFileSource_MissingSignatureIsNotAnError. The signing mode decides
// whether an unsigned policy may load. Reporting the absence as a read failure
// would turn `signing: off` into a hard error for every policy nobody signed.
func TestFileSource_MissingSignatureIsNotAnError(t *testing.T) {
	b, err := (&FileSource{Dir: writePolicyDir(t), Name: "p"}).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if b.Signature != nil {
		t.Errorf("Signature = %q, want nil", b.Signature)
	}
}

// TestFileSource_ManifestMismatchFails. The manifest check is a property of
// the local directory and has to stay on the fetch, not move to the Manager
// where a served bundle would be measured against a list it can never be in.
func TestFileSource_ManifestMismatchFails(t *testing.T) {
	dir := writePolicyDir(t)
	manifest := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(manifest, []byte("0000000000000000000000000000000000000000000000000000000000000000  p.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := (&FileSource{Dir: dir, Name: "p", ManifestPath: manifest}).Fetch(context.Background())
	if err == nil {
		t.Fatal("a policy whose digest does not match the manifest was accepted")
	}
}

// policyServer is a fake policy endpoint.
type policyServer struct {
	body      string
	sig       string
	etag      string
	status    int
	requests  atomic.Int32
	lastIfNIM atomic.Value // string
	lastQuery atomic.Value // string
}

func (p *policyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	p.lastIfNIM.Store(r.Header.Get("If-None-Match"))
	p.lastQuery.Store(r.URL.RawQuery)

	if p.status != 0 && p.status != http.StatusOK {
		http.Error(w, "server said no, and here is your request back: "+r.URL.String(), p.status)
		return
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == p.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if p.etag != "" {
		w.Header().Set("ETag", p.etag)
	}
	if p.sig != "" {
		w.Header().Set(SignatureHeader, p.sig)
	}
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write([]byte(p.body))
}

// TestRemoteSource_FetchAndConditionalGet is the whole point of an ETag: a
// poll that re-downloads and re-verifies an unchanged document on every tick
// costs the daemon nothing useful, and 304 has to be distinguishable from an
// empty response or a quiet poll reads as a policy that vanished.
func TestRemoteSource_FetchAndConditionalGet(t *testing.T) {
	srv := &policyServer{body: minimalPolicy, sig: `{"version":1,"key_id":"k"}`, etag: `"v1"`}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	src, err := NewRemoteSource(ts.URL + "/v1/policy")
	if err != nil {
		t.Fatalf("NewRemoteSource: %v", err)
	}

	b, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if string(b.Data) != minimalPolicy {
		t.Errorf("Data = %q", b.Data)
	}
	if string(b.Signature) != `{"version":1,"key_id":"k"}` {
		t.Errorf("Signature = %q, want the header value", b.Signature)
	}
	if b.Version != `"v1"` {
		t.Errorf("Version = %q, want the ETag", b.Version)
	}
	if got := srv.lastIfNIM.Load().(string); got != "" {
		t.Errorf("first request sent If-None-Match %q", got)
	}

	_, err = src.Fetch(context.Background())
	if !errors.Is(err, ErrNotModified) {
		t.Fatalf("second Fetch = %v, want ErrNotModified", err)
	}
	if got := srv.lastIfNIM.Load().(string); got != `"v1"` {
		t.Errorf("second request sent If-None-Match %q, want the recorded ETag", got)
	}
}

// TestRemoteSource_ETagNotRecordedOnFailure. Recording the ETag before the
// body was read whole would make the next conditional GET answer 304 for a
// document this agent never installed -- so it would keep enforcing the old
// policy while every poll reported success.
func TestRemoteSource_ETagNotRecordedOnFailure(t *testing.T) {
	body := strings.Repeat("#", 4096) + "\n" + minimalPolicy
	srv := &policyServer{body: body, etag: `"v1"`}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	src, err := NewRemoteSource(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	src.MaxBytes = 128 // smaller than the body

	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("an oversize document was accepted")
	}

	// The next fetch must be unconditional, or the server answers 304 and the
	// agent never sees the document it failed to read.
	src.MaxBytes = int64(len(body)) + 1
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("retry after a failed read: %v", err)
	}
	if got := srv.lastIfNIM.Load().(string); got != "" {
		t.Errorf("the retry sent If-None-Match %q; the failed fetch recorded its ETag", got)
	}
}

// TestRemoteSource_OversizeIsNotTruncation. Parsing a cut document either
// fails confusingly or, worse, succeeds with the rules after the cut missing.
func TestRemoteSource_OversizeIsNotTruncation(t *testing.T) {
	srv := &policyServer{body: strings.Repeat("x", 5000)}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	src, _ := NewRemoteSource(ts.URL)
	src.MaxBytes = 100

	b, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatalf("a document over the cap was accepted, returning %d bytes", len(b.Data))
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want it to name the limit", err)
	}
}

// TestRemoteSource_ErrorsDoNotLeakTheURLOrTheBody.
//
// A policy endpoint can carry a token in its query or its userinfo, and a
// server's error body can echo the request back. Both reach the log.
func TestRemoteSource_ErrorsDoNotLeakTheURLOrTheBody(t *testing.T) {
	srv := &policyServer{status: http.StatusInternalServerError}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	const token = "s3cret-token"
	src, err := NewRemoteSource(ts.URL + "/v1/policy?token=" + token)
	if err != nil {
		t.Fatal(err)
	}

	_, err = src.Fetch(context.Background())
	if err == nil {
		t.Fatal("HTTP 500 produced a bundle")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("the error carries the query token: %v", err)
	}
	if strings.Contains(err.Error(), "here is your request back") {
		t.Fatalf("the error carries the server's response body: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v, want it to name the status", err)
	}

	if got := src.Describe(); strings.Contains(got, token) {
		t.Errorf("Describe() = %q, leaks the token", got)
	}
}

// TestRemoteSource_LongPollParameter. Falling back to the ticker is what
// happens when a server ignores `wait`; asking for it is what makes a pushed
// change arrive in seconds rather than at the next tick.
func TestRemoteSource_LongPollParameter(t *testing.T) {
	srv := &policyServer{body: minimalPolicy}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	src, _ := NewRemoteSource(ts.URL + "/v1/policy")
	src.Wait = 30 * time.Second

	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	q0, err := url.ParseQuery(srv.lastQuery.Load().(string))
	if err != nil {
		t.Fatalf("the query does not parse: %v", err)
	}
	if q0.Get("wait") != "30s" {
		t.Errorf("wait = %q, want 30s", q0.Get("wait"))
	}

	// It must append rather than replace an existing query.
	src2, _ := NewRemoteSource(ts.URL + "/v1/policy?tenant=acme")
	src2.Wait = time.Second
	if _, err := src2.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Parse rather than substring-match: appending with the wrong separator
	// produces "tenant=acme?wait=1s", where both substrings are present and
	// the server sees one parameter whose value is "acme?wait=1s".
	q, err := url.ParseQuery(srv.lastQuery.Load().(string))
	if err != nil {
		t.Fatalf("the query does not parse: %v", err)
	}
	if q.Get("tenant") != "acme" {
		t.Errorf("tenant = %q, want acme", q.Get("tenant"))
	}
	if q.Get("wait") != "1s" {
		t.Errorf("wait = %q, want 1s", q.Get("wait"))
	}
}

// TestRemoteSource_ContextCancellationStopsTheFetch. A long poll holds the
// request open for the whole Wait; a shutdown must not wait it out.
func TestRemoteSource_ContextCancellationStopsTheFetch(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer ts.Close()

	src, _ := NewRemoteSource(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := src.Fetch(ctx); err == nil {
		t.Fatal("a cancelled fetch returned a bundle")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v; the caller's context was ignored", elapsed)
	}
}

func TestNewRemoteSource_Validation(t *testing.T) {
	for _, raw := range []string{"", "ftp://x/policy", "http://", "not a url at all\n"} {
		if _, err := NewRemoteSource(raw); err == nil {
			t.Errorf("NewRemoteSource(%q) was accepted", raw)
		}
	}
	if _, err := NewRemoteSource("https://policy.example/v1/policy"); err != nil {
		t.Errorf("a valid URL was rejected: %v", err)
	}
}

// TestManager_RemoteSourceGetsTheSameVerification is the property the split
// exists for. A policy served over HTTP must clear the same trust bar as one
// read from disk, not an approximation of it.
func TestManager_RemoteSourceGetsTheSameVerification(t *testing.T) {
	srv := &policyServer{body: minimalPolicy} // served with no signature
	ts := httptest.NewServer(srv)
	defer ts.Close()
	src, _ := NewRemoteSource(ts.URL)

	m := NewManager(t.TempDir(), "p", nil, "", "")
	m.SetSource(src)
	m.SetSigningConfig("enforce", t.TempDir())

	if _, err := m.Get(); err == nil {
		t.Fatal("an unsigned policy loaded under signing: enforce")
	} else if !strings.Contains(err.Error(), "signing verification") {
		t.Errorf("error = %v, want a signing failure", err)
	}
}

// TestManager_NotModifiedKeepsTheCurrentPolicy. A conditional GET answering
// 304 means the agent already has the current document. Installing an error
// there would take enforcement down on the first quiet poll.
func TestManager_NotModifiedKeepsTheCurrentPolicy(t *testing.T) {
	srv := &policyServer{body: minimalPolicy, etag: `"v1"`}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	src, _ := NewRemoteSource(ts.URL)

	m := NewManager(t.TempDir(), "p", nil, "", "")
	m.SetSource(src)

	first, err := m.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if first == nil {
		t.Fatal("no policy")
	}

	again, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("ReloadContext on a 304 returned an error: %v", err)
	}
	if again != first {
		t.Error("a 304 replaced the cached policy")
	}
	if got, _ := m.Get(); got != first {
		t.Error("a 304 left the Manager without a policy")
	}
}

// TestManager_NotModifiedWithNoPolicyIsAnError. Before anything is loaded a
// 304 is a broken server, not a quiet one: the agent has nothing to keep.
func TestManager_NotModifiedWithNoPolicyIsAnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer ts.Close()
	src, _ := NewRemoteSource(ts.URL)

	m := NewManager(t.TempDir(), "p", nil, "", "")
	m.SetSource(src)

	if _, err := m.ReloadContext(context.Background()); !errors.Is(err, ErrNotModified) {
		t.Fatalf("err = %v, want ErrNotModified with no policy cached", err)
	}
}

// TestManager_FileSourceUnchanged. Every existing deployment reads a local
// directory, and the refactor must not have moved when a manifest or a
// signature is checked.
func TestManager_FileSourceUnchanged(t *testing.T) {
	dir := writePolicyDir(t)

	m := NewManager(dir, "p", nil, "", "")
	p, err := m.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Name != "served" {
		t.Errorf("Name = %q", p.Name)
	}

	// Unsigned under enforce still fails, from the file path as before.
	m2 := NewManager(dir, "p", nil, "", "")
	m2.SetSigningConfig("enforce", t.TempDir())
	if _, err := m2.Get(); err == nil {
		t.Error("an unsigned local policy loaded under signing: enforce")
	}

	// And signing: off still loads it.
	m3 := NewManager(dir, "p", nil, "", "")
	m3.SetSigningConfig("off", "")
	if _, err := m3.Get(); err != nil {
		t.Errorf("signing: off rejected an unsigned policy: %v", err)
	}
}

// TestManager_SourceIsUsedForEveryLoad. A Manager that resolved the source
// once and cached it would keep polling a server the operator had switched
// away from.
func TestManager_SourceIsUsedForEveryLoad(t *testing.T) {
	srv := &policyServer{body: minimalPolicy}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	src, _ := NewRemoteSource(ts.URL)

	m := NewManager(t.TempDir(), "p", nil, "", "")
	m.SetSource(src)
	if _, err := m.Get(); err != nil {
		t.Fatalf("Get: %v", err)
	}
	before := srv.requests.Load()

	if _, err := m.ReloadContext(context.Background()); err != nil {
		t.Fatalf("ReloadContext: %v", err)
	}
	if srv.requests.Load() == before {
		t.Fatal("Reload did not fetch again")
	}
}

func TestFileSource_Describe(t *testing.T) {
	got := (&FileSource{Dir: "/etc/agentmon/policies", Name: "default"}).Describe()
	if !strings.Contains(got, "default") {
		t.Errorf("Describe() = %q", got)
	}
}

var _ Source = (*FileSource)(nil)
var _ Source = (*RemoteSource)(nil)
