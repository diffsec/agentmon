package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type stubSource struct {
	bundles []*Bundle
	errs    []error
	calls   int
}

func (s *stubSource) Describe() string { return "stub" }

func (s *stubSource) Fetch(context.Context) (*Bundle, error) {
	i := s.calls
	s.calls++
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	if i < len(s.bundles) {
		return s.bundles[i], nil
	}
	return nil, errors.New("stub exhausted")
}

func TestCachingSource_WritesWhatItFetched(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	inner := &stubSource{bundles: []*Bundle{{Data: []byte("policy: a"), Signature: []byte(`{"v":1}`), Version: `"e1"`}}}
	c := NewCachingSource(inner, dir, nil)

	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, cacheBundleName))
	if err != nil {
		t.Fatalf("read cached policy: %v", err)
	}
	if string(data) != "policy: a" {
		t.Errorf("cached %q, want the fetched bytes", data)
	}
	sig, err := os.ReadFile(filepath.Join(dir, cacheSigName))
	if err != nil {
		t.Fatalf("read cached signature: %v", err)
	}
	if string(sig) != `{"v":1}` {
		t.Errorf("cached signature %q", sig)
	}
	if _, err := os.Stat(filepath.Join(dir, cacheBundleName+".tmp")); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}
}

func TestCachingSource_FallsBackOnFirstFetchFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, cacheBundleName), []byte("policy: cached"), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, cacheSigName), []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatalf("seed sig: %v", err)
	}

	inner := &stubSource{errs: []error{errors.New("connection refused")}}
	c := NewCachingSource(inner, dir, nil)

	b, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("a reachable cache should carry the startup: %v", err)
	}
	if string(b.Data) != "policy: cached" {
		t.Errorf("got %q, want the cached document", b.Data)
	}
	if string(b.Signature) != `{"v":1}` {
		t.Errorf("cached signature not returned: %q", b.Signature)
	}
	// A cached bundle must not carry a Version: the agent has not proved to
	// the server that it holds this document, so it must not satisfy a later
	// conditional GET.
	if b.Version != "" {
		t.Errorf("cached bundle carries Version %q", b.Version)
	}
}

func TestCachingSource_DoesNotFallBackAfterASuccessfulFetch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	inner := &stubSource{
		bundles: []*Bundle{{Data: []byte("policy: fresh")}},
		errs:    []error{nil, errors.New("connection refused")},
	}
	c := NewCachingSource(inner, dir, nil)

	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	// The cache is a startup fallback. Serving it mid-run would silently
	// reinstall an older document over the one already in memory.
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("a mid-run failure fell back to the cache")
	}
}

func TestCachingSource_NoCacheAndNoServerReportsTheFetchError(t *testing.T) {
	inner := &stubSource{errs: []error{errors.New("connection refused")}}
	c := NewCachingSource(inner, filepath.Join(t.TempDir(), "empty"), nil)

	_, err := c.Fetch(context.Background())
	if err == nil {
		t.Fatal("no cache and no server must fail")
	}
	// The operator has to fix the fetch, not the cache.
	if err.Error() != "connection refused" {
		t.Errorf("error = %v, want the fetch failure", err)
	}
}

func TestCachingSource_NotModifiedPassesThrough(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	inner := &stubSource{errs: []error{ErrNotModified}}
	c := NewCachingSource(inner, dir, nil)

	_, err := c.Fetch(context.Background())
	if !errors.Is(err, ErrNotModified) {
		t.Fatalf("err = %v, want ErrNotModified", err)
	}
	if _, serr := os.Stat(dir); serr == nil {
		t.Error("a 304 wrote a cache entry")
	}
}

func TestCachingSource_NotModifiedIsNotACacheMiss(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, cacheBundleName), []byte("policy: stale"), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	inner := &stubSource{errs: []error{ErrNotModified, errors.New("connection refused")}}
	c := NewCachingSource(inner, dir, nil)

	// A 304 says the Manager already holds the current document. Treating it
	// as a failed fetch would hand back the cached copy, which may be older
	// than what the Manager is enforcing.
	if _, err := c.Fetch(context.Background()); !errors.Is(err, ErrNotModified) {
		t.Fatalf("first fetch = %v, want ErrNotModified", err)
	}
	// A 304 also proves the server is reachable, so the startup fallback is
	// spent and a later failure must be reported.
	if _, err := c.Fetch(context.Background()); errors.Is(err, ErrNotModified) || err == nil {
		t.Fatalf("second fetch = %v, want the fetch failure", err)
	}
}

func TestCachingSource_UnsignedBundleClearsAStaleSignature(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	inner := &stubSource{bundles: []*Bundle{
		{Data: []byte("policy: a"), Signature: []byte(`{"v":1}`)},
		{Data: []byte("policy: b")},
	}}
	c := NewCachingSource(inner, dir, nil)

	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	// Keeping the old signature would pair it with the new document, so the
	// next startup would verify a signature that covers different bytes.
	if _, err := os.Stat(filepath.Join(dir, cacheSigName)); !os.IsNotExist(err) {
		t.Fatal("a stale signature survived an unsigned bundle")
	}
}

func TestCachingSource_DescribeNamesTheInnerSource(t *testing.T) {
	c := NewCachingSource(&stubSource{}, t.TempDir(), nil)
	if c.Describe() != "stub" {
		t.Errorf("Describe() = %q, want the inner source", c.Describe())
	}
}

func TestAtomicWriteFile_RemovesTheTempFileWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory cannot be replaced by a rename, so the rename
	// fails after the temp file was written.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := atomicWriteFile(target, []byte("x"), 0o600); err == nil {
		t.Fatal("writing over a non-empty directory reported success")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Error("a failed write left its temporary file behind, which the next read could pick up")
	}
}
