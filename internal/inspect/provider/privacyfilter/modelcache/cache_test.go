package modelcache_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter/modelcache"
)

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// server serves named blobs and counts requests, so a test can assert that a
// populated cache touched the network zero times.
type server struct {
	*httptest.Server
	blobs map[string][]byte
	hits  int32
	// lie makes Content-Length claim more than the body delivers.
	lie bool
	// extra appends bytes beyond the advertised length.
	extra int
}

func newServer(t *testing.T, blobs map[string][]byte) *server {
	t.Helper()
	s := &server{blobs: blobs}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.hits, 1)
		body, ok := s.blobs[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if s.lie {
			w.Header().Set("Content-Length", "999999")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		if s.extra > 0 {
			// No Content-Length, so the cache cannot pre-check the size and
			// has to notice the over-long body while reading.
			w.Header().Set("Transfer-Encoding", "chunked")
			_, _ = w.Write(append(body, make([]byte, s.extra)...))
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) file(name string) modelcache.File {
	b := s.blobs[name]
	return modelcache.File{Name: name, URL: s.URL + "/" + name, Size: int64(len(b)), SHA256: digest(b)}
}

func newCache(t *testing.T, s *server) (*modelcache.Cache, string) {
	t.Helper()
	dir := t.TempDir()
	return modelcache.New(dir, s.Client(), nil), dir
}

func specOf(s *server, names ...string) modelcache.Spec {
	sp := modelcache.Spec{Name: "test-model"}
	for _, n := range names {
		sp.Files = append(sp.Files, s.file(n))
	}
	return sp
}

// TestEnsure_DownloadsAndVerifies is the happy path.
func TestEnsure_DownloadsAndVerifies(t *testing.T) {
	s := newServer(t, map[string][]byte{
		"model.onnx":      []byte("graph bytes"),
		"model.onnx_data": []byte("weight bytes, pretend this is 917MB"),
	})
	c, root := newCache(t, s)

	dir, err := c.Ensure(context.Background(), specOf(s, "model.onnx", "model.onnx_data"))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if dir != filepath.Join(root, "test-model") {
		t.Errorf("dir = %q", dir)
	}
	for name, want := range s.blobs {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("%s: content differs", name)
		}
	}
}

// TestEnsure_PopulatedCacheSkipsTheNetwork. Re-downloading 917MB on every
// daemon start would be its own outage.
func TestEnsure_PopulatedCacheSkipsTheNetwork(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("graph")})
	c, _ := newCache(t, s)
	spec := specOf(s, "model.onnx")

	if _, err := c.Ensure(context.Background(), spec); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	first := atomic.LoadInt32(&s.hits)

	if _, err := c.Ensure(context.Background(), spec); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := atomic.LoadInt32(&s.hits); got != first {
		t.Errorf("the second Ensure made %d extra request(s)", got-first)
	}
}

// TestEnsure_RejectsAWrongDigest is the control that makes the download source
// irrelevant. Nothing must be left behind, because a caller hands this
// directory straight to ONNX Runtime.
func TestEnsure_RejectsAWrongDigest(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("the wrong bytes")})
	c, _ := newCache(t, s)

	spec := specOf(s, "model.onnx")
	spec.Files[0].SHA256 = digest([]byte("the bytes we asked for"))

	dir, err := c.Ensure(context.Background(), spec)
	if err == nil {
		t.Fatal("a file whose digest did not match was accepted")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("err = %v, want it to name the digest", err)
	}
	_ = dir

	assertNoUsableCache(t, c, spec)
}

// TestEnsure_RejectsAContentLengthLie. The digest would catch a wrong file
// eventually, but not before a lying server had filled the disk, so the size
// is checked before the body is read.
func TestEnsure_RejectsAContentLengthLie(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("small")})
	s.lie = true
	c, _ := newCache(t, s)

	spec := specOf(s, "model.onnx")
	if _, err := c.Ensure(context.Background(), spec); err == nil {
		t.Fatal("a mismatched Content-Length was accepted")
	} else if !strings.Contains(err.Error(), "999999") {
		t.Errorf("err = %v, want it to report the offered length", err)
	}
	assertNoUsableCache(t, c, spec)
}

// TestEnsure_RejectsAnOverLongBody covers a response with no Content-Length,
// where the only defence is refusing to read past the expected size.
func TestEnsure_RejectsAnOverLongBody(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("expected")})
	s.extra = 4096
	c, _ := newCache(t, s)

	spec := specOf(s, "model.onnx")
	if _, err := c.Ensure(context.Background(), spec); err == nil {
		t.Fatal("a body longer than the spec was accepted")
	}
	assertNoUsableCache(t, c, spec)
}

// TestEnsure_LeavesNoPartialFiles. A .partial-* left in the directory would be
// harmless, but a destination file holding unverified bytes would not: the
// next run's size check could pass it straight to ONNX Runtime.
func TestEnsure_LeavesNoPartialFiles(t *testing.T) {
	s := newServer(t, map[string][]byte{"a.bin": []byte("good"), "b.bin": []byte("bad bytes")})
	c, root := newCache(t, s)

	spec := specOf(s, "a.bin", "b.bin")
	spec.Files[1].SHA256 = digest([]byte("different"))

	if _, err := c.Ensure(context.Background(), spec); err == nil {
		t.Fatal("Ensure succeeded despite a bad digest")
	}

	entries, err := os.ReadDir(filepath.Join(root, "test-model"))
	if err != nil {
		return // no directory at all is fine
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".partial-") {
			t.Errorf("a partial download was left behind: %s", e.Name())
		}
		if e.Name() == "b.bin" {
			t.Error("the file that failed verification was installed anyway")
		}
	}
}

// TestEnsure_PartialCacheIsRedownloaded. An interrupted run leaves files with
// no marker; without the marker check the next start would load a truncated
// model.
func TestEnsure_PartialCacheIsRedownloaded(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("graph bytes")})
	c, root := newCache(t, s)
	spec := specOf(s, "model.onnx")

	dir := filepath.Join(root, "test-model")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A truncated file and no marker: what a killed download looks like.
	if err := os.WriteFile(filepath.Join(dir, "model.onnx"), []byte("gra"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Ensure(context.Background(), spec); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "model.onnx"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "graph bytes" {
		t.Errorf("the truncated file was kept: %q", got)
	}
}

// TestEnsure_WrongSizeInCacheIsRedownloaded covers a cache that has the marker
// but whose file changed underneath.
func TestEnsure_WrongSizeInCacheIsRedownloaded(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("graph bytes")})
	c, root := newCache(t, s)
	spec := specOf(s, "model.onnx")

	if _, err := c.Ensure(context.Background(), spec); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	path := filepath.Join(root, "test-model", "model.onnx")
	if err := os.WriteFile(path, []byte("shorter"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Ensure(context.Background(), spec); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "graph bytes" {
		t.Errorf("the altered file was kept: %q", got)
	}
}

func TestSpec_Validate(t *testing.T) {
	good := modelcache.File{
		Name: "model.onnx", URL: "https://example.com/model.onnx",
		Size: 10, SHA256: digest([]byte("x")),
	}

	cases := []struct {
		name string
		spec modelcache.Spec
		want string
	}{
		{"no name", modelcache.Spec{Files: []modelcache.File{good}}, "no name"},
		{"no files", modelcache.Spec{Name: "m"}, "no files"},
		{
			// A spec can come from configuration, so a name that escapes
			// the cache directory would let one choose where the daemon
			// writes a gigabyte.
			"traversal in the name",
			modelcache.Spec{Name: "m", Files: []modelcache.File{withName(good, "../../etc/passwd")}},
			"escapes",
		},
		{"absolute name", modelcache.Spec{Name: "m", Files: []modelcache.File{withName(good, "/etc/passwd")}}, "absolute"},
		{"non-canonical name", modelcache.Spec{Name: "m", Files: []modelcache.File{withName(good, "./model.onnx")}}, "canonical"},
		{"duplicate names", modelcache.Spec{Name: "m", Files: []modelcache.File{good, good}}, "twice"},
		{"plain http", modelcache.Spec{Name: "m", Files: []modelcache.File{withURL(good, "http://example.com/m")}}, "https"},
		{"no url", modelcache.Spec{Name: "m", Files: []modelcache.File{withURL(good, "")}}, "no URL"},
		{"no size", modelcache.Spec{Name: "m", Files: []modelcache.File{withSize(good, 0)}}, "no size"},
		{"short digest", modelcache.Spec{Name: "m", Files: []modelcache.File{withDigest(good, "abc")}}, "64 hex"},
		{"non-hex digest", modelcache.Spec{Name: "m", Files: []modelcache.File{withDigest(good, strings.Repeat("z", 64))}}, "hex"},
		{"uppercase digest", modelcache.Spec{Name: "m", Files: []modelcache.File{withDigest(good, strings.ToUpper(digest([]byte("x"))))}}, "lowercase"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.spec.Validate()
			if err == nil {
				t.Fatalf("accepted a spec with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}

	if err := (modelcache.Spec{Name: "m", Files: []modelcache.File{good}}).Validate(); err != nil {
		t.Errorf("a valid spec was rejected: %v", err)
	}
}

// TestEnsure_ValidatesBeforeTouchingTheNetwork. Finding a configuration error
// after a 917MB download wastes the operator's bandwidth as well as their
// time.
func TestEnsure_ValidatesBeforeTouchingTheNetwork(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("graph")})
	c, _ := newCache(t, s)

	spec := specOf(s, "model.onnx")
	spec.Files[0].SHA256 = "not-a-digest"

	if _, err := c.Ensure(context.Background(), spec); err == nil {
		t.Fatal("an invalid spec was accepted")
	}
	if n := atomic.LoadInt32(&s.hits); n != 0 {
		t.Errorf("the server was contacted %d time(s) despite an invalid spec", n)
	}
}

// TestEnsure_ContextCancellation stops a long download.
func TestEnsure_ContextCancellation(t *testing.T) {
	s := newServer(t, map[string][]byte{"model.onnx": []byte("graph")})
	c, _ := newCache(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Ensure(ctx, specOf(s, "model.onnx")); err == nil {
		t.Fatal("a cancelled context still downloaded")
	}
}

func assertNoUsableCache(t *testing.T, c *modelcache.Cache, spec modelcache.Spec) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(c.Dir(spec), ".complete")); err == nil {
		t.Error("the cache was marked complete despite a failure")
	}
}

func withName(f modelcache.File, n string) modelcache.File   { f.Name = n; return f }
func withURL(f modelcache.File, u string) modelcache.File    { f.URL = u; return f }
func withSize(f modelcache.File, s int64) modelcache.File    { f.Size = s; return f }
func withDigest(f modelcache.File, d string) modelcache.File { f.SHA256 = d; return f }

// TestEnsure_BoundsWhatItReadsFromAnOversizedBody is what justifies the
// LimitReader, and it exists because mutation testing found nothing else did.
//
// Removing the cap still failed the over-long-body test, because the size
// check after the copy catches a wrong length either way. What it does not
// catch is a server that streams gigabytes at a spec that says kilobytes: the
// bytes are written to disk first and rejected afterwards. The cap is what
// keeps a hostile or misconfigured mirror from filling the disk before the
// error is reached.
func TestEnsure_BoundsWhatItReadsFromAnOversizedBody(t *testing.T) {
	const expected = 1024
	const flood = 8 << 20 // what the server would like to send

	var served int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length, so the pre-check cannot help; the cap is the
		// only thing standing between this and 8MB on disk.
		w.Header().Set("Transfer-Encoding", "chunked")
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < flood; sent += len(chunk) {
			n, err := w.Write(chunk)
			atomic.AddInt64(&served, int64(n))
			if err != nil {
				return // the client hung up, which is the point
			}
		}
	}))
	defer srv.Close()

	c := modelcache.New(t.TempDir(), srv.Client(), nil)
	spec := modelcache.Spec{Name: "test-model", Files: []modelcache.File{{
		Name: "model.onnx", URL: srv.URL + "/model.onnx",
		Size: expected, SHA256: digest(make([]byte, expected)),
	}}}

	if _, err := c.Ensure(context.Background(), spec); err == nil {
		t.Fatal("an unbounded body was accepted")
	}

	// Some slack for buffering between the handler and the client, but far
	// below the 8MB the server wanted to send.
	if got := atomic.LoadInt64(&served); got > 2<<20 {
		t.Errorf("the server got to send %d bytes against a %d-byte spec; the read is not bounded", got, expected)
	}
}
