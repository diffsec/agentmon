// Package modelcache downloads and verifies model files.
//
// Privacy Filter is 917MB of weights that agentmon has to have on disk before
// it can inspect anything, and those bytes are parsed by ONNX Runtime inside
// the daemon. That makes the digest the load-bearing control: where the file
// came from stops mattering once its SHA-256 matches, which is what lets the
// same cache be filled from Hugging Face, from a release mirror, or by an
// operator copying a directory in.
//
// The cache is write-once. A populated directory is never rewritten, and a
// download that fails verification never lands in it, so a caller handing the
// path to ONNX Runtime is not racing a partial file.
package modelcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// File is one file of a model.
type File struct {
	// Name is the file's path within the cache directory. It must be a
	// plain relative name: a spec can come from configuration, and a name
	// like "../../bin/agentmon" would otherwise let one choose where the
	// daemon writes a gigabyte.
	Name string
	// URL is where to fetch it.
	URL string
	// Size is the expected length in bytes. Checked before the body is
	// read so an oversized response is refused rather than streamed to
	// disk, and again after.
	Size int64
	// SHA256 is the expected digest, lowercase hex.
	SHA256 string
}

// Spec describes a complete model.
type Spec struct {
	// Name identifies the model in logs and in the cache layout.
	Name string
	// Files are every file the model needs. All of them must verify
	// before any of them is usable.
	Files []File
}

// Validate checks the spec is well formed. It runs before any network access,
// because the failures it catches -- a traversal in a name, a missing digest
// -- are configuration errors, and finding them after a 917MB download wastes
// the operator's time and bandwidth.
func (s Spec) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("modelcache: spec has no name")
	}
	if len(s.Files) == 0 {
		return fmt.Errorf("modelcache: spec %q has no files", s.Name)
	}
	seen := map[string]struct{}{}
	for i, f := range s.Files {
		if err := checkName(f.Name); err != nil {
			return fmt.Errorf("modelcache: spec %q file %d: %w", s.Name, i, err)
		}
		if _, dup := seen[f.Name]; dup {
			return fmt.Errorf("modelcache: spec %q lists %q twice", s.Name, f.Name)
		}
		seen[f.Name] = struct{}{}

		if f.URL == "" {
			return fmt.Errorf("modelcache: spec %q file %q has no URL", s.Name, f.Name)
		}
		if !strings.HasPrefix(f.URL, "https://") {
			// Plain HTTP would let anyone on the path substitute the bytes.
			// The digest would catch it, but failing on the scheme says why.
			return fmt.Errorf("modelcache: spec %q file %q: URL must be https", s.Name, f.Name)
		}
		if f.Size <= 0 {
			return fmt.Errorf("modelcache: spec %q file %q has no size", s.Name, f.Name)
		}
		if err := checkDigest(f.SHA256); err != nil {
			return fmt.Errorf("modelcache: spec %q file %q: %w", s.Name, f.Name, err)
		}
	}
	return nil
}

// checkName rejects anything that is not a plain relative path.
func checkName(name string) error {
	if name == "" {
		return errors.New("empty name")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return fmt.Errorf("name %q is absolute", name)
	}
	clean := filepath.Clean(name)
	if clean != name {
		return fmt.Errorf("name %q is not in canonical form (want %q)", name, clean)
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("name %q escapes the cache directory", name)
	}
	return nil
}

func checkDigest(d string) error {
	if len(d) != 64 {
		return fmt.Errorf("sha256 %q is not 64 hex characters", d)
	}
	if _, err := hex.DecodeString(d); err != nil {
		return fmt.Errorf("sha256 %q is not hex: %w", d, err)
	}
	if strings.ToLower(d) != d {
		return fmt.Errorf("sha256 %q must be lowercase", d)
	}
	return nil
}

// Cache stores model files under a root directory.
type Cache struct {
	root   string
	client *http.Client
	logger *slog.Logger
}

// New returns a Cache rooted at dir.
func New(dir string, client *http.Client, logger *slog.Logger) *Cache {
	if client == nil {
		// No overall timeout: a 917MB download over a slow link legitimately
		// takes a long while, and a blanket timeout would fail it partway
		// every time. Progress is bounded by the caller's context instead.
		client = &http.Client{Timeout: 0}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Cache{root: dir, client: client, logger: logger}
}

// Dir returns the directory a spec's files live in, whether or not it is
// populated.
func (c *Cache) Dir(s Spec) string { return filepath.Join(c.root, s.Name) }

// completeMarker is written last, after every file has verified.
//
// Its presence is what distinguishes a usable cache from a directory that
// happens to contain some files -- an interrupted download leaves the latter,
// and without the marker the next run would load a truncated model rather than
// finish the job.
const completeMarker = ".complete"

// Ensure makes the model available and returns its directory.
//
// A populated cache is returned without touching the network. Otherwise every
// file is downloaded, verified, and only then moved into place.
func (c *Cache) Ensure(ctx context.Context, s Spec) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	dir := c.Dir(s)

	if ok, err := c.complete(s); err != nil {
		return "", err
	} else if ok {
		return dir, nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("modelcache: creating %s: %w", dir, err)
	}

	total := int64(0)
	for _, f := range s.Files {
		total += f.Size
	}
	c.logger.Info("downloading inspection model",
		"model", s.Name, "files", len(s.Files), "bytes", total, "dir", dir)
	start := time.Now()

	for _, f := range s.Files {
		if err := c.fetch(ctx, dir, f); err != nil {
			return "", err
		}
	}

	// The marker goes in last. Every file above is already verified and in
	// place, so a crash before this point costs a re-download rather than
	// producing a cache that loads a file nobody checked.
	if err := os.WriteFile(filepath.Join(dir, completeMarker), []byte(s.Name+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("modelcache: marking %s complete: %w", dir, err)
	}
	c.logger.Info("inspection model ready", "model", s.Name, "took", time.Since(start).Round(time.Second))
	return dir, nil
}

// complete reports whether the cache already holds a verified copy.
//
// It checks the marker and every file's size, but not their digests. Re-hashing
// 917MB on every daemon start would cost seconds for a file the daemon itself
// wrote and has not touched since; the digest is the control on what gets
// written, not a defence against someone with write access to the cache, who
// could rewrite the marker too.
func (c *Cache) complete(s Spec) (bool, error) {
	dir := c.Dir(s)
	if _, err := os.Stat(filepath.Join(dir, completeMarker)); err != nil {
		return false, nil
	}
	for _, f := range s.Files {
		info, err := os.Stat(filepath.Join(dir, f.Name))
		if err != nil {
			c.logger.Warn("cached model is missing a file; re-downloading",
				"model", s.Name, "file", f.Name)
			return false, nil
		}
		if info.Size() != f.Size {
			c.logger.Warn("cached model file has the wrong size; re-downloading",
				"model", s.Name, "file", f.Name, "got", info.Size(), "want", f.Size)
			return false, nil
		}
	}
	return true, nil
}

// fetch downloads one file, verifies it, and moves it into place.
func (c *Cache) fetch(ctx context.Context, dir string, f File) error {
	dest := filepath.Join(dir, f.Name)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("modelcache: creating %s: %w", filepath.Dir(dest), err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return fmt.Errorf("modelcache: %s: %w", f.Name, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("modelcache: fetching %s: %w", f.Name, err)
	}
	// The body is closed but NOT drained. Draining exists to let a
	// connection be reused, and it is the wrong trade here: a server that
	// sends far more than the spec allows would have the whole excess read
	// and thrown away, which is the resource exhaustion the size cap below
	// exists to prevent. Dropping the connection instead costs one
	// handshake on a path that is already failing.
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("modelcache: fetching %s: HTTP %d", f.Name, resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != f.Size {
		// Fail before writing anything. The digest would catch a wrong file
		// eventually, but not before a lying server had filled the disk.
		return fmt.Errorf("modelcache: %s: server offered %d bytes, spec says %d", f.Name, resp.ContentLength, f.Size)
	}

	tmp, err := os.CreateTemp(dir, ".partial-*")
	if err != nil {
		return fmt.Errorf("modelcache: %s: %w", f.Name, err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName) // no-op once the rename has happened
	}()

	// LimitReader caps the write at exactly the expected length, so a
	// response with no Content-Length, or one that lies, cannot fill the
	// disk. Reading one byte past it is how an over-long body is detected.
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, f.Size+1))
	if err != nil {
		return fmt.Errorf("modelcache: downloading %s: %w", f.Name, err)
	}
	if written != f.Size {
		return fmt.Errorf("modelcache: %s: got %d bytes, spec says %d", f.Name, written, f.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 {
		return fmt.Errorf("modelcache: %s: sha256 %s does not match the expected %s", f.Name, got, f.SHA256)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("modelcache: %s: %w", f.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("modelcache: %s: %w", f.Name, err)
	}

	// Rename only after the digest matches, so the destination path never
	// holds bytes that failed verification -- not even briefly, and not if
	// the process dies here.
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("modelcache: installing %s: %w", f.Name, err)
	}
	return nil
}
