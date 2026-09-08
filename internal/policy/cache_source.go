package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// cacheBundleName and cacheSigName hold the last bundle a Source returned.
const (
	cacheBundleName = "policy.yaml"
	cacheSigName    = "policy.yaml.sig"
)

// CachingSource keeps the last bundle its inner Source returned, so a daemon
// that restarts while the policy server is unreachable comes up enforcing what
// that server last published.
//
// Without it, a policy server outage plus any daemon restart is a daemon that
// will not start. With it, the fallback is not "some other local policy" but
// the exact document the server served, and it is verified by the same
// Manager.verifyBundle as a fresh fetch -- a tampered cache file fails there.
//
// The cache is only consulted before anything has been fetched in this
// process. Once a fetch has succeeded, a later failure is reported and the
// Manager keeps the policy already in memory; falling back to disk there would
// silently reinstall an older document.
type CachingSource struct {
	inner  Source
	dir    string
	logger *slog.Logger

	mu      sync.Mutex
	fetched bool
}

// NewCachingSource wraps src with an on-disk last-known-good copy in dir.
func NewCachingSource(src Source, dir string, logger *slog.Logger) *CachingSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &CachingSource{inner: src, dir: dir, logger: logger}
}

// Describe implements Source.
func (c *CachingSource) Describe() string { return c.inner.Describe() }

// Fetch implements Source.
func (c *CachingSource) Fetch(ctx context.Context) (*Bundle, error) {
	b, err := c.inner.Fetch(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()

	if err == nil {
		c.fetched = true
		if werr := c.store(b); werr != nil {
			// A cache that cannot be written costs the next restart its
			// fallback and nothing else, so the fetch still succeeds.
			c.logger.Warn("policy cache write failed", "dir", c.dir, "error", werr)
		}
		return b, nil
	}
	if errors.Is(err, ErrNotModified) {
		// The server says the agent already has it. The cache was written when
		// that document arrived, so there is nothing to do.
		c.fetched = true
		return nil, err
	}
	if c.fetched {
		return nil, err
	}
	cached, cerr := c.load()
	if cerr != nil {
		// Report the fetch failure, not the cache miss: the fetch is what the
		// operator configured and what they need to fix.
		c.logger.Warn("policy fetch failed and no cached bundle is available",
			"source", c.inner.Describe(), "cache_dir", c.dir, "cache_error", cerr)
		return nil, err
	}
	c.logger.Warn("policy fetch failed; falling back to the last bundle this server served",
		"source", c.inner.Describe(), "cache_dir", c.dir, "error", err)
	c.fetched = true
	return cached, nil
}

// store writes the bundle atomically. The signature goes first: a reader that
// finds the policy without its signature would fail verification, while one
// that finds a signature without a policy finds nothing at all.
func (c *CachingSource) store(b *Bundle) error {
	if b == nil {
		return nil
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	sigPath := filepath.Join(c.dir, cacheSigName)
	if len(b.Signature) > 0 {
		if err := atomicWriteFile(sigPath, b.Signature, 0o600); err != nil {
			return fmt.Errorf("write cached signature: %w", err)
		}
	} else if err := os.Remove(sigPath); err != nil && !os.IsNotExist(err) {
		// A stale signature from a previous bundle would be checked against
		// the new document and fail, turning an unsigned source into a
		// corrupt cache.
		return fmt.Errorf("remove stale cached signature: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(c.dir, cacheBundleName), b.Data, 0o600); err != nil {
		return fmt.Errorf("write cached policy: %w", err)
	}
	return nil
}

func (c *CachingSource) load() (*Bundle, error) {
	path := filepath.Join(c.dir, cacheBundleName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(c.dir, cacheSigName))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(sig) == 0 {
		sig = nil
	}
	// No Version: the cached copy must not satisfy a later conditional GET,
	// because the agent has not proved to the server that it holds it.
	return &Bundle{Data: data, Signature: sig, Name: "cache:" + path}, nil
}

// atomicWriteFile writes through a temporary file in the same directory, so a
// crash mid-write leaves the previous cache rather than a truncated one.
func atomicWriteFile(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
