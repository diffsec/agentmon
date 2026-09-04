package policyserve

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/policy/signing"
)

// StoreConfig configures a DirStore.
type StoreConfig struct {
	// PolicyDir holds the signed bundles: name.yaml plus name.yaml.sig.
	PolicyDir string
	// BindingsPath is the bindings document. Empty serves every agent the
	// single policy named by DefaultPolicy.
	BindingsPath string
	// DefaultPolicy is the file name used when BindingsPath is empty.
	DefaultPolicy string
	// TrustStorePath verifies bundles at load. Required unless AllowUnsigned.
	TrustStorePath string
	// AllowUnsigned serves bundles without checking a signature. It exists for
	// a local development loop and logs on every load.
	AllowUnsigned bool
}

// DirStore serves bundles from a directory, reloading when it changes.
//
// Every bundle is verified against the trust store as it is loaded, and one
// that fails is not served. The agent verifies again -- that check is the
// authoritative one and this one cannot replace it -- but a bad bundle caught
// here is a startup error on one host instead of a fleet that fails closed
// against a document nobody can install.
type DirStore struct {
	cfg StoreConfig

	mu       sync.RWMutex
	bundles  map[string]*policy.Bundle
	bindings []compiledBinding
	changed  chan struct{}
	loadErr  error
}

// NewDirStore builds the store and performs the first load.
func NewDirStore(cfg StoreConfig) (*DirStore, error) {
	if strings.TrimSpace(cfg.PolicyDir) == "" {
		return nil, fmt.Errorf("policy directory is required")
	}
	if cfg.BindingsPath == "" && strings.TrimSpace(cfg.DefaultPolicy) == "" {
		return nil, fmt.Errorf("either a bindings file or a default policy is required")
	}
	if !cfg.AllowUnsigned && strings.TrimSpace(cfg.TrustStorePath) == "" {
		// Serving unverified bundles is a choice, not a default: without this
		// the server would happily distribute whatever landed in the
		// directory, and the only thing that noticed would be every agent.
		return nil, fmt.Errorf("trust store is required; pass allow-unsigned to serve without verification")
	}
	s := &DirStore{cfg: cfg, changed: make(chan struct{})}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Changed returns a channel closed on the next successful reload. Callers
// re-read it after each close, since the store replaces it.
func (s *DirStore) Changed() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.changed
}

// Reload re-reads the bindings and every bundle, then swaps them in.
//
// The swap is all-or-nothing. A partial reload would serve a new binding
// pointing at a policy the same reload failed to read, which reads to an agent
// as the policy being withdrawn.
func (s *DirStore) Reload() error {
	bindings, err := s.loadBindings()
	if err != nil {
		s.recordErr(err)
		return err
	}
	bundles, err := s.loadBundles(bindings)
	if err != nil {
		s.recordErr(err)
		return err
	}

	s.mu.Lock()
	s.bundles = bundles
	s.bindings = bindings
	s.loadErr = nil
	old := s.changed
	s.changed = make(chan struct{})
	s.mu.Unlock()
	close(old)
	return nil
}

func (s *DirStore) recordErr(err error) {
	s.mu.Lock()
	s.loadErr = err
	s.mu.Unlock()
}

// LoadErr returns the last reload failure, or nil. A failed reload leaves the
// previously loaded bundles in place, matching the agent's own behaviour: the
// last known good policy stays in force.
func (s *DirStore) LoadErr() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

func (s *DirStore) loadBindings() ([]compiledBinding, error) {
	if s.cfg.BindingsPath == "" {
		return compileBindings(&BindingFile{Bindings: []Binding{{Name: "default", Policy: s.cfg.DefaultPolicy}}})
	}
	data, err := os.ReadFile(s.cfg.BindingsPath)
	if err != nil {
		return nil, fmt.Errorf("read bindings: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var bf BindingFile
	if err := dec.Decode(&bf); err != nil {
		return nil, fmt.Errorf("parse bindings %s: %w", s.cfg.BindingsPath, err)
	}
	return compileBindings(&bf)
}

// loadBundles reads exactly the policies the bindings name. Reading the whole
// directory instead would serve a file no binding selects, which is how a
// half-finished policy left next to the live one gets handed to an agent.
func (s *DirStore) loadBundles(bindings []compiledBinding) (map[string]*policy.Bundle, error) {
	var ts *signing.TrustStore
	if !s.cfg.AllowUnsigned {
		var err error
		ts, err = signing.LoadTrustStore(s.cfg.TrustStorePath, true)
		if err != nil {
			return nil, fmt.Errorf("load trust store: %w", err)
		}
	}

	out := make(map[string]*policy.Bundle, len(bindings))
	for _, b := range bindings {
		if _, done := out[b.policy]; done {
			continue
		}
		bundle, err := s.loadBundle(b.policy, ts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.name, err)
		}
		out[b.policy] = bundle
	}
	return out, nil
}

func (s *DirStore) loadBundle(name string, ts *signing.TrustStore) (*policy.Bundle, error) {
	path := filepath.Join(s.cfg.PolicyDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	if ts != nil {
		res, verr := signing.VerifyBytes(data, sig, ts)
		if verr != nil {
			return nil, fmt.Errorf("verify %s: %w", name, verr)
		}
		slog.Info("policy serve: bundle verified", "policy", name, "key_id", res.KeyID, "signer", res.Signer)
	} else {
		slog.Warn("policy serve: serving an unverified bundle", "policy", name)
		if len(sig) == 0 {
			sig = nil
		}
	}
	// Parse and validate before serving. A document this build cannot parse is
	// one no agent of this build can install, and finding that out here costs
	// one error message rather than a fleet-wide fail-closed.
	if _, err := policy.ParseAndValidate(data); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &policy.Bundle{
		Data:      data,
		Signature: compactSignature(sig),
		Name:      name,
		Version:   etagFor(data),
	}, nil
}

// compactSignature strips whitespace from the detached signature JSON.
//
// It travels in an HTTP header, and a header value cannot contain a newline:
// Go rewrites one to a space on the way out, which happens to leave valid JSON
// but only by luck of JSON ignoring whitespace. Compacting first means the
// bytes an agent receives are the bytes chosen here. The signature covers the
// policy document, never the .sig file, so reformatting it verifies the same.
func compactSignature(sig []byte) []byte {
	if len(sig) == 0 {
		return nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, sig); err != nil {
		// Unparseable JSON never verified anyway; pass it through so the
		// agent reports the parse failure rather than a missing signature.
		return sig
	}
	return buf.Bytes()
}

// etagFor derives the change token from the document itself rather than from a
// counter or a mtime, so two servers behind a load balancer answer the same
// If-None-Match identically and a restart does not invalidate every agent's
// cached copy.
func etagFor(data []byte) string {
	sum := sha256.Sum256(data)
	return `"sha256:` + hex.EncodeToString(sum[:]) + `"`
}

// Lookup returns the bundle bound to sel. First matching binding wins, so
// bindings are ordered most specific first.
func (s *DirStore) Lookup(sel Selector) (*policy.Bundle, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.bindings {
		if !b.matches(sel) {
			continue
		}
		if bundle, ok := s.bundles[b.policy]; ok {
			return bundle, b.name, true
		}
	}
	return nil, "", false
}

// Stats reports what is loaded, for the health endpoint.
func (s *DirStore) Stats() (policies, bindings int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bundles), len(s.bindings)
}

// Validate implements hotreload.PolicyLoader.
//
// The watcher calls it before promoting a file out of .staging/, which is the
// delivery path: drop the .sig, then the .yaml, and the bundle is only
// published once both are present and agree. A file that fails here stays in
// staging and is never served.
func (s *DirStore) Validate(path string) error {
	if s.isBindings(path) {
		_, err := s.loadBindings()
		return err
	}
	var ts *signing.TrustStore
	if !s.cfg.AllowUnsigned {
		var err error
		ts, err = signing.LoadTrustStore(s.cfg.TrustStorePath, true)
		if err != nil {
			return fmt.Errorf("load trust store: %w", err)
		}
	}
	// loadBundle resolves within PolicyDir, and the watcher hands back a path
	// that may be in .staging/. Verify the file the watcher named.
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read signature: %w", err)
	}
	if ts != nil {
		if _, err := signing.VerifyBytes(data, sig, ts); err != nil {
			return fmt.Errorf("verify %s: %w", filepath.Base(path), err)
		}
	}
	_, err = policy.ParseAndValidate(data)
	return err
}

// LoadFromPath implements hotreload.PolicyLoader. One file changed, so the
// whole set is re-read: the bundles a binding names can change without that
// file changing, and a set assembled from two different reads is exactly the
// inconsistency Reload's all-or-nothing swap exists to prevent.
func (s *DirStore) LoadFromPath(string) error { return s.Reload() }

func (s *DirStore) isBindings(path string) bool {
	if s.cfg.BindingsPath == "" {
		return false
	}
	a, err1 := filepath.Abs(path)
	b, err2 := filepath.Abs(s.cfg.BindingsPath)
	if err1 != nil || err2 != nil {
		return path == s.cfg.BindingsPath
	}
	return a == b
}
