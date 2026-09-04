package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/diffsec/agentmon/internal/policy/signing"
)

// Manager selects and loads a policy once, based on config and env.
type Manager struct {
	mu             sync.RWMutex
	selectedName   string
	dir            string
	manifestPath   string
	signingMode    string
	trustStorePath string
	src            Source
	policy         *Policy
	err            error
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// NewManager binds the policy name but defers file I/O until first Get().
// envName is the value of AGENTMON_POLICY_NAME (already read from environment).
func NewManager(dir, defaultName string, allowed []string, manifestPath, envName string) *Manager {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, n := range allowed {
		allowedSet[n] = struct{}{}
	}

	selected := defaultName
	if envName != "" && nameRe.MatchString(envName) {
		if _, ok := allowedSet[envName]; ok || len(allowedSet) == 0 && envName == defaultName {
			selected = envName
		}
	}

	return &Manager{
		selectedName: selected,
		dir:          dir,
		manifestPath: manifestPath,
	}
}

// SelectedName returns the bound policy name (without suffix).
func (m *Manager) SelectedName() string {
	if m == nil {
		return ""
	}
	return m.selectedName
}

// SetSigningConfig configures signature verification for this manager.
// mode is "enforce", "warn", or "off". trustStorePath is a directory of public key JSON files.
func (m *Manager) SetSigningConfig(mode, trustStorePath string) {
	m.signingMode = mode
	m.trustStorePath = trustStorePath
}

// Get loads and returns the active policy, caching the result.
func (m *Manager) Get() (*Policy, error) {
	m.mu.RLock()
	if m.policy != nil || m.err != nil {
		p, e := m.policy, m.err
		m.mu.RUnlock()
		return p, e
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy != nil || m.err != nil {
		return m.policy, m.err
	}
	p, err := m.loadLocked(context.Background())
	m.policy = p
	m.err = err
	return p, err
}

// Reload forces the next Get() to re-read the policy file from disk.
// Used when the policy has been replaced out-of-band (e.g. a fresh
// snapshot was pushed by the operator via WTP SessionAck). Subsequent
// Get() calls return the new policy; in-flight callers that already
// captured a *Policy are unaffected.
//
// Returns the new policy or the parse/validate error. A Reload error
// also installs itself as the cached err so subsequent Get() calls
// surface the same failure without a re-read.
func (m *Manager) Reload() (*Policy, error) {
	return m.ReloadContext(context.Background())
}

// ReloadContext is Reload with a caller context bounding the fetch. A remote
// source needs one; a file source ignores it.
//
// ErrNotModified is not a failure and does not replace the cached policy: a
// conditional GET answering 304 means the agent already has the current
// document, and installing an error there would take enforcement down on the
// first quiet poll.
func (m *Manager) ReloadContext(ctx context.Context) (*Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.loadLocked(ctx)
	if errors.Is(err, ErrNotModified) && m.policy != nil {
		return m.policy, nil
	}
	m.policy = p
	m.err = err
	return p, err
}

// source returns the Source this Manager loads from.
//
// A Manager built by NewManager reads the local policy directory. SetSource
// points it somewhere else -- a policy server -- without changing anything
// after the fetch, so a remote policy is verified, parsed and validated by
// exactly the same code as a local one.
func (m *Manager) source() Source {
	if m.src != nil {
		return m.src
	}
	return &FileSource{Dir: m.dir, Name: m.selectedName, ManifestPath: m.manifestPath}
}

// SetSource replaces where the policy is fetched from. Pass nil to go back to
// the local directory.
func (m *Manager) SetSource(src Source) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.src = src
}

// loadLocked fetches, verifies, parses and validates. Caller MUST hold m.mu in
// write mode.
//
// ErrNotModified reaches the caller unchanged: only Reload can act on it,
// because keeping the current policy is only meaningful when there is one.
func (m *Manager) loadLocked(ctx context.Context) (*Policy, error) {
	bundle, err := m.source().Fetch(ctx)
	if err != nil {
		return nil, err
	}
	if err := m.verifyBundle(bundle); err != nil {
		return nil, err
	}
	return parseAndValidate(bundle.Data)
}

// verifyBundle applies the signing mode. It runs on every source, which is the
// point of splitting fetch out: a policy served over HTTP inherits the local
// trust guarantee rather than an approximation of it.
func (m *Manager) verifyBundle(b *Bundle) error {
	if m.signingMode == "" || m.signingMode == "off" {
		return nil
	}
	if m.trustStorePath == "" {
		if m.signingMode == "enforce" {
			return fmt.Errorf("signing verification: trust_store not configured")
		}
		fmt.Fprintf(os.Stderr, "WARNING: signing mode is %q but trust_store not configured\n", m.signingMode)
		return nil
	}
	if err := m.verifySigning(b); err != nil {
		if m.signingMode == "enforce" {
			return fmt.Errorf("signing verification: %w", err)
		}
		fmt.Fprintf(os.Stderr, "WARNING: policy signing verification failed: %v\n", err)
	}
	return nil
}

func parseAndValidate(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	return &p, nil
}

func (m *Manager) verifySigning(b *Bundle) error {
	ts, err := signing.LoadTrustStore(m.trustStorePath, m.signingMode == "enforce")
	if err != nil {
		return fmt.Errorf("load trust store: %w", err)
	}
	_, err = signing.VerifyBytes(b.Data, b.Signature, ts)
	return err
}

func verifyHash(path string, data []byte, manifestPath string) error {
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	lines := bytes.Split(bytes.TrimSpace(manifest), []byte{'\n'})
	base := filepath.Base(path)
	expected := ""
	for _, ln := range lines {
		fields := bytes.Fields(ln)
		if len(fields) >= 2 && string(fields[1]) == base {
			expected = string(fields[0])
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("policy not listed in manifest: %s", base)
	}
	actual := sha256.Sum256(data)
	if expected != hex.EncodeToString(actual[:]) {
		return fmt.Errorf("policy hash mismatch: %s", base)
	}
	return nil
}
