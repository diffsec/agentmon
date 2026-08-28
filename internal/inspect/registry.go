package inspect

import (
	"sync"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

// Registry hands out a Checker for a given policy.
//
// A Checker is per-policy, because the profiles it runs come from the
// policy's own inspection block, while the providers come from host
// configuration. Attaching one to each engine at construction would mean
// finding every place an engine is built -- there are eight outside the
// policy package, and the equivalent Tor wiring reaches only three of them
// (internal/api/session_policy.go:91 documents that gap). A registry keyed on
// the policy is immune to that: a session running a named policy file, and an
// engine swapped in by a live policy push, both get a correct Checker without
// anyone remembering to attach it.
type Registry struct {
	providers []Provider
	privacy   *PrivacyConfig
	timeout   time.Duration

	mu      sync.Mutex
	lastP   *policy.Policy
	lastC   *Checker
	lastErr error
}

// NewRegistry builds a Registry over the host's configured providers.
func NewRegistry(providers []Provider, privacy *PrivacyConfig, timeout time.Duration) *Registry {
	return &Registry{
		providers: append([]Provider(nil), providers...),
		privacy:   privacy,
		timeout:   timeout,
	}
}

// For returns the Checker for p.
//
// The result is memoised on the most recent policy only. Building a Checker
// is two small maps, so a miss is cheap, and a single-entry memo can never
// grow: keeping a map keyed on policy pointers would retain every policy ever
// swapped in for the life of the process.
func (r *Registry) For(p *policy.Policy) (*Checker, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p != nil && p == r.lastP {
		return r.lastC, r.lastErr
	}

	profiles := map[string]policy.InspectionProfile{}
	if p != nil && p.Inspection != nil {
		profiles = p.Inspection.Profiles
	}
	c, err := NewChecker(Config{
		Profiles:        profiles,
		Providers:       r.providers,
		Privacy:         r.privacy,
		ProviderTimeout: r.timeout,
	})
	r.lastP, r.lastC, r.lastErr = p, c, err
	return c, err
}

// Providers returns the configured provider names, for logging and for
// `agentmon detect`.
func (r *Registry) Providers() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.providers))
	for _, p := range r.providers {
		names = append(names, p.Name())
	}
	return names
}
