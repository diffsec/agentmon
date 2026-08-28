package inspect

import "fmt"

// PrivacyConfig gates what may leave the machine.
//
// This is the load-bearing difference between inspection and every other
// check in this codebase. pkgcheck sends package *names* to third parties;
// inspection sends the content itself, and the content is the sensitive
// material -- the request body, the file being written, the argv. Sending
// PII to a remote service to ask whether it contains PII is the failure that
// makes the feature worse than not having it.
//
// The zero value permits nothing remote. Remote egress is opt-in, per kind.
type PrivacyConfig struct {
	// AllowRemote permits providers that are not LocalProvider to see
	// content at all. False -- the zero value -- means only in-process
	// providers run.
	AllowRemote bool

	// RemoteKinds restricts which content kinds may reach a remote
	// provider, using the Kind* constants. Empty with AllowRemote set means
	// every kind may. It exists because the kinds differ enormously in
	// sensitivity: a command argv is usually a path and a flag, while a
	// proxy body is whatever the agent was about to send anywhere.
	RemoteKinds []string
}

// PrivacyGate decides whether a given provider may see a given request.
type PrivacyGate struct {
	allowRemote bool
	remoteKinds map[string]struct{}
}

// NewPrivacyGate builds a gate from configuration. A nil config gates
// everything remote, which is the safe reading of "not configured".
func NewPrivacyGate(cfg *PrivacyConfig) *PrivacyGate {
	g := &PrivacyGate{}
	if cfg == nil {
		return g
	}
	g.allowRemote = cfg.AllowRemote
	if len(cfg.RemoteKinds) > 0 {
		g.remoteKinds = make(map[string]struct{}, len(cfg.RemoteKinds))
		for _, k := range cfg.RemoteKinds {
			g.remoteKinds[k] = struct{}{}
		}
	}
	return g
}

// Allows reports whether p may inspect content of the given kind, and why not
// when it may not. The reason is for the audit log and for the operator; it
// names the kind and the provider, never the content.
func (g *PrivacyGate) Allows(p Provider, kind string) (bool, string) {
	if isLocal(p) {
		return true, ""
	}
	if !g.allowRemote {
		return false, fmt.Sprintf("provider %q is not local and remote inspection is not enabled", p.Name())
	}
	if g.remoteKinds == nil {
		return true, ""
	}
	if _, ok := g.remoteKinds[kind]; !ok {
		return false, fmt.Sprintf("provider %q is not local and content kind %q is not in the remote allowlist", p.Name(), kind)
	}
	return true, ""
}

// isLocal reports whether a Provider implements LocalProvider and says so.
func isLocal(p Provider) bool {
	lp, ok := p.(LocalProvider)
	return ok && lp.IsLocal()
}
