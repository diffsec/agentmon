package inspect_test

import (
	"context"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
)

type remoteProvider struct{ name string }

func (r remoteProvider) Name() string       { return r.name }
func (remoteProvider) Categories() []string { return []string{"secret"} }
func (remoteProvider) Inspect(context.Context, inspect.Request) (*inspect.Response, error) {
	return &inspect.Response{}, nil
}

// TestPrivacyGate_ZeroValuePermitsNothingRemote is the default that matters.
//
// Inspection differs from every other check here: pkgcheck sends package
// names to third parties, inspection sends the content itself. Sending PII to
// a remote service to ask whether it contains PII is the failure that makes
// the feature worse than not having it, so remote egress is opt-in.
func TestPrivacyGate_ZeroValuePermitsNothingRemote(t *testing.T) {
	for _, cfg := range []*inspect.PrivacyConfig{nil, {}} {
		g := inspect.NewPrivacyGate(cfg)
		allowed, why := g.Allows(remoteProvider{name: "shieldstral"}, inspect.KindProxyBody)
		if allowed {
			t.Fatalf("cfg %+v allowed content to reach a remote provider by default", cfg)
		}
		if !strings.Contains(why, "shieldstral") {
			t.Errorf("reason should name the provider, got %q", why)
		}
	}
}

// TestPrivacyGate_LocalProvidersAlwaysAllowed: an in-process provider makes
// no network calls, so there is nothing to gate.
func TestPrivacyGate_LocalProvidersAlwaysAllowed(t *testing.T) {
	g := inspect.NewPrivacyGate(nil)
	if allowed, why := g.Allows(&stubProvider{name: "regex", local: true}, inspect.KindProxyBody); !allowed {
		t.Fatalf("a local provider was gated: %s", why)
	}
}

// TestPrivacyGate_RemoteKindsRestrictsByKind. The kinds differ enormously in
// sensitivity: a command argv is usually a path and a flag, a proxy body is
// whatever the agent was about to send anywhere.
func TestPrivacyGate_RemoteKindsRestrictsByKind(t *testing.T) {
	g := inspect.NewPrivacyGate(&inspect.PrivacyConfig{
		AllowRemote: true,
		RemoteKinds: []string{inspect.KindCommand},
	})
	p := remoteProvider{name: "remote"}

	if allowed, why := g.Allows(p, inspect.KindCommand); !allowed {
		t.Errorf("an allowlisted kind was refused: %s", why)
	}
	allowed, why := g.Allows(p, inspect.KindProxyBody)
	if allowed {
		t.Fatal("a kind outside the allowlist reached a remote provider")
	}
	if !strings.Contains(why, inspect.KindProxyBody) {
		t.Errorf("reason should name the kind, got %q", why)
	}
}

// TestPrivacyGate_AllowRemoteWithNoKindsPermitsAll keeps the check above from
// being satisfied by a gate that refuses everything.
func TestPrivacyGate_AllowRemoteWithNoKindsPermitsAll(t *testing.T) {
	g := inspect.NewPrivacyGate(&inspect.PrivacyConfig{AllowRemote: true})
	for _, kind := range []string{inspect.KindFile, inspect.KindCommand, inspect.KindProxyBody, inspect.KindMCPArgs} {
		if allowed, why := g.Allows(remoteProvider{name: "r"}, kind); !allowed {
			t.Errorf("kind %q was refused with no allowlist configured: %s", kind, why)
		}
	}
}
