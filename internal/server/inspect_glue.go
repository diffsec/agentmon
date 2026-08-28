package server

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/policy"
)

// wireInspection builds the inspection registry from configuration and checks
// it can actually run everything the policy asks for.
//
// It returns a nil registry when the policy needs no inspection, so a
// deployment that does not use the feature pays nothing and configures
// nothing.
//
// The gate is a hard startup failure rather than a warning. A policy with
// inspect rules and no usable inspector does not degrade -- every one of
// those rules resolves to deny, which inverts what the operator wrote. An
// `allow` rule with an inspection precondition becomes a block on the path it
// was written to permit. That is not a reduced-capability mode worth booting
// into; it is a policy nobody authored.
func wireInspection(cfg config.InspectionConfig, p *policy.Policy, engine *policy.Engine) (*inspect.Registry, error) {
	needed := p.InspectionProfilesUsed()

	if !cfg.Enabled {
		if len(needed) > 0 {
			return nil, fmt.Errorf("policy uses inspection profile(s) %s but inspection.enabled is false; "+
				"every rule naming them would deny. Enable inspection and configure a provider, or remove the inspect rules",
				strings.Join(needed, ", "))
		}
		return nil, nil
	}

	providers, err := buildInspectProviders(cfg.Providers)
	if err != nil {
		return nil, err
	}

	privacy := &inspect.PrivacyConfig{
		AllowRemote: cfg.Privacy.AllowRemote,
		RemoteKinds: cfg.Privacy.RemoteKinds,
	}
	reg := inspect.NewRegistry(providers, privacy, cfg.ProviderTimeout)

	checker, err := reg.For(p)
	if err != nil {
		return nil, fmt.Errorf("inspection: %w", err)
	}

	// Check every profile the policy actually names, not just that some
	// provider exists. A profile pointing at a provider nobody configured
	// is the failure this gate is for, and it is invisible until a rule
	// matches.
	if missing := checker.Missing(needed); len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("inspection cannot run the profiles this policy uses:\n  - %s",
			strings.Join(missing, "\n  - "))
	}

	// Carried on the engine for symmetry with SetThreatStore/SetTorPolicy
	// and so introspection can see it. The content-holding callers resolve
	// through the registry, which is correct for per-session engines too.
	engine.SetInspector(checker)

	if len(needed) == 0 {
		slog.Info("content inspection enabled", "providers", reg.Providers(), "note", "no policy rule uses it yet")
	} else {
		slog.Info("content inspection enabled", "providers", reg.Providers(), "profiles", needed)
	}
	if privacy.AllowRemote {
		slog.Warn("content inspection may send content off this machine",
			"kinds", remoteKindsLabel(privacy.RemoteKinds))
	}
	return reg, nil
}

func remoteKindsLabel(kinds []string) string {
	if len(kinds) == 0 {
		return "all"
	}
	return strings.Join(kinds, ",")
}

// buildInspectProviders constructs every enabled provider. A configured but
// disabled provider is skipped here and reported by Checker.Missing if a
// profile names it, so the operator gets "provider X is not configured"
// rather than a rule that quietly denies.
func buildInspectProviders(cfgs map[string]config.InspectProviderConfig) ([]inspect.Provider, error) {
	names := make([]string, 0, len(cfgs))
	for name := range cfgs {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic errors when more than one is broken

	var out []inspect.Provider
	for _, name := range names {
		pc := cfgs[name]
		if !pc.Enabled {
			continue
		}
		p, err := buildInspectProvider(name, pc)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// buildInspectProvider constructs one provider.
//
// An unknown type is an error, not a skip. Skipping would leave a policy
// naming that provider to fail at match time, long after the typo that caused
// it, and the reported reason would be "provider not configured" rather than
// "no such provider type".
func buildInspectProvider(name string, pc config.InspectProviderConfig) (inspect.Provider, error) {
	switch pc.Type {
	case "regex":
		p, err := provider.NewRegex(pc.Patterns)
		if err != nil {
			return nil, fmt.Errorf("inspection provider %q: %w", name, err)
		}
		if name != provider.RegexName {
			return nil, fmt.Errorf("inspection provider %q: a type: regex provider must be named %q, because that is the name a policy profile refers to",
				name, provider.RegexName)
		}
		return p, nil
	case "":
		return nil, fmt.Errorf("inspection provider %q: type is required", name)
	default:
		return nil, fmt.Errorf("inspection provider %q: unknown type %q (known types: regex)", name, pc.Type)
	}
}
