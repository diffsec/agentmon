package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider"
	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter"
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
func wireInspection(ctx context.Context, cfg config.InspectionConfig, p *policy.Policy, engine *policy.Engine) (*inspect.Registry, error) {
	needed := p.InspectionProfilesUsed()

	if !cfg.Enabled {
		if len(needed) > 0 {
			return nil, fmt.Errorf("policy uses inspection profile(s) %s but inspection.enabled is false; "+
				"every rule naming them would deny. Enable inspection and configure a provider, or remove the inspect rules",
				strings.Join(needed, ", "))
		}
		return nil, nil
	}

	providers, err := buildInspectProviders(ctx, cfg.Providers)
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
func buildInspectProviders(ctx context.Context, cfgs map[string]config.InspectProviderConfig) ([]inspect.Provider, error) {
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
		p, err := buildInspectProvider(ctx, name, pc)
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
func buildInspectProvider(ctx context.Context, name string, pc config.InspectProviderConfig) (inspect.Provider, error) {
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
	case "sidecar":
		if name != provider.SidecarName {
			return nil, fmt.Errorf("inspection provider %q: a type: sidecar provider must be named %q, because that is the name a policy profile refers to",
				name, provider.SidecarName)
		}
		baseURL := optString(pc.Options, "base_url")
		if baseURL == "" {
			return nil, fmt.Errorf("inspection provider %q: options.base_url is required for type: sidecar", name)
		}
		apiKey, err := inspectAPIKey(name, pc.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		p, err := provider.NewSidecar(provider.SidecarConfig{BaseURL: baseURL, APIKey: apiKey})
		if err != nil {
			return nil, fmt.Errorf("inspection provider %q: %w", name, err)
		}
		return p, nil
	case "shieldstral":
		if name != provider.ShieldstralName {
			return nil, fmt.Errorf("inspection provider %q: a type: shieldstral provider must be named %q, because that is the name a policy profile refers to",
				name, provider.ShieldstralName)
		}
		baseURL := optString(pc.Options, "base_url")
		if baseURL == "" {
			return nil, fmt.Errorf("inspection provider %q: options.base_url is required for type: shieldstral (the OpenAI-compatible root of a vLLM, llama-server or SGLang instance)", name)
		}
		model := optString(pc.Options, "model")
		if model == "" {
			return nil, fmt.Errorf("inspection provider %q: options.model is required for type: shieldstral; it is what the server routes on, and an empty one reaches whatever checkpoint the server defaults to", name)
		}
		apiKey, err := inspectAPIKey(name, pc.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		p, err := provider.NewShieldstral(provider.ShieldstralConfig{
			BaseURL:     baseURL,
			Model:       model,
			APIKey:      apiKey,
			Concurrency: optInt(pc.Options, "concurrency", 0),
		})
		if err != nil {
			return nil, fmt.Errorf("inspection provider %q: %w", name, err)
		}
		return p, nil
	case "privacy_filter":
		if name != privacyfilter.Name {
			return nil, fmt.Errorf("inspection provider %q: a type: privacy_filter provider must be named %q, because that is the name a policy profile refers to",
				name, privacyfilter.Name)
		}
		p, err := privacyfilter.Open(ctx, privacyfilter.Config{
			Variant:        privacyfilter.Variant(optString(pc.Options, "variant")),
			CacheDir:       optString(pc.Options, "cache_dir"),
			LibraryPath:    optString(pc.Options, "library_path"),
			IntraOpThreads: optInt(pc.Options, "intra_op_threads", 0),
			// Downloading 917MB is opt-in. A daemon that fetched it
			// silently on first start would look like a hang, and an
			// air-gapped host needs a way to say no.
			AllowDownload: optBool(pc.Options, "allow_download", false),
		})
		if err != nil {
			return nil, fmt.Errorf("inspection provider %q: %w", name, err)
		}
		return p, nil
	case "":
		return nil, fmt.Errorf("inspection provider %q: type is required", name)
	default:
		return nil, fmt.Errorf("inspection provider %q: unknown type %q (known types: regex, sidecar, shieldstral, privacy_filter)", name, pc.Type)
	}
}

// inspectAPIKey reads the provider's credential from the environment.
//
// Unlike pkgcheck's requireAPIKey, an api_key_env that is set but empty is a
// hard error here rather than a skip-with-warning. pkgcheck skipping a
// provider costs a vulnerability lookup; skipping an inspection provider
// means every rule naming it fails closed, and the operator would be looking
// at blocked requests with nothing in the startup log to explain them.
func inspectAPIKey(name, apiKeyEnv string) (string, error) {
	if apiKeyEnv == "" {
		return "", nil
	}
	val := os.Getenv(apiKeyEnv)
	if val == "" {
		return "", fmt.Errorf("inspection provider %q: api_key_env names %s, which is unset or empty", name, apiKeyEnv)
	}
	return val, nil
}

// optBool reads a bool from a provider's options map.
func optBool(opts map[string]any, key string, defaultVal bool) bool {
	if opts == nil {
		return defaultVal
	}
	if v, ok := opts[key].(bool); ok {
		return v
	}
	return defaultVal
}
