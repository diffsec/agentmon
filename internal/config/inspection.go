package config

import "time"

// InspectionConfig configures the content inspection runtime: which providers
// exist, what may leave the machine, and how long a provider gets.
//
// It is NOT where inspection profiles are defined. Profiles live in the
// policy's own `inspection.profiles` block, because they are policy — which
// categories to look for, which questions to ask, what to do about a finding.
// This block is deployment: which inspector binaries or endpoints this host
// can actually reach. The same policy therefore runs on a host with a local
// regex provider and on one with a model-backed provider, without editing.
type InspectionConfig struct {
	// Enabled turns the inspection runtime on. A policy containing inspect
	// rules will not load while this is false: every one of those rules
	// would deny, inverting what the operator wrote.
	Enabled bool `yaml:"enabled"`

	// Providers are the available inspectors, keyed by the name a policy
	// profile refers to in its `provider:` field.
	Providers map[string]InspectProviderConfig `yaml:"providers,omitempty"`

	// Privacy gates what content may reach a provider that is not local.
	Privacy InspectPrivacyConfig `yaml:"privacy"`

	// MaxBodyBytes caps how much of a request body is buffered for
	// inspection. Zero uses the proxy package default (8 MiB).
	//
	// Exceeding it is a failed inspection, not a skip, so the rule's
	// on_failure decides -- a deny by default. Set it above the largest
	// payload the agent legitimately sends, or the block will look like a
	// policy that is working rather than a limit that was too low.
	MaxBodyBytes int64 `yaml:"max_body_bytes,omitempty"`

	// ProviderTimeout bounds a single provider call. Zero uses the
	// package default. A rule's own `inspect.timeout` bounds the whole
	// inspection across every profile, and is the tighter of the two in
	// practice.
	ProviderTimeout time.Duration `yaml:"provider_timeout,omitempty"`
}

// InspectProviderConfig configures one inspection provider.
type InspectProviderConfig struct {
	// Enabled must be true for the provider to be built. A disabled
	// provider is not a missing one: a policy profile naming it still
	// fails at startup, with the reason that it is disabled.
	Enabled bool `yaml:"enabled"`

	// Type selects the implementation. "regex" is the only built-in
	// today; it runs in-process and needs no credentials.
	Type string `yaml:"type"`

	// Patterns adds or overrides regex categories, for type: regex. The
	// key is the category name a profile lists under `categories:`.
	Patterns map[string]string `yaml:"patterns,omitempty"`

	// APIKeyEnv names the environment variable holding this provider's
	// credential, for provider types that need one.
	APIKeyEnv string `yaml:"api_key_env,omitempty"`

	// Options carries provider-specific settings.
	Options map[string]any `yaml:"options,omitempty"`
}

// InspectPrivacyConfig gates what content may leave the machine.
//
// The zero value permits nothing remote. This differs from most config in
// this file, where the zero value is a disabled feature rather than a closed
// door, and it differs deliberately: inspection sends the content itself, not
// a name or a hash, so an unconfigured remote provider that silently received
// request bodies would be the worst possible default.
type InspectPrivacyConfig struct {
	// AllowRemote permits providers that do not run in-process to see
	// content at all.
	AllowRemote bool `yaml:"allow_remote"`

	// RemoteKinds restricts which content kinds may reach a remote
	// provider: file, command, network, proxy_body, mcp_args. Empty with
	// AllowRemote set means every kind may.
	RemoteKinds []string `yaml:"remote_kinds,omitempty"`
}
