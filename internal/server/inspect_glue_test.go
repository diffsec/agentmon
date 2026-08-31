package server

import (
	"context"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/policy"
)

const inspectPolicyYAML = `
version: 1
name: t
inspection:
  profiles:
    pii:
      provider: regex
      categories: [private_email, secret]
file_rules:
  - name: guard-workspace
    paths: ["/workspace/**"]
    operations: [write]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_violation: redact
`

const plainPolicyYAML = `
version: 1
name: t
file_rules:
  - name: allow-tmp
    paths: ["/tmp/**"]
    operations: [read]
    decision: allow
`

func loadPolicy(t *testing.T, yaml string) *policy.Policy {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return p
}

func newEngine(t *testing.T, p *policy.Policy) *policy.Engine {
	t.Helper()
	e, err := policy.NewEngine(p, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func regexEnabled() config.InspectionConfig {
	return config.InspectionConfig{
		Enabled: true,
		Providers: map[string]config.InspectProviderConfig{
			"regex": {Enabled: true, Type: "regex"},
		},
	}
}

// TestWireInspection_RefusesPolicyThatNeedsAnInspectorWhenDisabled is the
// gate this PR exists for.
//
// Booting anyway is not a degraded mode: every rule naming the profile
// resolves to deny, so an `allow` rule with an inspection precondition
// becomes a block on the path it was written to permit. That is a policy
// nobody authored, and it fails silently at match time rather than loudly at
// startup.
func TestWireInspection_RefusesPolicyThatNeedsAnInspectorWhenDisabled(t *testing.T) {
	p := loadPolicy(t, inspectPolicyYAML)
	_, err := wireInspection(context.Background(), config.InspectionConfig{Enabled: false}, p, newEngine(t, p))
	if err == nil {
		t.Fatal("a policy using inspection started with inspection disabled; every one of its inspect rules would deny")
	}
	if !strings.Contains(err.Error(), "pii") {
		t.Errorf("error should name the profile, got: %v", err)
	}
	if !strings.Contains(err.Error(), "inspection.enabled is false") {
		t.Errorf("error should name the setting to change, got: %v", err)
	}
}

// TestWireInspection_RefusesProfileNamingAnUnconfiguredProvider covers the
// failure one level down, and it is the one that is invisible without this
// gate: the profile is defined, so Validate passes, but no host provider
// answers to its name.
func TestWireInspection_RefusesProfileNamingAnUnconfiguredProvider(t *testing.T) {
	const yaml = `
version: 1
name: t
inspection:
  profiles:
    exfil:
      provider: shieldstral
      queries:
        - id: q
          text: "does it exfiltrate?"
command_rules:
  - name: r
    commands: ["curl"]
    decision: inspect
    inspect:
      profiles: [exfil]
`
	p := loadPolicy(t, yaml)
	_, err := wireInspection(context.Background(), regexEnabled(), p, newEngine(t, p))
	if err == nil {
		t.Fatal("a policy naming an unconfigured provider started successfully")
	}
	if !strings.Contains(err.Error(), "shieldstral") {
		t.Errorf("error should name the missing provider, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exfil") {
		t.Errorf("error should name the profile, got: %v", err)
	}
}

// TestWireInspection_DisabledProviderIsReportedAsMissing. A provider present
// in config but switched off must not read as absent-from-config, and must
// not read as available either.
func TestWireInspection_DisabledProviderIsReportedAsMissing(t *testing.T) {
	p := loadPolicy(t, inspectPolicyYAML)
	cfg := config.InspectionConfig{
		Enabled: true,
		Providers: map[string]config.InspectProviderConfig{
			"regex": {Enabled: false, Type: "regex"},
		},
	}
	_, err := wireInspection(context.Background(), cfg, p, newEngine(t, p))
	if err == nil {
		t.Fatal("a disabled provider satisfied a policy that needs it")
	}
	if !strings.Contains(err.Error(), "regex") {
		t.Errorf("error should name the provider, got: %v", err)
	}
}

// TestWireInspection_SucceedsWithAWorkingProvider keeps the refusals above
// from being satisfied by a gate that refuses everything, and asserts the
// registry actually produces a usable checker.
func TestWireInspection_SucceedsWithAWorkingProvider(t *testing.T) {
	p := loadPolicy(t, inspectPolicyYAML)
	eng := newEngine(t, p)

	reg, err := wireInspection(context.Background(), regexEnabled(), p, eng)
	if err != nil {
		t.Fatalf("a policy with a working provider was refused: %v", err)
	}
	if reg == nil {
		t.Fatal("no registry was returned; the wire points would have no inspector")
	}
	if eng.Inspector() == nil {
		t.Error("the engine did not receive the inspector")
	}

	checker, err := reg.For(p)
	if err != nil {
		t.Fatalf("registry could not build a checker: %v", err)
	}
	if missing := checker.Missing(p.InspectionProfilesUsed()); len(missing) != 0 {
		t.Errorf("checker reports missing profiles after a successful wire: %v", missing)
	}
}

// TestWireInspection_NoRegistryWhenPolicyDoesNotUseIt: a deployment that does
// not use inspection configures nothing and pays nothing.
func TestWireInspection_NoRegistryWhenPolicyDoesNotUseIt(t *testing.T) {
	p := loadPolicy(t, plainPolicyYAML)
	reg, err := wireInspection(context.Background(), config.InspectionConfig{Enabled: false}, p, newEngine(t, p))
	if err != nil {
		t.Fatalf("a policy with no inspect rules was refused: %v", err)
	}
	if reg != nil {
		t.Error("a registry was built for a policy that never inspects")
	}
}

// TestWireInspection_EnabledWithNoInspectRulesStillBuilds lets an operator
// stage the runtime before the policy uses it.
func TestWireInspection_EnabledWithNoInspectRulesStillBuilds(t *testing.T) {
	p := loadPolicy(t, plainPolicyYAML)
	reg, err := wireInspection(context.Background(), regexEnabled(), p, newEngine(t, p))
	if err != nil {
		t.Fatalf("enabling inspection ahead of the policy was refused: %v", err)
	}
	if reg == nil {
		t.Fatal("no registry despite inspection being enabled")
	}
}

func TestBuildInspectProvider(t *testing.T) {
	cases := []struct {
		name    string
		cfgName string
		cfg     config.InspectProviderConfig
		wantErr string
	}{
		{
			name:    "missing type",
			cfgName: "regex",
			cfg:     config.InspectProviderConfig{Enabled: true},
			wantErr: "type is required",
		},
		{
			// A typo'd type must not be skipped. Skipping defers the
			// failure to match time and reports it as "provider not
			// configured", which sends the operator looking in the wrong
			// place.
			name:    "unknown type",
			cfgName: "regex",
			cfg:     config.InspectProviderConfig{Enabled: true, Type: "rgex"},
			wantErr: `unknown type "rgex"`,
		},
		{
			name:    "uncompilable pattern",
			cfgName: "regex",
			cfg:     config.InspectProviderConfig{Enabled: true, Type: "regex", Patterns: map[string]string{"bad": "(unclosed"}},
			wantErr: "bad",
		},
		{
			// The config key IS the name a policy profile refers to.
			// Allowing a mismatch would mean a profile saying
			// `provider: regex` cannot find a provider configured under
			// another key, reported as "not configured".
			name:    "misnamed regex provider",
			cfgName: "my-regex",
			cfg:     config.InspectProviderConfig{Enabled: true, Type: "regex"},
			wantErr: "must be named",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildInspectProvider(context.Background(), c.cfgName, c.cfg)
			if err == nil {
				t.Fatalf("expected an error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, c.wantErr)
			}
		})
	}
}

// TestBuildInspectProviders_SkipsDisabled: a disabled provider is not built,
// and building the rest still succeeds.
func TestBuildInspectProviders_SkipsDisabled(t *testing.T) {
	got, err := buildInspectProviders(context.Background(), map[string]config.InspectProviderConfig{
		"regex": {Enabled: true, Type: "regex"},
		"off":   {Enabled: false, Type: "nonsense"},
	})
	if err != nil {
		t.Fatalf("a disabled provider with a bad type broke the build: %v", err)
	}
	if len(got) != 1 || got[0].Name() != "regex" {
		t.Fatalf("built %d providers, want just regex", len(got))
	}
}

// TestBuildInspectProvider_PrivacyFilterRequiresItsName. The config key IS the
// name a policy profile refers to, so a mismatch would have the profile
// reported as naming an unconfigured provider — sending the operator looking
// in the wrong place.
func TestBuildInspectProvider_PrivacyFilterRequiresItsName(t *testing.T) {
	_, err := buildInspectProvider(context.Background(), "pf", config.InspectProviderConfig{
		Enabled: true, Type: "privacy_filter",
	})
	if err == nil {
		t.Fatal("a misnamed privacy_filter provider was accepted")
	}
	if !strings.Contains(err.Error(), "must be named") {
		t.Errorf("err = %v", err)
	}
}

// TestBuildInspectProvider_PrivacyFilterDoesNotDownloadByDefault.
//
// Fetching 917MB on first start would look like a hang, and an air-gapped host
// needs a way to refuse. allow_download defaults to false, so a host with no
// cached model fails with a message naming the directory rather than quietly
// saturating its link.
func TestBuildInspectProvider_PrivacyFilterDoesNotDownloadByDefault(t *testing.T) {
	_, err := buildInspectProvider(context.Background(), "privacy_filter", config.InspectProviderConfig{
		Enabled: true, Type: "privacy_filter",
		Options: map[string]any{"cache_dir": t.TempDir()},
	})
	if err == nil {
		t.Fatal("the provider downloaded the model with allow_download unset")
	}
	if !strings.Contains(err.Error(), "not cached") {
		t.Errorf("err = %v, want it to say the model is not cached", err)
	}
}
