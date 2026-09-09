package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/pkg/types"
)

// configsDir is the repo's shipped policy tree, relative to this package.
const configsDir = "../../configs"

// TestShippedPolicies_BuildAnEngine loads every policy shipped in configs/ and
// builds an engine from it.
//
// Parsing is not enough. args_patterns are compiled by regexp.Compile inside
// NewEngine, so a pattern written as a glob parses cleanly and then fails at
// engine build -- which is startup, on the operator's machine.
// configs/default-policy.yaml shipped with args_patterns: ["*-rf*"] and had
// never been loaded by anything in this tree.
func TestShippedPolicies_BuildAnEngine(t *testing.T) {
	for _, path := range shippedPolicyFiles(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			p, err := policy.LoadFromFile(path)
			if err != nil {
				t.Fatalf("%s does not load: %v", path, err)
			}
			if _, err := policy.NewEngine(p, false, true); err != nil {
				t.Fatalf("%s does not build an engine: %v", path, err)
			}
		})
	}
}

// shippedPolicyFiles returns every YAML under configs/ that is a policy
// document. configs/ also holds api_keys.yaml and server-config.yaml, which
// are not policies; they are identified by the absence of any rule block
// rather than by a filename list, so a new policy is picked up automatically.
func shippedPolicyFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(configsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if !strings.Contains(string(data), "_rules:") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Skipf("configs/ not readable: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no shipped policies found; the walk is looking in the wrong place")
	}
	return out
}

// TestDefaultPolicy_DangerousRmPatterns pins what the rewritten regexes match.
// The originals were globs, so three of the four compiled to something other
// than what they read as and the fourth did not compile at all.
func TestDefaultPolicy_DangerousRmPatterns(t *testing.T) {
	eng := engineFor(t, filepath.Join(configsDir, "default-policy.yaml"))

	deny := [][]string{
		{"-rf", "/tmp/x"},
		{"-fr", "/tmp/x"},
		{"-Rf", "/tmp/x"},
		{"-fR", "/tmp/x"},
		{"-rfv", "/tmp/x"},
		{"--force", "--recursive", "/tmp/x"},
		{"--recursive", "--force", "/tmp/x"},
		{"-v", "-rf", "/tmp/x"},
	}
	for _, args := range deny {
		dec := eng.CheckCommand("rm", args)
		// Assert the rule, not the decision. This policy ends in
		// default-deny-commands, so every rm denies whatever the patterns
		// match, and checking only the decision passes with the rule gone.
		if dec.Rule != "block-dangerous-rm" {
			t.Errorf("rm %v: rule = %q, want block-dangerous-rm", args, dec.Rule)
		}
		if dec.EffectiveDecision != types.DecisionDeny {
			t.Errorf("rm %v: decision = %s, want deny", args, dec.EffectiveDecision)
		}
	}

	// Filenames that contain the same letters as the flags. The patterns are
	// anchored on a flag token, so an over-broad regex like `r[a-z]*f` shows
	// up here rather than in production as "rm relief.txt is denied".
	allow := [][]string{
		{"/tmp/x"},
		{"-i", "/tmp/x"},
		{"--force", "/tmp/x"},
		{"--recursive", "/tmp/x"},
		{"relief.txt"},
		{"draft-final.md"},
		{"-i", "roof.conf"},
	}
	for _, args := range allow {
		dec := eng.CheckCommand("rm", args)
		if dec.EffectiveDecision == types.DecisionDeny && dec.Rule == "block-dangerous-rm" {
			t.Errorf("rm %v: matched block-dangerous-rm, but neither -rf nor both long flags are present", args)
		}
	}
}

// TestDefaultPolicy_PackageInstallPatterns is the same check for the rule that
// compiled but meant the wrong thing: "install*" is the regex "instal" plus
// zero or more "l", so it matched "instal" and any word containing it.
func TestDefaultPolicy_PackageInstallPatterns(t *testing.T) {
	eng := engineFor(t, filepath.Join(configsDir, "default-policy.yaml"))

	for _, args := range [][]string{
		{"install", "left-pad"},
		{"add", "left-pad"},
		{"update"},
		{"upgrade", "--all"},
	} {
		dec := eng.CheckCommand("npm", args)
		if dec.Rule != "approve-package-install" {
			t.Errorf("npm %v: rule = %q, want approve-package-install", args, dec.Rule)
		}
	}

	for _, args := range [][]string{
		{"run", "instal"},
		{"run", "reinstallation"},
		{"test"},
	} {
		dec := eng.CheckCommand("npm", args)
		if dec.Rule == "approve-package-install" {
			t.Errorf("npm %v: matched approve-package-install; the glob-shaped pattern used to do this", args)
		}
	}
}

func engineFor(t *testing.T, path string) *policy.Engine {
	t.Helper()
	p, err := policy.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	eng, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("build engine from %s: %v", path, err)
	}
	return eng
}

// TestShippedPolicies_NoShadowedCommandRule catches the bug that made
// approve-package-install dead in two shipped policies.
//
// Command rules are first match wins. A rule carrying args_patterns is
// narrower than one without, so an earlier rule naming the same command with
// no args_patterns matches first and the narrower rule never runs. In
// configs/policies/agent-sandbox.yaml that meant every npm, pip, pip3 and
// cargo install ran under `decision: allow` while the policy claimed to
// require approval, and nothing failed: the policy loaded, the engine built,
// and the rule was simply unreachable.
func TestShippedPolicies_NoShadowedCommandRule(t *testing.T) {
	for _, path := range shippedPolicyFiles(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			p, err := policy.LoadFromFile(path)
			if err != nil {
				t.Fatalf("%s does not load: %v", path, err)
			}
			for i, rule := range p.CommandRules {
				if len(rule.ArgsPatterns) == 0 {
					continue
				}
				for _, earlier := range p.CommandRules[:i] {
					if len(earlier.ArgsPatterns) > 0 {
						// Two argument-constrained rules can legitimately
						// overlap; which one wins is then a real ordering
						// choice rather than an accident.
						continue
					}
					if shadowed := overlappingCommands(rule.Commands, earlier.Commands); len(shadowed) > 0 {
						t.Errorf("rule %q is unreachable for %v: the earlier rule %q (decision=%s) names the same commands with no args_patterns, and command rules are first match wins",
							rule.Name, shadowed, earlier.Name, earlier.Decision)
					}
				}
			}
		})
	}
}

// overlappingCommands returns the commands both rules name. Comparison is by
// literal name, case-insensitively, which is how the engine matches a
// basename; a glob in the earlier rule can shadow more than this reports, so
// the check is a floor rather than a proof.
func overlappingCommands(narrow, broad []string) []string {
	have := make(map[string]struct{}, len(broad))
	for _, c := range broad {
		have[strings.ToLower(c)] = struct{}{}
	}
	var out []string
	for _, c := range narrow {
		if _, ok := have[strings.ToLower(c)]; ok {
			out = append(out, c)
		}
	}
	return out
}

// TestAgentSandbox_PackageInstallRequiresApproval pins the fix in the preset
// where it mattered: agent-sandbox is a shipped enforcement policy, not a
// documentation sample.
func TestAgentSandbox_PackageInstallRequiresApproval(t *testing.T) {
	eng := engineFor(t, filepath.Join(configsDir, "policies", "agent-sandbox.yaml"))

	for _, cmd := range []string{"npm", "pip", "pip3", "cargo"} {
		dec := eng.CheckCommand(cmd, []string{"install", "left-pad"})
		if dec.Rule != "approve-package-install" {
			t.Errorf("%s install: rule = %q, want approve-package-install", cmd, dec.Rule)
		}
	}
	// Everything else on those tools still runs under allow-dev-tools.
	if dec := eng.CheckCommand("npm", []string{"test"}); dec.Rule == "approve-package-install" {
		t.Errorf("npm test matched approve-package-install")
	}
	if dec := eng.CheckCommand("npm", []string{"run", "reinstallation"}); dec.Rule == "approve-package-install" {
		t.Errorf("npm run reinstallation matched approve-package-install; the pattern is not anchored")
	}
}
