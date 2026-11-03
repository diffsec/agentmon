package pkgcheck

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

// CheckerConfig holds all dependencies for the top-level package checker.
type CheckerConfig struct {
	Scope     string // "new_packages_only" | "all_installs"
	Resolvers []Resolver
	Providers map[string]ProviderEntry
	// Rules are the package rules of the daemon's default policy. Check uses
	// them. CheckForPolicy takes a session's own rules instead.
	Rules []policy.PackageRule
	// BlockOn are the rules from package_checks.block_on. They apply after a
	// policy's rules, except its final catch-all. See ComposeRules.
	BlockOn   []policy.PackageRule
	Allowlist *Allowlist
	// Privacy configures which packages are sent to external providers.
	// An empty PrivacyConfig (the zero value) means no filtering — all
	// packages are sent. T16 will plumb the YAML field through server.go.
	Privacy PrivacyConfig
}

// Checker is the single entry point for package install checks.
// It classifies the command, resolves the install plan, runs provider checks
// in parallel, evaluates findings via policy rules, and returns a verdict.
type Checker struct {
	cfg  CheckerConfig
	orch *Orchestrator
	eval *Evaluator

	// recent holds the verdicts of the last recentTTL, by install. On macOS
	// one `agentmon exec pip install x` is checked twice: by the exec API,
	// and again when the system extension sees the exec. Without this, the
	// second check resolves the same install again.
	mu     sync.Mutex
	recent map[string]recentVerdict
	now    func() time.Time
}

type recentVerdict struct {
	verdict Verdict
	at      time.Time
}

// recentTTL is how long Check reuses a verdict for the same install.
const recentTTL = 30 * time.Second

// NewChecker creates a new Checker wired to the given config.
func NewChecker(cfg CheckerConfig) *Checker {
	pf := NewPrivacyFilter(cfg.Privacy)
	return &Checker{
		cfg: cfg,
		orch: NewOrchestrator(OrchestratorConfig{
			Providers:     cfg.Providers,
			PrivacyFilter: pf,
		}),
		eval:   NewEvaluator(ComposeRules(cfg.Rules, cfg.BlockOn)),
		recent: make(map[string]recentVerdict),
		now:    time.Now,
	}
}

// Check evaluates a command. Returns a nil verdict if the command is not a
// recognised package-install operation.
//
// A verdict of allow, warn or block for the same install in the same
// directory is reused for recentTTL. An approve verdict is not reused,
// because each one asks a person.
func (c *Checker) Check(ctx context.Context, command string, args []string, workDir string) (*Verdict, error) {
	return c.check(ctx, c.eval, "default", command, args, workDir)
}

// CheckForPolicy is Check with a session policy's package rules in place of
// the default policy's. The block_on rules still apply. Before, every check
// used the daemon's default policy, so an agent-default session never got
// agent-default's package rules.
func (c *Checker) CheckForPolicy(ctx context.Context, rules []policy.PackageRule, command string, args []string, workDir string) (*Verdict, error) {
	eval := NewEvaluator(ComposeRules(rules, c.cfg.BlockOn))
	return c.check(ctx, eval, fmt.Sprintf("%+v", rules), command, args, workDir)
}

// check classifies the command and returns a recent verdict for the same
// install under the same rules, or checks it. rulesKey names the rules.
func (c *Checker) check(ctx context.Context, eval *Evaluator, rulesKey string, command string, args []string, workDir string) (*Verdict, error) {
	// `python -m pip install x` is a pip install.
	command, args = UnwrapInstallCommand(command, args)
	intent := ClassifyInstallCommand(command, args, c.cfg.Scope)
	if intent == nil {
		return nil, nil
	}
	key := rulesKey + "\x00" + recentKey(intent, workDir)
	if v, ok := c.recentVerdict(key); ok {
		return v, nil
	}
	v, err := c.resolveAndEvaluate(ctx, eval, command, args, workDir, intent)
	if err == nil && v != nil && v.Action != VerdictApprove {
		c.mu.Lock()
		c.recent[key] = recentVerdict{verdict: *v, at: c.now()}
		c.mu.Unlock()
	}
	return v, err
}

// recentKey names an install: the tool, the directory and the arguments.
// The directory is resolved, because the exec API and macOS ES can name the
// same one differently, for example /var and /private/var.
func recentKey(intent *InstallIntent, workDir string) string {
	if dir, err := filepath.EvalSymlinks(workDir); err == nil {
		workDir = dir
	}
	return intent.Tool + "\x00" + workDir + "\x00" + strings.Join(intent.OrigArgs, "\x00")
}

// recentVerdict returns a copy of a verdict from the last recentTTL, and
// drops the ones that are older.
func (c *Checker) recentVerdict(key string) (*Verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, r := range c.recent {
		if now.Sub(r.at) > recentTTL {
			delete(c.recent, k)
		}
	}
	r, ok := c.recent[key]
	if !ok {
		return nil, false
	}
	v := r.verdict
	return &v, true
}

func (c *Checker) resolveAndEvaluate(ctx context.Context, eval *Evaluator, command string, args []string, workDir string, intent *InstallIntent) (*Verdict, error) {
	// 2. Find a resolver that can handle this tool.
	// Strip leading global flags so args[0] is the subcommand,
	// which is what resolvers' CanResolve expects.
	cleanArgs := stripGlobalFlags(intent.OrigArgs)
	var resolver Resolver
	for _, r := range c.cfg.Resolvers {
		if r.CanResolve(intent.Tool, cleanArgs) {
			resolver = r
			break
		}
	}
	if resolver == nil {
		return nil, fmt.Errorf("no resolver for tool %q", intent.Tool)
	}

	// 3. Resolve the install plan.
	fullArgs := append([]string{command}, args...)
	plan, err := resolver.Resolve(ctx, workDir, fullArgs)
	if err != nil {
		return nil, fmt.Errorf("resolve install plan: %w", err)
	}

	// 4. Run all providers in parallel, applying privacy filtering.
	findings, providerErrs, skipped := c.orch.CheckAllWithPrivacy(ctx, CheckRequest{
		Ecosystem: plan.Ecosystem,
		Packages:  plan.AllPackagesWithRegistry(),
	})

	// 5. Handle provider errors: collect all, then apply strictest action.
	// Process provider errors by strictness after seeing ALL of them.
	// Initialize to VerdictAllow (weight 0) so the first real action always wins.
	strictestFailAction := VerdictAllow
	var strictestFailSummary string
	hasFailAction := false
	for _, pe := range providerErrs {
		switch pe.OnFailure {
		case "deny":
			if VerdictBlock.weight() > strictestFailAction.weight() {
				strictestFailAction = VerdictBlock
				strictestFailSummary = fmt.Sprintf("Provider %s unavailable (on_failure=%s): %v", pe.Provider, pe.OnFailure, pe.Err)
				hasFailAction = true
			}
		case "approve":
			if VerdictApprove.weight() > strictestFailAction.weight() {
				strictestFailAction = VerdictApprove
				strictestFailSummary = fmt.Sprintf("Provider %s unavailable (on_failure=%s): %v", pe.Provider, pe.OnFailure, pe.Err)
				hasFailAction = true
			}
		case "warn":
			findings = append(findings, Finding{
				Type:     FindingReputation,
				Provider: pe.Provider,
				Severity: SeverityInfo,
				Title:    fmt.Sprintf("provider %s unavailable", pe.Provider),
				Detail:   pe.Err.Error(),
			})
		}
		// "allow" on failure: no finding injected, evaluator decides on existing findings.
	}

	// Apply strictest failure action.
	if hasFailAction && strictestFailAction == VerdictBlock {
		return &Verdict{
			Action:   VerdictBlock,
			Findings: findings, // preserve any findings collected before the block decision
			Skipped:  skipped,
			Summary:  strictestFailSummary,
		}, nil
	}

	// 6. Evaluate findings against policy rules.
	verdict := eval.EvaluateWithContext(EvalContext{
		Findings:       findings,
		Ecosystem:      plan.Ecosystem,
		ProviderErrors: providerErrs,
		Skipped:        skipped,
	})

	// If any provider needs approval and verdict is weaker, upgrade to approve.
	if hasFailAction && strictestFailAction == VerdictApprove && verdict.Action.weight() < VerdictApprove.weight() {
		verdict.Action = VerdictApprove
	}

	// 7. Populate allowlist for allow/warn verdicts.
	if c.cfg.Allowlist != nil && (verdict.Action == VerdictAllow || verdict.Action == VerdictWarn) {
		registry := plan.Registry
		for _, pkg := range plan.AllPackages() {
			c.cfg.Allowlist.Add(registry, pkg.Name, pkg.Version)
		}
	}

	// 8. Enrich summary with package list; append provider failure reason if present.
	// Capture any "degraded:" prefix EvaluateWithContext added before
	// buildCheckerSummary regenerates the summary line.
	degradedPrefix := ""
	if strings.HasPrefix(verdict.Summary, "degraded:") {
		if semi := strings.Index(verdict.Summary, "; "); semi >= 0 {
			degradedPrefix = verdict.Summary[:semi+2]
		}
	}
	verdict.Summary = degradedPrefix + buildCheckerSummary(intent, plan, verdict)
	if hasFailAction && strictestFailSummary != "" {
		verdict.Summary = verdict.Summary + "; " + strictestFailSummary
	}

	return verdict, nil
}

// stripGlobalFlags removes leading global flags from args so that args[0]
// is the subcommand. Resolvers' CanResolve expects args[0] to be the
// subcommand (e.g., "install", "add", "pip"), but raw command args may
// contain leading flags like "--prefix /tmp".
func stripGlobalFlags(args []string) []string {
	sub, remaining := skipGlobalFlags(args)
	if sub == "" {
		return args
	}
	return append([]string{sub}, remaining...)
}

// buildCheckerSummary creates a human-readable summary for the verdict.
func buildCheckerSummary(intent *InstallIntent, plan *InstallPlan, verdict *Verdict) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] ", intent.Tool))

	pkgNames := make([]string, 0, len(plan.Direct))
	for _, p := range plan.Direct {
		pkgNames = append(pkgNames, p.String())
	}
	if len(pkgNames) > 0 {
		sb.WriteString(strings.Join(pkgNames, ", "))
	} else {
		sb.WriteString("bulk install")
	}

	sb.WriteString(fmt.Sprintf(" -> %s", verdict.Action))
	if len(verdict.Findings) > 0 {
		sb.WriteString(fmt.Sprintf(" (%d finding(s))", len(verdict.Findings)))
	}
	return sb.String()
}

// ComposeRules puts a policy's package rules first, then the block_on rules.
// A policy's last rule that matches every finding moves to the end.
// Otherwise it would shadow every block_on rule: agent-default ends with an
// allow for every finding, and block_on.vulnerability=high must still block
// a high vulnerability. A policy without a catch-all keeps the evaluator's
// default deny for a finding that no rule matches.
func ComposeRules(policyRules, blockOn []policy.PackageRule) []policy.PackageRule {
	out := make([]policy.PackageRule, 0, len(policyRules)+len(blockOn))
	var catchAll *policy.PackageRule
	if n := len(policyRules); n > 0 && IsCatchAllRule(policyRules[n-1]) {
		catchAll = &policyRules[n-1]
		policyRules = policyRules[:n-1]
	}
	out = append(out, policyRules...)
	out = append(out, blockOn...)
	if catchAll != nil {
		out = append(out, *catchAll)
	}
	return out
}

// IsCatchAllRule reports whether a package rule matches every finding.
func IsCatchAllRule(r policy.PackageRule) bool {
	m := r.Match
	return m.FindingType == "" && m.Severity == "" && len(m.Packages) == 0 &&
		len(m.NamePatterns) == 0 && len(m.Reasons) == 0 && m.Ecosystem == "" &&
		m.LicenseSPDX == nil && len(m.Options) == 0
}
