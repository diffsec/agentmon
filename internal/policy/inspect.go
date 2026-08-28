package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/diffsec/agentmon/pkg/types"
)

// InspectionConfig is the policy's `inspection:` block: a set of named,
// reusable inspection profiles that rules refer to by name. Defining the
// provider and its parameters once, away from the rules, is what lets a
// single profile change apply to every rule that names it.
type InspectionConfig struct {
	Profiles map[string]InspectionProfile `yaml:"profiles"`
}

// InspectionProfile describes one way of inspecting content. The fields a
// given provider reads differ: a span classifier reads Categories, a
// question-answering safety classifier reads Instruct and Queries. Validation
// checks the shape of what is present, not which provider will consume it —
// no providers exist yet, and hardcoding a provider whitelist here would have
// to be edited every time one is added.
type InspectionProfile struct {
	// Provider names the inspector implementation, e.g. privacy_filter.
	Provider string `yaml:"provider"`
	// Categories restricts a span classifier to a subset of its labels.
	Categories []string `yaml:"categories,omitempty"`
	// Action is the profile's own default outcome on a finding. A rule's
	// on_violation overrides it.
	Action string `yaml:"action,omitempty"`
	// Instruct is the context and strictness given to a safety classifier.
	Instruct string `yaml:"instruct,omitempty"`
	// Queries are the yes/no questions a safety classifier answers.
	Queries []InspectionQuery `yaml:"queries,omitempty"`
}

// InspectionQuery is one yes/no question put to a safety classifier.
type InspectionQuery struct {
	ID        string  `yaml:"id"`
	Text      string  `yaml:"text"`
	Threshold float64 `yaml:"threshold,omitempty"`
}

// InspectSpec is a rule's `inspect:` block. It is the decision itself when the
// rule's decision is "inspect", and a precondition on the rule's decision when
// Require is true.
type InspectSpec struct {
	// Require makes inspection a precondition on a non-inspect decision.
	// Without it, an inspect block on e.g. `decision: allow` would be
	// inert, so Validate rejects that combination rather than silently
	// ignoring the block.
	Require bool `yaml:"require,omitempty"`
	// Profiles names entries in inspection.profiles. At least one.
	Profiles []string `yaml:"profiles"`
	// OnViolation is applied when inspection reports a finding.
	// Defaults to deny.
	OnViolation string `yaml:"on_violation,omitempty"`
	// OnFailure is applied when inspection cannot run, errors, or times
	// out. Defaults to fail_closed.
	OnFailure string `yaml:"on_failure,omitempty"`
	// Timeout bounds a single inspection. Zero leaves it to the inspector.
	Timeout duration `yaml:"timeout,omitempty"`
}

// Inspection outcome vocabularies. on_failure reuses the words already in this
// schema (DnsRedirectRule.OnFailure, ConnectRedirectRule.OnFailure) rather
// than inventing a third spelling of the same idea.
const (
	inspectDefaultOnViolation = "deny"
	inspectDefaultOnFailure   = "fail_closed"
)

var (
	inspectOnViolationValues = []string{"allow", "deny", "approve", "redact"}
	inspectOnFailureValues   = []string{"fail_closed", "fail_open", "approve"}
	inspectActionValues      = []string{"redact", "deny", "approve"}
)

// effectiveOnViolation and effectiveOnFailure apply the defaults. A caller
// must never read the raw fields: an empty OnFailure means fail_closed, and
// treating it as an empty string would fail open.
func (s *InspectSpec) effectiveOnViolation() string {
	if s == nil || s.OnViolation == "" {
		return inspectDefaultOnViolation
	}
	return s.OnViolation
}

func (s *InspectSpec) effectiveOnFailure() string {
	if s == nil || s.OnFailure == "" {
		return inspectDefaultOnFailure
	}
	return s.OnFailure
}

// toInspectInfo projects the policy-level spec onto the wire type carried on a
// Decision, with defaults resolved so no consumer has to know them.
func toInspectInfo(s *InspectSpec) *types.InspectInfo {
	if s == nil {
		return nil
	}
	return &types.InspectInfo{
		Profiles:    append([]string{}, s.Profiles...),
		OnViolation: s.effectiveOnViolation(),
		OnFailure:   s.effectiveOnFailure(),
		TimeoutMS:   int(s.Timeout.Milliseconds()),
		Require:     s.Require,
	}
}

// InspectRequest is the content handed to an inspector.
type InspectRequest struct {
	// Profiles are the profile names from the matched rule's spec.
	Profiles []string
	// Kind describes where the content came from: file, command, network,
	// proxy_body, mcp_args. Providers use it to pick a strictness, and the
	// audit log records it.
	Kind string
	// Content is the text to inspect.
	Content string
}

// InspectVerdict is an inspector's answer.
type InspectVerdict struct {
	// Violation is true when at least one profile reported a finding.
	Violation bool
	// Profile names the profile that produced the finding.
	Profile string
	// Detail is a short human-readable reason for the audit log. It must
	// not contain the inspected content — that content is exactly the
	// sensitive material inspection exists to keep from leaking.
	Detail string
	// Redacted is the rewritten content, set only when the resolved action
	// is redact.
	Redacted string
}

// InspectChecker is the optional content inspector, mirroring ThreatChecker
// and TorChecker: the policy package declares the interface and keeps zero
// dependency on any implementation.
type InspectChecker interface {
	Inspect(ctx context.Context, req InspectRequest) (InspectVerdict, error)
}

// SetInspector installs the optional content inspector. Pass nil to disable.
//
// The engine is usable without one: wrapRuleDecision resolves every
// inspect-bearing rule to an effective deny, because it runs at rule-match
// time and has no content. Wiring an inspector does not change that; it is the
// content-holding callers, added in later work, that consult it.
func (e *Engine) SetInspector(ic InspectChecker) {
	e.inspector = ic
}

// Inspector returns the installed inspector, or nil.
func (e *Engine) Inspector() InspectChecker { return e.inspector }

// RequiresInspection reports whether any rule in the policy names an
// inspection profile. A server that cannot provide an inspector should refuse
// to install such a policy rather than run it, because every inspect-bearing
// rule would otherwise resolve to a deny the operator did not write.
func (p Policy) RequiresInspection() bool {
	for _, r := range p.FileRules {
		if r.Inspect != nil || strings.EqualFold(r.Decision, string(types.DecisionInspect)) {
			return true
		}
	}
	for _, r := range p.NetworkRules {
		if r.Inspect != nil || strings.EqualFold(r.Decision, string(types.DecisionInspect)) {
			return true
		}
	}
	for _, r := range p.CommandRules {
		if r.Inspect != nil || strings.EqualFold(r.Decision, string(types.DecisionInspect)) {
			return true
		}
	}
	return false
}

// RequiresInspection reports whether the engine's policy needs an inspector.
func (e *Engine) RequiresInspection() bool {
	if e.policy == nil {
		return false
	}
	return e.policy.RequiresInspection()
}

// validateInspection checks the `inspection:` block and every rule's
// `inspect:` block, and enforces the decision whitelist for the rule kinds
// that carry one.
//
// Before this existed, Validate did not look at decision strings at all: an
// unrecognised decision reached wrapDecision's default arm and became a deny,
// with no error at load time and a rule name of "invalid-policy-decision" in
// the audit log as the only clue. A typo'd `decsion: allow` therefore denied
// silently, and `decision: inspect` would have done the same.
func (p Policy) validateInspection() error {
	profiles := map[string]InspectionProfile{}
	if p.Inspection != nil {
		profiles = p.Inspection.Profiles
	}

	for _, name := range sortedProfileNames(profiles) {
		prof := profiles[name]
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("inspection.profiles: profile name is required")
		}
		if strings.TrimSpace(prof.Provider) == "" {
			return fmt.Errorf("inspection.profiles[%s]: provider is required", name)
		}
		if prof.Action != "" && !containsInspectValue(inspectActionValues, prof.Action) {
			return fmt.Errorf("inspection.profiles[%s]: action must be one of %s", name, strings.Join(inspectActionValues, ", "))
		}
		if len(prof.Categories) == 0 && len(prof.Queries) == 0 {
			return fmt.Errorf("inspection.profiles[%s]: at least one of categories or queries is required, otherwise the profile inspects nothing", name)
		}
		seenQuery := map[string]struct{}{}
		for i, q := range prof.Queries {
			if strings.TrimSpace(q.ID) == "" {
				return fmt.Errorf("inspection.profiles[%s].queries[%d]: id is required", name, i)
			}
			if _, dup := seenQuery[q.ID]; dup {
				return fmt.Errorf("inspection.profiles[%s].queries[%d]: duplicate id %q", name, i, q.ID)
			}
			seenQuery[q.ID] = struct{}{}
			if strings.TrimSpace(q.Text) == "" {
				return fmt.Errorf("inspection.profiles[%s].queries[%d]: text is required", name, i)
			}
			if q.Threshold < 0 || q.Threshold > 1 {
				return fmt.Errorf("inspection.profiles[%s].queries[%d]: threshold must be between 0 and 1, got %v", name, i, q.Threshold)
			}
		}
	}

	for i, r := range p.FileRules {
		if err := validateRuleDecision(fmt.Sprintf("file_rules[%d] (%s)", i, r.Name), r.Decision, r.Inspect, profiles, true); err != nil {
			return err
		}
	}
	for i, r := range p.NetworkRules {
		if err := validateRuleDecision(fmt.Sprintf("network_rules[%d] (%s)", i, r.Name), r.Decision, r.Inspect, profiles, true); err != nil {
			return err
		}
	}
	for i, r := range p.CommandRules {
		if err := validateRuleDecision(fmt.Sprintf("command_rules[%d] (%s)", i, r.Name), r.Decision, r.Inspect, profiles, true); err != nil {
			return err
		}
	}
	for i, r := range p.UnixRules {
		if err := validateRuleDecision(fmt.Sprintf("unix_socket_rules[%d] (%s)", i, r.Name), r.Decision, nil, profiles, false); err != nil {
			return err
		}
	}
	return nil
}

// ruleDecisionValues is the whitelist for file, network, command and unix
// socket rules. Signal rules are deliberately excluded: they have their own
// vocabulary including "absorb" and their own engine
// (internal/signal), so a shared whitelist would reject valid signal policy.
var ruleDecisionValues = []types.Decision{
	types.DecisionAllow,
	types.DecisionDeny,
	types.DecisionApprove,
	types.DecisionRedirect,
	types.DecisionAudit,
	types.DecisionSoftDelete,
}

func validateRuleDecision(where, decision string, spec *InspectSpec, profiles map[string]InspectionProfile, inspectAllowed bool) error {
	d := types.Decision(strings.ToLower(strings.TrimSpace(decision)))

	// An empty decision is left alone. Several rule kinds are constructed
	// programmatically with the field unset and rely on the engine's
	// default-deny, and rejecting it here would break policies that load
	// today for no safety gain -- the fall-through is already a deny.
	if d == "" {
		if spec != nil {
			return fmt.Errorf("%s: inspect block requires a decision", where)
		}
		return nil
	}

	known := false
	for _, v := range ruleDecisionValues {
		if d == v {
			known = true
			break
		}
	}
	if d == types.DecisionInspect {
		if !inspectAllowed {
			return fmt.Errorf("%s: decision inspect is not supported on this rule kind; there is no content to inspect", where)
		}
		known = true
	}
	if !known {
		return fmt.Errorf("%s: unknown decision %q", where, decision)
	}

	if d == types.DecisionInspect {
		if spec == nil {
			return fmt.Errorf("%s: decision inspect requires an inspect block naming at least one profile", where)
		}
	} else if spec != nil && !spec.Require {
		// Attaching inspection to a decision that does not defer to it,
		// without require, does nothing at all. Refusing it is what stops
		// a policy from reading as if content were being checked when
		// nothing checks it.
		return fmt.Errorf("%s: inspect block on decision %q has no effect; set inspect.require: true to make inspection a precondition, or use decision: inspect", where, decision)
	}

	if spec == nil {
		return nil
	}
	if len(spec.Profiles) == 0 {
		return fmt.Errorf("%s: inspect.profiles must name at least one profile", where)
	}
	for _, name := range spec.Profiles {
		if _, ok := profiles[name]; !ok {
			return fmt.Errorf("%s: inspect.profiles references undefined profile %q; define it under inspection.profiles", where, name)
		}
	}
	if spec.OnViolation != "" && !containsInspectValue(inspectOnViolationValues, spec.OnViolation) {
		return fmt.Errorf("%s: inspect.on_violation must be one of %s", where, strings.Join(inspectOnViolationValues, ", "))
	}
	if spec.OnFailure != "" && !containsInspectValue(inspectOnFailureValues, spec.OnFailure) {
		return fmt.Errorf("%s: inspect.on_failure must be one of %s", where, strings.Join(inspectOnFailureValues, ", "))
	}
	if spec.Timeout.Duration < 0 {
		return fmt.Errorf("%s: inspect.timeout must not be negative", where)
	}
	return nil
}

func containsInspectValue(vals []string, v string) bool {
	for _, s := range vals {
		if s == v {
			return true
		}
	}
	return false
}

// sortedProfileNames makes validation errors deterministic: ranging a map
// directly would report a different profile's error on different runs for a
// policy with more than one broken profile.
func sortedProfileNames(m map[string]InspectionProfile) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
