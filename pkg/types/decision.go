package types

type Decision string

const (
	DecisionAllow      Decision = "allow"
	DecisionDeny       Decision = "deny"
	DecisionApprove    Decision = "approve"
	DecisionRedirect   Decision = "redirect"
	DecisionAudit      Decision = "audit"       // Allow + enhanced logging
	DecisionSoftDelete Decision = "soft_delete" // Redirect destructive ops to trash

	// DecisionInspect defers the verdict to content inspection. It is not a
	// terminal state: a caller that holds the content runs the named
	// inspection profiles and resolves it to the rule's on_violation (on a
	// finding) or allow (on a clean result). A caller that does not
	// understand inspection sees EffectiveDecision deny, so an unwired code
	// path blocks rather than passes.
	DecisionInspect Decision = "inspect"
)

// InspectInfo is the inspection contract attached to a policy Decision. It is
// present when the rule's decision is "inspect", and when any other decision
// carries an `inspect:` block with require: true.
//
// There is no DecisionRedact: redaction is an allow whose content was
// rewritten, which the content-holding caller applies. Adding a terminal
// "redact" state would give every enforcement backend a decision it has no
// way to act on.
type InspectInfo struct {
	// Profiles names entries in the policy's inspection.profiles block.
	Profiles []string `json:"profiles"`
	// OnViolation is the decision to apply when inspection reports a
	// finding. One of allow, deny, approve, redact.
	OnViolation string `json:"on_violation"`
	// OnFailure is what to do when inspection cannot run or times out.
	// One of fail_closed, fail_open, approve.
	OnFailure string `json:"on_failure"`
	// TimeoutMS bounds a single inspection. Zero means the inspector's own
	// default applies.
	TimeoutMS int `json:"timeout_ms,omitempty"`
	// Require marks inspection as a precondition on a non-inspect decision
	// rather than the decision itself.
	Require bool `json:"require,omitempty"`
}

type ApprovalMode string

const (
	ApprovalModeShadow   ApprovalMode = "shadow"
	ApprovalModeEnforced ApprovalMode = "enforced"
)

type RedirectInfo struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`        // Prepended args
	ArgsAppend  []string          `json:"args_append,omitempty"` // Appended args
	Environment map[string]string `json:"environment,omitempty"` // Environment overrides
	Reason      string            `json:"reason,omitempty"`
}

// FileRedirectInfo describes a file path redirect.
type FileRedirectInfo struct {
	OriginalPath string `json:"original_path"`
	RedirectPath string `json:"redirect_path"`
	Operation    string `json:"operation"`
	Reason       string `json:"reason,omitempty"`
}
