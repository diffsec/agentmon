// Package inspect runs content through inspection providers and resolves the
// policy engine's `inspect` decision against what they find.
//
// The policy engine cannot resolve an inspect decision itself: it matches
// rules against a path, an argv or a destination, never the content those
// refer to (see internal/policy/engine.go, wrapRuleDecision). It therefore
// emits a Decision whose EffectiveDecision is deny with an InspectInfo
// attached. This package is what a content-holding caller uses to turn that
// into a real verdict -- see Resolve.
package inspect

import (
	"context"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

// Kind describes where inspected content came from. Providers use it to pick
// a strictness, and it is recorded on the audit trail.
const (
	KindFile      = "file"
	KindCommand   = "command"
	KindNetwork   = "network"
	KindProxyBody = "proxy_body"
	KindMCPArgs   = "mcp_args"
)

// Provider inspects content and reports findings. Implementations live in
// internal/inspect/provider.
type Provider interface {
	// Name returns the provider's identifier, matching the `provider:` field
	// of an inspection profile.
	Name() string

	// Categories returns the finding categories this provider can produce.
	// A profile naming a category no provider covers is a configuration
	// error the caller should surface, not a silent clean result.
	Categories() []string

	// Inspect examines req.Content and returns findings.
	Inspect(ctx context.Context, req Request) (*Response, error)
}

// LocalProvider is an optional interface for providers that run entirely
// in-process and make no network calls. The privacy gate lets those see
// content unconditionally; everything else has to be permitted explicitly.
// It mirrors pkgcheck.LocalProvider, which draws the same distinction for
// package names.
type LocalProvider interface {
	IsLocal() bool
}

// Request is one profile applied to one piece of content.
type Request struct {
	// Profile is the name the policy gave this profile.
	Profile string
	// Spec is the profile definition from the policy's inspection block.
	Spec policy.InspectionProfile
	// Kind is one of the Kind* constants.
	Kind string
	// Content is the text to inspect.
	Content string
}

// Response is one provider's answer for one request.
type Response struct {
	Provider string
	Findings []Finding
	Metadata ResponseMetadata
}

// Finding is one detected span or one answered query.
//
// A Finding deliberately does NOT carry the matched text. That text is
// exactly the sensitive material inspection exists to keep from spreading,
// and findings end up in logs, audit events and error messages. Callers that
// need the content have it already; everyone else gets offsets.
type Finding struct {
	// Profile is the profile that produced this finding.
	Profile string
	// Category is the taxonomy label, e.g. private_email or secret. For a
	// query-based provider it is the query's id.
	Category string
	// Start and End are byte offsets into the inspected content. Both are
	// zero for a finding with no span, such as a query answer.
	Start int
	End   int
	// Score is the provider's confidence in [0,1]. Zero means the provider
	// does not report one.
	Score float64
}

// HasSpan reports whether the finding identifies a byte range that can be
// redacted. A query answer ("does this exfiltrate credentials?") has no span,
// so on_violation: redact cannot act on it.
func (f Finding) HasSpan() bool { return f.End > f.Start }

// ResponseMetadata holds operational details about a provider response.
type ResponseMetadata struct {
	Duration time.Duration
	Error    string
}

// ProviderError records a failure from a single provider.
type ProviderError struct {
	Provider string
	Profile  string
	Err      error
}

func (e ProviderError) Error() string {
	return "inspect provider " + e.Provider + " (profile " + e.Profile + "): " + e.Err.Error()
}

func (e ProviderError) Unwrap() error { return e.Err }
