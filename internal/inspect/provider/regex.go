// Package provider holds inspection provider implementations.
package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/diffsec/agentmon/internal/inspect"
)

// RegexName is the provider name a policy profile uses to select this
// provider: `provider: regex`.
const RegexName = "regex"

// builtinPatterns maps categories from the Privacy Filter taxonomy to cheap
// regexes. The taxonomy is shared deliberately: a profile written against the
// regex provider keeps working when a model-backed provider replaces it, and
// the regex pass stays useful afterwards as the filter that decides whether
// the model runs at all.
//
// internal/proxy/dlp.go:71 carries an overlapping set under different names
// (email, phone, api_key). They should be consolidated when the DLP wire
// point lands; importing internal/proxy from here would invert the dependency,
// since proxy is a consumer of this package.
var builtinPatterns = map[string]string{
	"private_email": `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,

	// US formats: xxx-xxx-xxxx, (xxx) xxx-xxxx, xxx.xxx.xxxx, +1xxxxxxxxxx.
	"private_phone": `(?:\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`,

	"private_url": `https?://[^\s"'<>]+`,

	// Credit-card-shaped and SSN-shaped runs.
	"account_number": `\b(?:\d[ -]*?){13,19}\b|\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`,

	// Common credential prefixes followed by a high-entropy tail.
	"secret": `(?i)(?:sk|api|key|secret|token)[-_]?[a-zA-Z0-9]{20,}`,
}

// Regex is a local, in-process inspection provider backed by regular
// expressions.
//
// It exists so the inspection path is provable end to end with no model, no
// sidecar and no network: a rule matches, content is inspected, a decision
// resolves to deny or redact. It is genuinely useful beyond testing as the
// cheap pre-pass in front of an expensive model, but it is not a PII detector
// -- it has no notion of context, so it cannot tell a customer's phone number
// from a support line in a code comment.
type Regex struct {
	patterns map[string]*regexp.Regexp
}

// NewRegex builds a provider over the built-in patterns, plus any extras.
// An extra whose name matches a built-in replaces it.
func NewRegex(extra map[string]string) (*Regex, error) {
	merged := make(map[string]string, len(builtinPatterns)+len(extra))
	for k, v := range builtinPatterns {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}

	compiled := make(map[string]*regexp.Regexp, len(merged))
	for name, pat := range merged {
		re, err := regexp.Compile(pat)
		if err != nil {
			// An uncompilable pattern is a configuration error, not a
			// category to quietly drop. internal/proxy/dlp.go's addPattern
			// skips silently, and the result is a DLP processor that reports
			// a pattern count the operator never chose.
			return nil, fmt.Errorf("inspect/provider: category %q: %w", name, err)
		}
		compiled[name] = re
	}
	return &Regex{patterns: compiled}, nil
}

// Name implements inspect.Provider.
func (r *Regex) Name() string { return RegexName }

// IsLocal implements inspect.LocalProvider: this provider makes no network
// calls, so the privacy gate lets it see content unconditionally.
func (r *Regex) IsLocal() bool { return true }

// Categories implements inspect.Provider.
func (r *Regex) Categories() []string {
	out := make([]string, 0, len(r.patterns))
	for k := range r.patterns {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Inspect implements inspect.Provider.
//
// The profile's Categories field selects which patterns run. An empty
// Categories list runs every one: a profile that names no categories is
// asking for a general sweep, and running nothing would report clean.
//
// A category the provider does not know is an error, not a skip. Silently
// ignoring it would mean a profile asking for `secret` against a provider
// with no secret pattern comes back clean, which is the fail-open this whole
// design exists to prevent.
func (r *Regex) Inspect(ctx context.Context, req inspect.Request) (*inspect.Response, error) {
	start := time.Now()

	categories := req.Spec.Categories
	if len(categories) == 0 {
		categories = r.Categories()
	}
	for _, c := range categories {
		if _, ok := r.patterns[c]; !ok {
			return nil, fmt.Errorf("category %q is not supported by the regex provider", c)
		}
	}
	sort.Strings(categories)

	var findings []inspect.Finding
	for _, cat := range categories {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, m := range r.patterns[cat].FindAllStringIndex(req.Content, -1) {
			findings = append(findings, inspect.Finding{
				Profile:  req.Profile,
				Category: cat,
				Start:    m[0],
				End:      m[1],
				// A regex match is a match; there is no confidence to
				// report, and inventing a score would let a threshold
				// filter it as if one had been measured.
				Score: 0,
			})
		}
	}

	return &inspect.Response{
		Provider: RegexName,
		Findings: findings,
		Metadata: inspect.ResponseMetadata{Duration: time.Since(start)},
	}, nil
}
