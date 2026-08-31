package inspect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

// defaultProviderTimeout bounds a single provider call when neither the rule
// nor the configuration sets one. It is a backstop, not a policy: a provider
// that hangs must not hold an AUTH decision or an HTTP request open
// indefinitely, because the caller's own deadline is what turns into a
// user-visible stall.
const defaultProviderTimeout = 10 * time.Second

// Config configures a Checker.
type Config struct {
	// Profiles is the policy's inspection.profiles block.
	Profiles map[string]policy.InspectionProfile
	// Providers are the available inspectors, keyed on Name().
	Providers []Provider
	// Privacy gates what may reach a non-local provider. Nil permits
	// nothing remote.
	Privacy *PrivacyConfig
	// ProviderTimeout bounds one provider call. Zero uses
	// defaultProviderTimeout.
	ProviderTimeout time.Duration
}

// Checker runs inspection profiles against content. It satisfies
// policy.InspectChecker, which is how it reaches the engine via
// Engine.SetInspector.
type Checker struct {
	profiles  map[string]policy.InspectionProfile
	providers map[string]Provider
	gate      *PrivacyGate
	timeout   time.Duration
}

// NewChecker builds a Checker. Duplicate provider names are a configuration
// error rather than a last-one-wins surprise: two providers answering to the
// same name means half the profiles silently reach the wrong one.
func NewChecker(cfg Config) (*Checker, error) {
	providers := make(map[string]Provider, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if p == nil {
			return nil, errors.New("inspect: nil provider in configuration")
		}
		name := p.Name()
		if name == "" {
			return nil, errors.New("inspect: provider with an empty name")
		}
		if _, dup := providers[name]; dup {
			return nil, fmt.Errorf("inspect: duplicate provider name %q", name)
		}
		providers[name] = p
	}

	profiles := make(map[string]policy.InspectionProfile, len(cfg.Profiles))
	for k, v := range cfg.Profiles {
		profiles[k] = v
	}

	timeout := cfg.ProviderTimeout
	if timeout <= 0 {
		timeout = defaultProviderTimeout
	}

	return &Checker{
		profiles:  profiles,
		providers: providers,
		gate:      NewPrivacyGate(cfg.Privacy),
		timeout:   timeout,
	}, nil
}

// Missing reports the profiles a Checker cannot run, and why. It exists so a
// caller can refuse to install a policy up front rather than discovering at
// the first request that every inspect rule fails closed.
func (c *Checker) Missing(profiles []string) []string {
	var missing []string
	for _, name := range profiles {
		prof, ok := c.profiles[name]
		if !ok {
			missing = append(missing, fmt.Sprintf("profile %q is not defined", name))
			continue
		}
		if _, ok := c.providers[prof.Provider]; !ok {
			missing = append(missing, fmt.Sprintf("profile %q names provider %q, which is not configured", name, prof.Provider))
		}
	}
	return missing
}

// Inspect runs every named profile against the content and merges the
// results. It satisfies policy.InspectChecker.
//
// Any failure -- an unknown profile, an unconfigured provider, a privacy
// refusal, a provider error, a timeout -- returns an error rather than a
// clean verdict. Content that was not inspected must never be reported as
// content that was inspected and found clean; Resolve routes the error to the
// rule's on_failure, which defaults to fail_closed.
func (c *Checker) Inspect(ctx context.Context, req policy.InspectRequest) (policy.InspectVerdict, error) {
	return c.InspectWith(ctx, req, nil)
}

// InspectWith is Inspect with a caller-supplied redaction strategy. A nil
// redactor uses PlaceholderRedactor. It satisfies RedactingChecker, which is
// how Resolve passes a caller's redactor down without widening
// policy.InspectChecker -- that interface stays narrow so the policy package
// keeps no dependency on this one.
func (c *Checker) InspectWith(ctx context.Context, req policy.InspectRequest, redactor Redactor) (policy.InspectVerdict, error) {
	if len(req.Profiles) == 0 {
		return policy.InspectVerdict{}, errors.New("inspect: no profiles named")
	}

	type job struct {
		profile string
		spec    policy.InspectionProfile
		p       Provider
	}
	jobs := make([]job, 0, len(req.Profiles))
	for _, name := range req.Profiles {
		spec, ok := c.profiles[name]
		if !ok {
			return policy.InspectVerdict{}, fmt.Errorf("inspect: profile %q is not defined", name)
		}
		p, ok := c.providers[spec.Provider]
		if !ok {
			return policy.InspectVerdict{}, fmt.Errorf("inspect: profile %q names provider %q, which is not configured", name, spec.Provider)
		}
		if allowed, why := c.gate.Allows(p, req.Kind); !allowed {
			return policy.InspectVerdict{}, fmt.Errorf("inspect: profile %q cannot run: %s", name, why)
		}
		jobs = append(jobs, job{profile: name, spec: spec, p: p})
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []Finding
		errs     []error
	)

	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()

			pctx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()

			resp, err := j.p.Inspect(pctx, Request{
				Profile: j.profile,
				Spec:    j.spec,
				Kind:    req.Kind,
				Content: req.Content,
			})

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, ProviderError{Provider: j.p.Name(), Profile: j.profile, Err: err})
				return
			}
			if resp == nil {
				errs = append(errs, ProviderError{
					Provider: j.p.Name(),
					Profile:  j.profile,
					Err:      errors.New("returned no response and no error"),
				})
				return
			}
			for _, f := range resp.Findings {
				if f.Profile == "" {
					f.Profile = j.profile
				}
				findings = append(findings, f)
			}
		}(j)
	}
	wg.Wait()

	// One provider failing fails the whole inspection. Reporting the other
	// providers' clean results would answer a question nobody asked: the
	// content was checked for some things and not others, and the caller has
	// no way to tell which. Fail, and let on_failure decide.
	if len(errs) > 0 {
		return policy.InspectVerdict{}, errors.Join(errs...)
	}

	if len(findings) == 0 {
		return policy.InspectVerdict{}, nil
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Start != findings[j].Start {
			return findings[i].Start < findings[j].Start
		}
		return findings[i].End < findings[j].End
	})

	return policy.InspectVerdict{
		Violation: true,
		Profile:   findings[0].Profile,
		Detail:    summarise(findings),
		Redacted:  redact(req.Content, findings, redactor),
	}, nil
}

// summarise describes findings without reproducing any of the content they
// point at. It goes into audit events and error messages.
func summarise(findings []Finding) string {
	counts := map[string]int{}
	var order []string
	for _, f := range findings {
		if _, seen := counts[f.Category]; !seen {
			order = append(order, f.Category)
		}
		counts[f.Category]++
	}
	sort.Strings(order)

	parts := make([]string, 0, len(order))
	for _, cat := range order {
		if counts[cat] == 1 {
			parts = append(parts, cat)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s x%d", cat, counts[cat]))
	}
	noun := "findings"
	if len(findings) == 1 {
		noun = "finding"
	}
	return fmt.Sprintf("%d %s: %s", len(findings), noun, strings.Join(parts, ", "))
}

// redact rewrites the spans the findings identify.
//
// Redaction happens here, once, from the merged span set -- not inside each
// provider. Two providers reporting overlapping spans would otherwise have
// their rewrites applied in sequence, and the first rewrite invalidates every
// offset the second was measured against. Merging first makes the result
// independent of provider order and of how many providers ran.
//
// The replacement is a non-reversible placeholder. Reversible pseudonymisation
// belongs to the DLP wire point, which already has a token store that can
// detokenise a response (internal/proxy/dlp.go); doing it here would create a
// second, unrelated token space.
func redact(content string, findings []Finding, redactor Redactor) string {
	if redactor == nil {
		redactor = PlaceholderRedactor{}
	}
	type span struct {
		start, end int
		category   string
	}
	var spans []span
	for _, f := range findings {
		if !f.HasSpan() {
			continue
		}
		if f.Start < 0 || f.End > len(content) {
			continue // a provider reporting offsets outside the content is ignored rather than trusted
		}
		spans = append(spans, span{f.Start, f.End, f.Category})
	}
	if len(spans) == 0 {
		return ""
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})

	var b strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last {
			// Overlaps a span already written. Extend only if it reaches
			// further; otherwise it is fully covered and adds nothing.
			if s.end <= last {
				continue
			}
			s.start = last
		}
		b.WriteString(content[last:s.start])
		b.WriteString(redactor.Replace(s.category, content[s.start:s.end]))
		last = s.end
	}
	b.WriteString(content[last:])
	return b.String()
}
