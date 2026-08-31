package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/diffsec/agentmon/internal/httpretry"
	"github.com/diffsec/agentmon/internal/inspect"
)

// SidecarName is the provider name a policy profile uses: `provider: sidecar`.
const SidecarName = "sidecar"

// maxSidecarResponseBytes bounds how much of a sidecar response is read.
// The sidecar is a separate process the operator deploys, but it is not the
// trust boundary the daemon is, and an unbounded read on a response is the
// same denial-of-service surface as an unbounded read on a request body.
const maxSidecarResponseBytes = 32 << 20 // 32 MiB

// Sidecar is an HTTP inspection provider speaking the agentmon inspection
// contract:
//
//	POST {base}/v1/inspect/pii     {text, categories}          -> {spans, redacted_text}
//	POST {base}/v1/inspect/safety  {document, instruct, queries} -> {results}
//
// It is deliberately NOT a LocalProvider: content sent here leaves the
// process, and on a remote base URL leaves the machine, so the privacy gate
// must have a say. A sidecar bound to 127.0.0.1 is still gated, because
// nothing in an HTTP URL proves where it actually resolves to.
//
// The contract is the boundary, not the model. Anything that serves these two
// endpoints works, which is what keeps the choice of inference runtime -- a
// Python service, an ONNX Runtime process, llama.cpp behind a shim -- out of
// this codebase.
type Sidecar struct {
	baseURL string
	apiKey  string
	client  *httpretry.Client
	breaker *httpretry.Breaker
}

// SidecarConfig configures a Sidecar provider.
type SidecarConfig struct {
	// BaseURL is the sidecar root, e.g. http://127.0.0.1:8731.
	BaseURL string
	// APIKey, when set, is sent as a bearer token.
	APIKey string
	// MaxAttempts, BaseBackoff and MaxBackoff tune the retry client. Zero
	// values use httpretry's defaults.
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// Transport is for tests.
	Transport http.RoundTripper
}

// NewSidecar builds a Sidecar provider.
func NewSidecar(cfg SidecarConfig) (*Sidecar, error) {
	raw := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if raw == "" {
		return nil, fmt.Errorf("inspect/provider: sidecar base_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("inspect/provider: sidecar base_url %q: %w", cfg.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("inspect/provider: sidecar base_url %q must be http or https", cfg.BaseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("inspect/provider: sidecar base_url %q has no host", cfg.BaseURL)
	}

	return &Sidecar{
		baseURL: raw,
		apiKey:  cfg.APIKey,
		client: httpretry.New(httpretry.Config{
			MaxAttempts:       cfg.MaxAttempts,
			BaseBackoff:       cfg.BaseBackoff,
			MaxBackoff:        cfg.MaxBackoff,
			RespectRetryAfter: true,
			Transport:         cfg.Transport,
		}),
		breaker: httpretry.NewBreaker(httpretry.BreakerConfig{}),
	}, nil
}

// Name implements inspect.Provider.
func (s *Sidecar) Name() string { return SidecarName }

// Categories implements inspect.Provider.
//
// The sidecar's taxonomy is fixed by the models behind it, so this is the
// Privacy Filter label set. A profile naming something outside it is rejected
// before any content is sent -- a category the sidecar will not look for must
// not come back as a clean result.
func (s *Sidecar) Categories() []string {
	return []string{
		"account_number", "private_address", "private_date", "private_email",
		"private_person", "private_phone", "private_url", "secret",
	}
}

// Inspect implements inspect.Provider.
//
// A profile with categories runs the PII endpoint; one with queries runs the
// safety endpoint; one with both runs both and merges. Validate already
// rejects a profile with neither.
func (s *Sidecar) Inspect(ctx context.Context, req inspect.Request) (*inspect.Response, error) {
	start := time.Now()
	var findings []inspect.Finding

	if len(req.Spec.Categories) > 0 {
		got, err := s.inspectPII(ctx, req)
		if err != nil {
			return nil, err
		}
		findings = append(findings, got...)
	}
	if len(req.Spec.Queries) > 0 {
		got, err := s.inspectSafety(ctx, req)
		if err != nil {
			return nil, err
		}
		findings = append(findings, got...)
	}

	return &inspect.Response{
		Provider: SidecarName,
		Findings: findings,
		Metadata: inspect.ResponseMetadata{Duration: time.Since(start)},
	}, nil
}

// piiRequest is the body of POST /v1/inspect/pii.
type piiRequest struct {
	Text       string   `json:"text"`
	Categories []string `json:"categories,omitempty"`
}

// piiResponse is the reply.
//
// Span offsets are BYTES into the UTF-8 encoding of the text that was sent,
// half-open [start, end). This is stated here because it is the one part of
// the contract that fails silently when it is wrong: Privacy Filter's own
// decoder works in token offsets, so a sidecar that forwards those unconverted
// produces spans that look plausible and cut the wrong bytes out of a request
// body. validateSpan rejects anything out of range or off a rune boundary.
type piiResponse struct {
	Spans        []piiSpan `json:"spans"`
	RedactedText string    `json:"redacted_text,omitempty"`
}

type piiSpan struct {
	Start    int      `json:"start"`
	End      int      `json:"end"`
	Category string   `json:"category"`
	Score    *float64 `json:"score,omitempty"`
}

func (s *Sidecar) inspectPII(ctx context.Context, req inspect.Request) ([]inspect.Finding, error) {
	wanted := map[string]struct{}{}
	supported := map[string]struct{}{}
	for _, c := range s.Categories() {
		supported[c] = struct{}{}
	}
	for _, c := range req.Spec.Categories {
		if _, ok := supported[c]; !ok {
			return nil, fmt.Errorf("category %q is not supported by the sidecar provider", c)
		}
		wanted[c] = struct{}{}
	}

	var out piiResponse
	if err := s.post(ctx, "/v1/inspect/pii", piiRequest{
		Text:       req.Content,
		Categories: req.Spec.Categories,
	}, &out); err != nil {
		return nil, err
	}

	findings := make([]inspect.Finding, 0, len(out.Spans))
	for i, sp := range out.Spans {
		if err := validateSpan(req.Content, sp.Start, sp.End); err != nil {
			return nil, fmt.Errorf("span %d (%s): %w", i, sp.Category, err)
		}
		// A span for a category this profile did not ask for is dropped
		// rather than trusted: a profile scoped to `secret` must not start
		// redacting every email address because the sidecar volunteered one.
		if _, ok := wanted[sp.Category]; !ok {
			continue
		}
		f := inspect.Finding{
			Profile:  req.Profile,
			Category: sp.Category,
			Start:    sp.Start,
			End:      sp.End,
		}
		if sp.Score != nil {
			f.Score = *sp.Score
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// validateSpan checks a span against the exact content that was sent.
//
// An out-of-range or mid-rune span is an error, not a dropped finding. The
// provider and the daemon disagreeing about offsets means every other span in
// the same response is suspect too, and silently skipping the bad one would
// leave the rest to cut the wrong bytes.
func validateSpan(content string, start, end int) error {
	if start < 0 || end < 0 {
		return fmt.Errorf("negative offset [%d,%d)", start, end)
	}
	if end <= start {
		return fmt.Errorf("empty or inverted span [%d,%d)", start, end)
	}
	if end > len(content) {
		return fmt.Errorf("span [%d,%d) runs past the %d bytes that were sent; offsets must be bytes, not runes or tokens", start, end, len(content))
	}
	if !utf8.RuneStart(content[start]) {
		return fmt.Errorf("span start %d is inside a UTF-8 sequence", start)
	}
	if end < len(content) && !utf8.RuneStart(content[end]) {
		return fmt.Errorf("span end %d is inside a UTF-8 sequence", end)
	}
	return nil
}

// safetyRequest is the body of POST /v1/inspect/safety.
type safetyRequest struct {
	Document string        `json:"document"`
	Instruct string        `json:"instruct,omitempty"`
	Queries  []safetyQuery `json:"queries"`
}

type safetyQuery struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type safetyResponse struct {
	Results []safetyResult `json:"results"`
}

type safetyResult struct {
	ID      string   `json:"id"`
	Score   *float64 `json:"score,omitempty"`
	Verdict *bool    `json:"verdict,omitempty"`
}

// defaultSafetyThreshold matches Shieldstral's own operating point.
const defaultSafetyThreshold = 0.5

func (s *Sidecar) inspectSafety(ctx context.Context, req inspect.Request) ([]inspect.Finding, error) {
	queries := make([]safetyQuery, 0, len(req.Spec.Queries))
	thresholds := make(map[string]float64, len(req.Spec.Queries))
	for _, q := range req.Spec.Queries {
		queries = append(queries, safetyQuery{ID: q.ID, Text: q.Text})
		th := q.Threshold
		if th <= 0 {
			th = defaultSafetyThreshold
		}
		thresholds[q.ID] = th
	}

	var out safetyResponse
	if err := s.post(ctx, "/v1/inspect/safety", safetyRequest{
		Document: req.Content,
		Instruct: req.Spec.Instruct,
		Queries:  queries,
	}, &out); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var findings []inspect.Finding
	for _, r := range out.Results {
		th, known := thresholds[r.ID]
		if !known {
			// A result for a question nobody asked. Ignoring it is right;
			// acting on it would let the sidecar inject findings the policy
			// did not author.
			continue
		}
		seen[r.ID] = struct{}{}

		violated := false
		switch {
		case r.Score != nil:
			// The threshold is policy and the sidecar's own verdict is its
			// default, so the score decides whenever there is one.
			violated = *r.Score >= th
		case r.Verdict != nil:
			violated = *r.Verdict
		default:
			return nil, fmt.Errorf("query %q: sidecar returned neither score nor verdict", r.ID)
		}
		if !violated {
			continue
		}
		f := inspect.Finding{Profile: req.Profile, Category: r.ID}
		if r.Score != nil {
			f.Score = *r.Score
		}
		findings = append(findings, f)
	}

	// Every question must be answered. A missing answer is an unasked
	// question as far as the content is concerned, and reporting the rest as
	// a clean result would mean the profile checked less than it said.
	for _, q := range req.Spec.Queries {
		if _, ok := seen[q.ID]; !ok {
			return nil, fmt.Errorf("sidecar did not answer query %q", q.ID)
		}
	}
	return findings, nil
}

// post sends a JSON request and decodes a JSON reply, under the retry client
// and the circuit breaker.
func (s *Sidecar) post(ctx context.Context, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding %s request: %w", path, err)
	}

	return httpretry.CallWithBreaker(s.breaker, ctx, nil, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("building %s request: %w", path, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if s.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+s.apiKey)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("calling %s: %w", path, err)
		}
		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusOK {
			// The body may carry the sidecar's own error text, but it may
			// also echo the content that was sent. Only the status is
			// surfaced, because this error reaches the audit log.
			return fmt.Errorf("%s returned HTTP %d", path, resp.StatusCode)
		}

		dec := json.NewDecoder(io.LimitReader(resp.Body, maxSidecarResponseBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(out); err != nil {
			return fmt.Errorf("decoding %s response: %w", path, err)
		}
		return nil
	})
}
