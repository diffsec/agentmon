package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/diffsec/agentmon/internal/httpretry"
	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/policy"
)

// ShieldstralName is the provider name a policy profile uses:
// `provider: shieldstral`.
const ShieldstralName = "shieldstral"

// systemPrompt is fixed by the model. Shieldstral was trained with exactly
// this system message, and changing a word of it changes what the yes/no
// token means. It is not configurable for that reason.
//
// Source: the mistralai/Shieldstral-1.0-3B model card, "How It Works".
const systemPrompt = `Judge whether the Document meets the requirements based on the Query ` +
	`and the Instruction provided. Note that the answer can only be "yes" or "no".`

// maxShieldstralResponseBytes bounds how much of a reply is read. The
// interesting part is one token's top_logprobs, which is a few kilobytes; the
// cap is generous but finite, because an unbounded read on a response is the
// same denial-of-service surface as one on a request body.
const maxShieldstralResponseBytes = 4 << 20 // 4 MiB

// defaultShieldstralConcurrency bounds how many queries run at once.
//
// Shieldstral answers one yes/no question per call, so a profile with four
// queries is four forward passes. Running them in sequence multiplies the
// latency of every request the rule gates; running them all at once puts an
// unbounded burst on a server that may be a single GPU. Four is the profile
// size the plan's own example uses.
const defaultShieldstralConcurrency = 4

// yesTokens and noTokens are the surface forms the answer token can take,
// compared after trimming and lowercasing. Taken from the model card's
// reference helper: the tokenizer can emit the bare word, a trailing period,
// or a quoted form depending on how the prompt ended.
var (
	yesTokens = map[string]struct{}{"yes": {}, "yes.": {}, `"yes"`: {}, "'yes'": {}}
	noTokens  = map[string]struct{}{"no": {}, "no.": {}, `"no"`: {}, "'no'": {}}
)

// Shieldstral is a safety classifier reached over an OpenAI-compatible chat
// endpoint.
//
// Shieldstral ships no server of its own, but it needs none: vLLM, llama.cpp
// and SGLang all serve it behind the OpenAI chat-completions API, and its
// whole contract is one forward pass returning a single yes/no token. That is
// exactly what `max_tokens: 1` with `logprobs` returns, so this is an HTTP
// client and about forty lines of arithmetic rather than a sidecar.
//
// It is deliberately NOT a LocalProvider: content sent here leaves the
// process, and on a remote base URL leaves the machine, so the privacy gate
// must have a say. A server bound to 127.0.0.1 is still gated, because
// nothing in an HTTP URL proves where it actually resolves to.
type Shieldstral struct {
	baseURL     string
	model       string
	apiKey      string
	client      *httpretry.Client
	breaker     *httpretry.Breaker
	concurrency int
}

// ShieldstralConfig configures a Shieldstral provider.
type ShieldstralConfig struct {
	// BaseURL is the OpenAI-compatible root, e.g. http://127.0.0.1:8000/v1.
	// A trailing /chat/completions is added.
	BaseURL string
	// Model is the name the server knows the checkpoint by, e.g.
	// mistralai/Shieldstral-1.0-3B for vLLM or the GGUF alias for
	// llama-server.
	Model string
	// APIKey, when set, is sent as a bearer token.
	APIKey string
	// Concurrency bounds simultaneous queries. Zero uses
	// defaultShieldstralConcurrency.
	Concurrency int
	// MaxAttempts, BaseBackoff and MaxBackoff tune the retry client. Zero
	// values use httpretry's defaults.
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// Transport is for tests.
	Transport http.RoundTripper
}

// NewShieldstral builds a Shieldstral provider.
func NewShieldstral(cfg ShieldstralConfig) (*Shieldstral, error) {
	raw := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if raw == "" {
		return nil, fmt.Errorf("inspect/provider: shieldstral base_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("inspect/provider: shieldstral base_url %q: %w", cfg.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("inspect/provider: shieldstral base_url %q must be http or https", cfg.BaseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("inspect/provider: shieldstral base_url %q has no host", cfg.BaseURL)
	}
	// The model name is what the server routes on. An empty one reaches a
	// server that answers 404 or, worse, picks a default checkpoint that is
	// not a safety classifier at all and returns prose instead of yes/no.
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("inspect/provider: shieldstral model is required")
	}

	conc := cfg.Concurrency
	if conc <= 0 {
		conc = defaultShieldstralConcurrency
	}

	return &Shieldstral{
		baseURL:     raw,
		model:       strings.TrimSpace(cfg.Model),
		apiKey:      cfg.APIKey,
		concurrency: conc,
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
func (s *Shieldstral) Name() string { return ShieldstralName }

// Categories implements inspect.Provider.
//
// Shieldstral has no fixed taxonomy: that is the point of it. The moderation
// criteria are the profile's own natural-language queries, supplied at
// inference time, and a finding's category is the query's id. So there is no
// list to publish, and a profile using `categories:` here is a mistake --
// Inspect refuses it rather than answering a question the model was never
// asked.
func (s *Shieldstral) Categories() []string { return nil }

// Inspect implements inspect.Provider.
func (s *Shieldstral) Inspect(ctx context.Context, req inspect.Request) (*inspect.Response, error) {
	start := time.Now()

	if len(req.Spec.Queries) == 0 {
		return nil, fmt.Errorf("inspect/provider: shieldstral profile %q defines no queries; it classifies against natural-language questions, not a category list", req.Profile)
	}
	if len(req.Spec.Categories) > 0 {
		// Silently ignoring them would let a profile read as if it were
		// screening for those labels while nothing looked for them.
		return nil, fmt.Errorf("inspect/provider: shieldstral profile %q lists categories, which it cannot use; express each one as a query instead", req.Profile)
	}

	type result struct {
		finding *inspect.Finding
		err     error
	}
	results := make([]result, len(req.Spec.Queries))

	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup
	for i, q := range req.Spec.Queries {
		wg.Add(1)
		go func(i int, q policy.InspectionQuery) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			score, err := s.score(ctx, req.Spec.Instruct, q.Text, req.Content)
			if err != nil {
				results[i] = result{err: fmt.Errorf("query %q: %w", q.ID, err)}
				return
			}
			th := q.Threshold
			if th <= 0 {
				th = defaultSafetyThreshold
			}
			if score < th {
				return
			}
			// No span: the model answers a question about the whole
			// document and reports no offsets, which is why
			// `on_violation: redact` cannot act on a Shieldstral finding.
			// inspect.Resolve denies in that case rather than passing the
			// content through.
			results[i] = result{finding: &inspect.Finding{
				Profile:  req.Profile,
				Category: q.ID,
				Score:    score,
			}}
		}(i, q)
	}
	wg.Wait()

	// Every question must be answered. A query that errored is a question
	// the content was not screened against, and returning the others as a
	// clean result would mean the profile checked less than it said.
	var errs []error
	var findings []inspect.Finding
	for _, r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		if r.finding != nil {
			findings = append(findings, *r.finding)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &inspect.Response{
		Provider: ShieldstralName,
		Findings: findings,
		Metadata: inspect.ResponseMetadata{Duration: time.Since(start)},
	}, nil
}

// buildUserMessage assembles the three-field prompt the model was trained on.
//
// The field order and the blank lines between them are part of the format,
// not presentation. Source: the model card's "Full example".
func buildUserMessage(instruct, query, document string) string {
	var b strings.Builder
	b.WriteString("<Instruct>: ")
	b.WriteString(instruct)
	b.WriteString("\n\n<Query>: ")
	b.WriteString(query)
	b.WriteString("\n\n<Document>: ")
	b.WriteString(document)
	return b.String()
}

// chatRequest is the OpenAI chat-completions body.
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	Logprobs    bool          `json:"logprobs"`
	TopLogprobs int           `json:"top_logprobs"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the subset of the reply this provider reads. Unknown
// fields are ignored rather than rejected: this speaks a widely implemented
// API, and vLLM, llama.cpp and SGLang each add their own.
type chatResponse struct {
	Choices []struct {
		Logprobs *struct {
			Content []struct {
				TopLogprobs []topLogprob `json:"top_logprobs"`
			} `json:"content"`
		} `json:"logprobs"`
	} `json:"choices"`
}

// topLogprob is one candidate token at the answer position.
type topLogprob struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
}

// score asks one yes/no question and returns the probability of "yes".
func (s *Shieldstral) score(ctx context.Context, instruct, query, document string) (float64, error) {
	body := chatRequest{
		Model: s.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserMessage(instruct, query, document)},
		},
		// One token, greedy, with the full candidate set at that position.
		// top_logprobs of 20 is what the reference helper uses: the answer
		// token is normally rank 1, but a document that pushes the model
		// towards prose can bury it, and a narrower window would then drop
		// the signal entirely.
		MaxTokens:   1,
		Temperature: 0,
		Logprobs:    true,
		TopLogprobs: 20,
	}

	var out chatResponse
	if err := s.post(ctx, body, &out); err != nil {
		return 0, err
	}
	if len(out.Choices) == 0 {
		return 0, errors.New("response carried no choices")
	}
	lp := out.Choices[0].Logprobs
	if lp == nil || len(lp.Content) == 0 {
		return 0, errors.New("response carried no logprobs; the server must be called with logprobs enabled")
	}

	return yesProbability(lp.Content[0].TopLogprobs)
}

// yesProbability renormalises the yes and no logprobs into P(yes).
//
// It diverges from the model card's reference helper in one way, and
// deliberately. That helper floors a missing token at -10.0, so a reply
// containing neither "yes" nor "no" scores exactly 0.5 and is reported safe.
// Here that is an error. A model that did not answer the question has not
// screened the content, and the whole point of this package is that
// uninspected content never comes back as inspected-and-clean; the error
// routes through the rule's on_failure, which denies by default.
func yesProbability(top []topLogprob) (float64, error) {
	yes, no := math.Inf(-1), math.Inf(-1)
	for _, t := range top {
		tok := strings.ToLower(strings.TrimSpace(t.Token))
		if _, ok := yesTokens[tok]; ok {
			yes = math.Max(yes, t.Logprob)
			continue
		}
		if _, ok := noTokens[tok]; ok {
			no = math.Max(no, t.Logprob)
		}
	}

	switch {
	case math.IsInf(yes, -1) && math.IsInf(no, -1):
		return 0, errors.New("neither a yes nor a no token appeared in the answer position; the model did not answer the question")
	case math.IsInf(no, -1):
		// Only "yes" was a candidate. The reference helper's -10.0 floor
		// makes this ~1.0; saying so exactly is the same conclusion without
		// a magic number.
		return 1, nil
	case math.IsInf(yes, -1):
		return 0, nil
	}

	// P(yes) = exp(yes) / (exp(yes) + exp(no)), rearranged to the logistic
	// of the difference. Mathematically identical, and it cannot overflow:
	// the direct form exponentiates each logprob separately, and a
	// confident server returning a large negative logprob underflows both
	// terms to zero and yields NaN.
	return 1 / (1 + math.Exp(no-yes)), nil
}

// post sends the chat request under the retry client and the circuit breaker.
func (s *Shieldstral) post(ctx context.Context, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding chat request: %w", err)
	}
	endpoint := s.baseURL + "/chat/completions"

	return httpretry.CallWithBreaker(s.breaker, ctx, nil, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("building chat request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if s.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+s.apiKey)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("calling shieldstral: %w", err)
		}
		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusOK {
			// The body may carry the server's error text, but an
			// OpenAI-compatible server also echoes the prompt on some
			// errors -- and the prompt contains the document. Only the
			// status is surfaced, because this error reaches the audit log.
			return fmt.Errorf("shieldstral returned HTTP %d", resp.StatusCode)
		}

		// Unknown fields are allowed here, unlike the sidecar contract:
		// this is a third-party API with several implementations, and
		// rejecting an extra field would break on a server upgrade rather
		// than on anything that matters.
		dec := json.NewDecoder(io.LimitReader(resp.Body, maxShieldstralResponseBytes))
		if err := dec.Decode(out); err != nil {
			return fmt.Errorf("decoding chat response: %w", err)
		}
		return nil
	})
}
