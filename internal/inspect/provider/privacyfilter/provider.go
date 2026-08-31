package privacyfilter

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider/onnxrt"
	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter/modelcache"
	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter/tokenizer"
)

// Name is the provider name a policy profile uses: `provider: privacy_filter`.
const Name = "privacy_filter"

// modelContextTokens is the model's own context window, from its config.json
// (default_n_ctx). Text that tokenizes longer than this cannot be inspected in
// one pass.
//
// Exceeding it is an error, not a truncation. Inspecting the first 128k tokens
// and reporting the rest clean would let an agent bury anything past the limit,
// which is the same bypass a truncated body would be -- so it routes through
// the rule's on_failure and denies by default. Chunking long inputs is the fix
// and is not implemented here; see the note on Inspect.
const modelContextTokens = 128000

// Provider runs OpenAI Privacy Filter locally.
//
// It implements inspect.LocalProvider: everything happens in this process, so
// the privacy gate lets it see content without the allow_remote opt-in a
// sidecar needs. That is the point of the whole Go + ONNX path -- content that
// is being inspected for PII never leaves the machine to find out whether it
// contains PII.
type Provider struct {
	lib  *onnxrt.Library
	sess *onnxrt.Session
	tok  *tokenizer.Tokenizer
	cal  Calibration

	// needsMask records whether the loaded graph takes attention_mask.
	// Feeding an input the model does not declare is an error from ONNX
	// Runtime, so this is read from the graph rather than assumed.
	needsMask bool

	mu     sync.Mutex
	closed bool
}

// Config configures the provider.
type Config struct {
	// Variant selects the quantisation. Empty uses VariantQ4.
	Variant Variant
	// CacheDir is where model files are downloaded to. Empty uses
	// DefaultCacheDir.
	CacheDir string
	// LibraryPath points at libonnxruntime. Empty searches the standard
	// locations.
	LibraryPath string
	// IntraOpThreads bounds the threads one operator may use. Zero leaves
	// ONNX Runtime's default of one per core, which is too many for a
	// daemon that must stay responsive while inspecting one request.
	IntraOpThreads int
	// HTTPClient fetches model files. Nil uses a default.
	HTTPClient *http.Client
	// AllowDownload permits fetching the model when the cache is empty.
	// False requires an already-populated cache, which is how an air-gapped
	// or bandwidth-constrained deployment opts out of a 917MB download at
	// startup.
	AllowDownload bool
}

// DefaultCacheDir returns the default model cache location.
func DefaultCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("privacyfilter: locating a cache directory: %w", err)
	}
	return filepath.Join(dir, "agentmon", "models"), nil
}

// Open loads the model, downloading it first if the cache is empty and
// AllowDownload is set.
//
// It is slow by design -- a cold start downloads 917MB and a warm one still
// reads it -- so callers wire it at startup rather than per request. The
// server's inspection gate already refuses to start when a policy needs an
// inspector that cannot be built, which is what turns a failure here into a
// startup error rather than a request that denies for reasons nobody can see.
func Open(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Variant == "" {
		cfg.Variant = VariantQ4
	}
	spec, err := SpecFor(cfg.Variant)
	if err != nil {
		return nil, err
	}
	graph, err := GraphFile(cfg.Variant)
	if err != nil {
		return nil, err
	}

	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir, err = DefaultCacheDir()
		if err != nil {
			return nil, err
		}
	}

	cache := modelcache.New(cacheDir, cfg.HTTPClient, nil)
	dir := cache.Dir(spec)
	if !cfg.AllowDownload {
		if _, statErr := os.Stat(filepath.Join(dir, graph)); statErr != nil {
			return nil, fmt.Errorf("privacyfilter: model is not cached at %s and downloading is disabled: %w", dir, statErr)
		}
	} else {
		if dir, err = cache.Ensure(ctx, spec); err != nil {
			return nil, err
		}
	}

	tok, err := loadTokenizer(filepath.Join(dir, "tokenizer.json"))
	if err != nil {
		return nil, err
	}

	calRaw, err := os.ReadFile(filepath.Join(dir, "viterbi_calibration.json"))
	if err != nil {
		return nil, fmt.Errorf("privacyfilter: reading calibration: %w", err)
	}
	cal, err := LoadCalibration(calRaw, "")
	if err != nil {
		return nil, err
	}

	lib, err := onnxrt.Open(cfg.LibraryPath)
	if err != nil {
		return nil, err
	}

	// From a path, not from bytes: the graph is 160KB and its weights are a
	// separate 917MB file that ONNX Runtime resolves relative to the graph's
	// own directory.
	sess, err := lib.NewSessionFromPath(filepath.Join(dir, graph), onnxrt.SessionOptions{
		IntraOpThreads: cfg.IntraOpThreads,
	})
	if err != nil {
		lib.Close()
		return nil, err
	}

	p := &Provider{lib: lib, sess: sess, tok: tok, cal: cal}
	if err := p.checkGraph(); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

func loadTokenizer(path string) (*tokenizer.Tokenizer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("privacyfilter: opening tokenizer: %w", err)
	}
	defer f.Close()
	return tokenizer.Load(f)
}

// checkGraph confirms the loaded model has the shape this code assumes.
//
// A model with different input or output names would fail on the first
// request instead of at startup, and the message would be an ONNX Runtime
// error about a missing feed rather than "this is not the model you
// configured".
func (p *Provider) checkGraph() error {
	ins, err := p.sess.InputNames()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, n := range ins {
		seen[n] = true
	}
	if !seen["input_ids"] {
		return fmt.Errorf("privacyfilter: model has inputs %v; expected input_ids", ins)
	}

	outs, err := p.sess.OutputNames()
	if err != nil {
		return err
	}
	if len(outs) == 0 || outs[0] != "logits" {
		return fmt.Errorf("privacyfilter: model has outputs %v; expected logits", outs)
	}
	p.needsMask = seen["attention_mask"]
	return nil
}

// Close releases the session and the runtime.
func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.sess != nil {
		p.sess.Close()
	}
	if p.lib != nil {
		p.lib.Close()
	}
	p.closed = true
}

// Name implements inspect.Provider.
func (p *Provider) Name() string { return Name }

// IsLocal implements inspect.LocalProvider.
func (p *Provider) IsLocal() bool { return true }

// Categories implements inspect.Provider.
func (p *Provider) Categories() []string {
	return append([]string(nil), Categories...)
}

// Inspect implements inspect.Provider.
//
// One forward pass labels every token, and the constrained decoder turns those
// labels into spans. Token spans are then mapped to byte offsets through the
// tokenizer's own offsets -- never computed here -- because only the tokenizer
// knows where a token sits in the text, and a provider inventing byte offsets
// is how a redactor cuts the wrong bytes.
//
// Text longer than the model's context window is refused rather than
// truncated. Inspecting a prefix and reporting the rest clean would let an
// agent bury anything past the limit. Chunking with overlap would lift the
// limit and is not implemented: a span crossing a chunk boundary needs care,
// and getting it wrong produces spans with the wrong ends rather than an
// error.
func (p *Provider) Inspect(ctx context.Context, req inspect.Request) (*inspect.Response, error) {
	start := time.Now()

	wanted, err := p.wantedCategories(req.Spec.Categories)
	if err != nil {
		return nil, err
	}
	if req.Content == "" {
		return &inspect.Response{Provider: Name, Metadata: inspect.ResponseMetadata{Duration: time.Since(start)}}, nil
	}

	toks, err := p.tok.Encode(req.Content)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return &inspect.Response{Provider: Name, Metadata: inspect.ResponseMetadata{Duration: time.Since(start)}}, nil
	}
	if len(toks) > modelContextTokens {
		return nil, fmt.Errorf("content is %d tokens, past the model's %d-token context; it cannot be inspected in one pass",
			len(toks), modelContextTokens)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	logits, err := p.run(toks)
	if err != nil {
		return nil, err
	}

	spans, err := Decode(logits, len(toks), p.cal)
	if err != nil {
		return nil, err
	}

	findings := make([]inspect.Finding, 0, len(spans))
	for _, s := range spans {
		if _, ok := wanted[s.Category]; !ok {
			continue
		}
		if s.Start < 0 || s.End > len(toks) || s.End <= s.Start {
			// The decoder builds spans from a path it validated, so this
			// cannot happen -- and if it does, the offsets are meaningless
			// rather than merely wrong.
			return nil, fmt.Errorf("decoder produced token span [%d,%d) for %d tokens", s.Start, s.End, len(toks))
		}
		findings = append(findings, inspect.Finding{
			Profile:  req.Profile,
			Category: s.Category,
			Start:    toks[s.Start].Start,
			End:      toks[s.End-1].End,
			Score:    s.Score,
		})
	}

	return &inspect.Response{
		Provider: Name,
		Findings: findings,
		Metadata: inspect.ResponseMetadata{Duration: time.Since(start)},
	}, nil
}

// wantedCategories resolves the profile's category list.
//
// An unknown category is an error, not a skip. A profile asking for a category
// this model cannot produce would otherwise come back clean, which is the
// fail-open the whole design exists to prevent. An empty list means every
// category, because a profile naming none is asking for a general sweep and
// running nothing would report clean.
func (p *Provider) wantedCategories(requested []string) (map[string]struct{}, error) {
	known := map[string]struct{}{}
	for _, c := range Categories {
		known[c] = struct{}{}
	}
	if len(requested) == 0 {
		return known, nil
	}
	out := make(map[string]struct{}, len(requested))
	for _, c := range requested {
		if _, ok := known[c]; !ok {
			return nil, fmt.Errorf("category %q is not one this model detects", c)
		}
		out[c] = struct{}{}
	}
	return out, nil
}

// run performs one forward pass and returns the [T, NumLabels] logit grid.
func (p *Provider) run(toks []tokenizer.Token) ([]float32, error) {
	ids := make([]int64, len(toks))
	for i, t := range toks {
		ids[i] = int64(t.ID)
	}
	shape := []int64{1, int64(len(ids))}

	inputs := map[string]*onnxrt.Tensor{
		"input_ids": onnxrt.NewInt64Tensor(shape, ids),
	}
	if p.needsMask {
		mask := make([]int64, len(ids))
		for i := range mask {
			mask[i] = 1
		}
		inputs["attention_mask"] = onnxrt.NewInt64Tensor(shape, mask)
	}

	out, err := p.sess.Run(inputs, []string{"logits"})
	if err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, fmt.Errorf("privacyfilter: model returned %d outputs, want 1", len(out))
	}

	got := out[0]
	want := len(toks) * NumLabels
	if len(got.Floats) != want {
		// Catching this here beats letting Decode read the grid at the
		// wrong stride, which produces spans rather than an error.
		//
		// Untested: the real model always returns [1, T, 33], and nothing
		// short of a fake session can make it return anything else.
		// Mutation testing confirmed removing this check breaks nothing
		// today. It stays because the alternative to failing here is
		// mislabelled spans with plausible offsets.
		return nil, fmt.Errorf("privacyfilter: model returned %d logits with shape %v; want %d for %d tokens x %d labels",
			len(got.Floats), got.Shape, want, len(toks), NumLabels)
	}
	return got.Floats, nil
}

var _ inspect.Provider = (*Provider)(nil)
var _ inspect.LocalProvider = (*Provider)(nil)
