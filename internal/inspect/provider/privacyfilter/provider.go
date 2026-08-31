package privacyfilter

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider/onnxrt"
	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter/modelcache"
	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter/tokenizer"
)

// Name is the provider name a policy profile uses: `provider: privacy_filter`.
const Name = "privacy_filter"

// modelContextTokens is the model's own context window, from its config.json
// (default_n_ctx).
//
// Nothing here approaches it: windows are DefaultWindow tokens, and content
// longer than one window is split rather than refused. It is kept as an
// assertion -- a window configured larger than the model can accept would
// fail inside ONNX Runtime with a shape error rather than here.
const modelContextTokens = 128000

// MaxConcurrency caps how many windows may run at once.
//
// Four, because measurement says throughput stops improving there and starts
// collapsing beyond it: six workers ran slower than one, and twelve was killed
// by the OS. Each worker holds its own activations for a 917MB model, so the
// failure mode of an over-large value is not a slow request -- it is the
// daemon dying.
const MaxConcurrency = 4

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

	// window and overlap size the inference windows. See chunk.go.
	window, overlap int
	// concurrency is how many windows run at once.
	concurrency int

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
	// Concurrency is how many windows run at once. Zero or one runs them in
	// sequence. Values above MaxConcurrency are clamped.
	//
	// The gain is modest and it stops early: measured on a 12-core M-series
	// laptop over 128KB, concurrency 1 gave 4.0 KB/s, 2 gave 5.3, 4 gave 5.6
	// and there it flattened. The model is bound by memory bandwidth rather
	// than compute, so extra workers contend for the same 917MB of weights
	// instead of adding throughput.
	//
	// Past that it gets actively worse, then fatal. Six workers measured
	// 1.4 KB/s and eight measured 0.9 -- slower than running them one at a
	// time -- and twelve was killed by the OS for exhausting memory. That is
	// what MaxConcurrency exists to prevent: a config typo must not take the
	// daemon down.
	Concurrency int

	// Window and Overlap size the inference windows. Zero uses
	// DefaultWindow and DefaultOverlap. Lowering Overlap below the model's
	// receptive field makes chunking lossy, so it is exposed for
	// measurement rather than tuning.
	Window, Overlap int

	// CoreML asks ONNX Runtime for Apple's CoreML execution provider.
	//
	// Measured 8x SLOWER on this model: 38.4s against 4.9s for 32KB, with
	// identical findings. ONNX Runtime partitions the graph and runs on CPU
	// whatever CoreML will not take, and for a sparse mixture-of-experts the
	// partition boundaries cost more than the accelerator saves. Left
	// reachable because that is a property of this model and this runtime
	// version, not a law -- but do not turn it on without measuring.
	CoreML bool

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
		CoreML:         cfg.CoreML,
	})
	if err != nil {
		lib.Close()
		return nil, err
	}

	win, over := cfg.Window, cfg.Overlap
	if win <= 0 {
		win = DefaultWindow
	}
	if over <= 0 {
		over = DefaultOverlap
	}

	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 1
	}
	if conc > MaxConcurrency {
		slog.Warn("privacyfilter: window concurrency clamped",
			"requested", cfg.Concurrency, "using", MaxConcurrency,
			"reason", "higher values measured slower and were killed for exhausting memory")
		conc = MaxConcurrency
	}

	p := &Provider{lib: lib, sess: sess, tok: tok, cal: cal, window: win, overlap: over, concurrency: conc}
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
// Content is labelled a window at a time and the constrained decoder turns
// those labels into spans. Token spans are then mapped to byte offsets through
// the tokenizer's own offsets -- never computed here -- because only the
// tokenizer knows where a token sits in the text, and a provider inventing
// byte offsets is how a redactor cuts the wrong bytes.
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

	spans, err := p.decodeAll(ctx, toks)
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

// decodeAll labels the whole token sequence, a window at a time, and returns
// the spans in document order.
//
// Windowing is lossless rather than approximate: each window carries
// DefaultOverlap tokens of real context on either side of the region it
// commits, and that overlap is the model's full receptive field, so a
// committed token is labelled exactly as it would be in a single pass. See
// chunk.go for the derivation.
//
// Windows run concurrently when Concurrency is set. ONNX Runtime sessions are
// safe for concurrent Run, and the windows are independent, so this is close
// to free parallelism -- measured about 3x aggregate throughput at 8 workers.
// It is not the default because it multiplies peak memory by the worker count
// and competes with whatever else the daemon is doing while one request waits.
func (p *Provider) decodeAll(ctx context.Context, toks []tokenizer.Token) ([]Span, error) {
	if p.window > modelContextTokens {
		return nil, fmt.Errorf("privacyfilter: window %d exceeds the model's %d-token context", p.window, modelContextTokens)
	}
	wins, err := windowsFor(len(toks), p.window, p.overlap)
	if err != nil {
		return nil, err
	}

	// Results are collected per window and concatenated in window order, so
	// spans come out in document order regardless of which window finished
	// first. Sorting afterwards would work too, but it would hide an
	// ordering bug rather than make one impossible.
	perWindow := make([][]Span, len(wins))

	workers := p.concurrency
	if workers > len(wins) {
		workers = len(wins)
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		next     int32
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt32(&next, 1)) - 1
				if i >= len(wins) {
					return
				}
				mu.Lock()
				stop := firstErr != nil
				mu.Unlock()
				if stop {
					return
				}

				spans, err := p.decodeWindow(ctx, toks, wins[i])
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				if err == nil {
					perWindow[i] = spans
				}
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	var all []Span
	for _, spans := range perWindow {
		all = append(all, spans...)
	}
	return all, nil
}

// decodeWindow labels one window and returns the spans it is responsible for,
// in document-relative token offsets.
func (p *Provider) decodeWindow(ctx context.Context, toks []tokenizer.Token, w window) ([]Span, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	logits, err := p.run(toks[w.start:w.end])
	if err != nil {
		return nil, err
	}
	spans, err := Decode(logits, w.end-w.start, p.cal)
	if err != nil {
		return nil, err
	}

	var out []Span
	for _, s := range spans {
		// Window-relative to document-relative.
		s.Start += w.start
		s.End += w.start

		// Exactly one window commits each token, so a span belongs to the
		// window whose committed region holds its START. Filtering on the
		// whole span instead would drop one that begins inside the region
		// and runs past it, and filtering on overlap would report it twice.
		if s.Start < w.commitStart || s.Start >= w.commitEnd {
			continue
		}
		out = append(out, s)
	}
	return out, nil
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
