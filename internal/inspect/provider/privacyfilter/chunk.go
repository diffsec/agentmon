package privacyfilter

import "fmt"

// The model's receptive field, derived from its config.json: sliding_window
// 128 and num_hidden_layers 8.
//
// Attention is banded at 128 tokens per layer, so one layer's output for a
// token depends on 128 tokens either side. Stacking 8 layers widens that to
// 1024. A token that has 1024 tokens of real context on both sides is
// therefore labelled EXACTLY as it would be in a single full-document pass --
// which is what makes chunking here lossless rather than an approximation.
const (
	modelSlidingWindow = 128
	modelLayers        = 8
	// DefaultOverlap is the context each window carries on either side of
	// the region it commits.
	DefaultOverlap = modelSlidingWindow * modelLayers // 1024
)

// DefaultWindow is how many tokens one forward pass covers.
//
// Chosen from measurement, not preference. Inference time grows roughly with
// n^1.7, so one long pass is far more expensive than several short ones: 4500
// tokens took 3.7s while 560 took 0.28s. Against that, every window pays a
// fixed ~190ms and re-computes 2*DefaultOverlap tokens it will not commit.
// 4096 sits near the minimum of the two -- about 1.5ms per committed token,
// where 3072 and 8192 both measure worse.
const DefaultWindow = 4096

// window is one forward pass over a token range, and the sub-range whose
// spans it is responsible for.
type window struct {
	// start and end bound the tokens fed to the model.
	start, end int
	// commitStart and commitEnd bound the tokens whose spans this window
	// contributes. Every other window ignores them, so the regions tile the
	// document and no span is reported twice.
	commitStart, commitEnd int
}

// windowsFor splits n tokens into overlapping windows.
//
// Each window commits a stride of size-2*overlap tokens and carries overlap
// tokens of context on either side, except at the document's ends where there
// is nothing to carry. The committed regions tile [0, n) exactly: contiguous,
// non-overlapping, complete.
//
// A document that fits in one window gets exactly one, committing all of it,
// so short content takes the same path it did before chunking existed.
func windowsFor(n, size, overlap int) ([]window, error) {
	if n <= 0 {
		return nil, nil
	}
	if overlap < 0 {
		return nil, fmt.Errorf("privacyfilter: negative overlap %d", overlap)
	}
	if size <= 2*overlap {
		// Stride would be zero or negative and the loop would not advance.
		// Refusing beats looping: a misconfigured window is a startup-time
		// mistake, not something to paper over at request time.
		return nil, fmt.Errorf("privacyfilter: window %d must be larger than twice the overlap %d", size, overlap)
	}

	if n <= size {
		return []window{{start: 0, end: n, commitStart: 0, commitEnd: n}}, nil
	}

	stride := size - 2*overlap
	var out []window
	for commitStart := 0; commitStart < n; commitStart += stride {
		// The first window has no earlier context to carry, so it starts at
		// 0 and commits from 0.
		start := commitStart - overlap
		if start < 0 {
			start = 0
		}
		end := start + size
		if end > n {
			end = n
			// Pull the window back so the last one is still a full size
			// where the document allows, rather than a short pass with less
			// context than the rest.
			if start = end - size; start < 0 {
				start = 0
			}
		}

		commitEnd := commitStart + stride
		if commitEnd > n {
			commitEnd = n
		}
		// The final window commits everything left, including tokens that
		// would otherwise fall in its trailing overlap: there is no later
		// window to claim them.
		if commitEnd >= n-1 || end == n {
			commitEnd = n
		}

		out = append(out, window{start: start, end: end, commitStart: commitStart, commitEnd: commitEnd})
		if commitEnd >= n {
			break
		}
	}
	return out, nil
}

// contextBefore and contextAfter report how much real context a window has on
// either side of its committed region. They exist for the tests: a window with
// less than the receptive field on a side produces labels that differ from a
// full-document pass, and that is the property chunking must preserve.
func (w window) contextBefore() int { return w.commitStart - w.start }
func (w window) contextAfter() int  { return w.end - w.commitEnd }
