package privacyfilter

import (
	"fmt"
	"testing"
)

// TestWindowsFor_CommittedRegionsTileExactly is the property everything else
// rests on.
//
// If the committed regions leave a gap, tokens in it are labelled by no window
// and any PII there is silently missed. If they overlap, a span is reported
// twice and the redactor rewrites the same bytes twice, corrupting offsets
// after the first. Both fail quietly, which is why this sweeps rather than
// spot-checks.
func TestWindowsFor_CommittedRegionsTileExactly(t *testing.T) {
	for _, size := range []int{16, 64, 4096} {
		for _, overlap := range []int{1, 4, 7} {
			if size <= 2*overlap {
				continue
			}
			for n := 1; n <= 4*size; n++ {
				wins, err := windowsFor(n, size, overlap)
				if err != nil {
					t.Fatalf("n=%d size=%d overlap=%d: %v", n, size, overlap, err)
				}
				if len(wins) == 0 {
					t.Fatalf("n=%d size=%d overlap=%d: no windows", n, size, overlap)
				}

				at := 0
				for i, w := range wins {
					if w.commitStart != at {
						t.Fatalf("n=%d size=%d overlap=%d: window %d commits from %d, expected %d",
							n, size, overlap, i, w.commitStart, at)
					}
					if w.commitEnd <= w.commitStart {
						t.Fatalf("n=%d size=%d overlap=%d: window %d commits an empty range [%d,%d)",
							n, size, overlap, i, w.commitStart, w.commitEnd)
					}
					at = w.commitEnd
				}
				if at != n {
					t.Fatalf("n=%d size=%d overlap=%d: committed regions cover %d tokens, want %d",
						n, size, overlap, at, n)
				}
			}
		}
	}
}

// TestWindowsFor_CommittedRegionIsInsideItsWindow. A window can only label
// tokens it was fed, so committing outside the fed range would index logits
// that do not exist.
func TestWindowsFor_CommittedRegionIsInsideItsWindow(t *testing.T) {
	for _, size := range []int{16, 64, 512} {
		for _, overlap := range []int{1, 4, 7} {
			if size <= 2*overlap {
				continue
			}
			for n := 1; n <= 3*size; n++ {
				wins, _ := windowsFor(n, size, overlap)
				for i, w := range wins {
					if w.start < 0 || w.end > n || w.end <= w.start {
						t.Fatalf("n=%d: window %d is [%d,%d)", n, i, w.start, w.end)
					}
					if w.end-w.start > size {
						t.Fatalf("n=%d: window %d feeds %d tokens, over the %d limit", n, i, w.end-w.start, size)
					}
					if w.commitStart < w.start || w.commitEnd > w.end {
						t.Fatalf("n=%d: window %d commits [%d,%d) outside its range [%d,%d)",
							n, i, w.commitStart, w.commitEnd, w.start, w.end)
					}
				}
			}
		}
	}
}

// TestWindowsFor_CarriesTheFullReceptiveField is what makes chunking lossless
// rather than an approximation.
//
// A committed token needs the model's whole receptive field on each side --
// 1024 tokens, from 8 layers of 128-token banded attention -- to be labelled
// exactly as a single full-document pass would label it. Less context than
// that and the answer merely looks plausible.
//
// The document's own ends are the exception: there is nothing to carry there,
// and a full pass would have nothing either.
func TestWindowsFor_CarriesTheFullReceptiveField(t *testing.T) {
	const size, overlap = 64, 8

	for n := 1; n <= 5*size; n++ {
		wins, _ := windowsFor(n, size, overlap)
		for i, w := range wins {
			if w.commitStart > 0 && w.contextBefore() < overlap {
				t.Fatalf("n=%d: window %d has %d tokens of context before its committed region, want %d",
					n, i, w.contextBefore(), overlap)
			}
			if w.commitEnd < n && w.contextAfter() < overlap {
				t.Fatalf("n=%d: window %d has %d tokens of context after its committed region, want %d",
					n, i, w.contextAfter(), overlap)
			}
		}
	}
}

// TestWindowsFor_ShortInputTakesTheSinglePassPath. Content that fits must go
// through unchanged, so chunking cannot regress what already worked.
func TestWindowsFor_ShortInputTakesTheSinglePassPath(t *testing.T) {
	for _, n := range []int{1, 2, 100, 4096} {
		wins, err := windowsFor(n, 4096, 1024)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(wins) != 1 {
			t.Errorf("n=%d produced %d windows, want 1", n, len(wins))
			continue
		}
		w := wins[0]
		if w.start != 0 || w.end != n || w.commitStart != 0 || w.commitEnd != n {
			t.Errorf("n=%d: window is %+v, want the whole document", n, w)
		}
	}
}

// TestWindowsFor_RejectsAWindowThatCannotAdvance. A stride of zero would loop
// forever; refusing beats hanging a request, and the configuration that gets
// here is a startup mistake.
func TestWindowsFor_RejectsAWindowThatCannotAdvance(t *testing.T) {
	for _, c := range []struct{ size, overlap int }{
		{100, 50}, {100, 60}, {10, 5}, {1, 1},
	} {
		if _, err := windowsFor(1000, c.size, c.overlap); err == nil {
			t.Errorf("size=%d overlap=%d was accepted; stride would be <= 0", c.size, c.overlap)
		}
	}
	if _, err := windowsFor(1000, 100, -1); err == nil {
		t.Error("a negative overlap was accepted")
	}
	if wins, err := windowsFor(0, 100, 10); err != nil || wins != nil {
		t.Errorf("n=0 gave (%v, %v), want (nil, nil)", wins, err)
	}
}

// TestWindowsFor_WindowCountIsReasonable guards against a stride so small the
// document is re-scanned many times over. At the shipped settings a 100k-token
// document should need tens of passes, not thousands.
func TestWindowsFor_WindowCountIsReasonable(t *testing.T) {
	const n = 100000
	wins, err := windowsFor(n, DefaultWindow, DefaultOverlap)
	if err != nil {
		t.Fatal(err)
	}

	stride := DefaultWindow - 2*DefaultOverlap
	want := (n + stride - 1) / stride
	if len(wins) > want+1 {
		t.Errorf("got %d windows for %d tokens, want about %d", len(wins), n, want)
	}

	fed := 0
	for _, w := range wins {
		fed += w.end - w.start
	}
	// Overlap is recomputed work. At 4096/1024 that is a 2x tax, which is
	// the price of losslessness; anything much worse means the stride is
	// wrong.
	if ratio := float64(fed) / float64(n); ratio > 2.5 {
		t.Errorf("windows feed %.2fx the document (%d of %d tokens)", ratio, fed, n)
	}
	t.Logf("%d tokens -> %d windows, feeding %.2fx the document", n, len(wins), float64(fed)/float64(n))
}

// TestDefaultOverlapMatchesTheModel pins the derivation. The overlap is not a
// tuning knob: it is the model's receptive field, and a value below it makes
// chunking lossy in a way no test of the output would obviously catch.
func TestDefaultOverlapMatchesTheModel(t *testing.T) {
	if got := modelSlidingWindow * modelLayers; got != DefaultOverlap {
		t.Fatalf("DefaultOverlap is %d but the model's receptive field is %d (%d layers x %d band)",
			DefaultOverlap, got, modelLayers, modelSlidingWindow)
	}
	if DefaultWindow <= 2*DefaultOverlap {
		t.Fatalf("DefaultWindow %d must exceed twice DefaultOverlap %d, or the stride is not positive",
			DefaultWindow, DefaultOverlap)
	}
}

func TestWindowsFor_Examples(t *testing.T) {
	wins, err := windowsFor(30, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, w := range wins {
		got = append(got, fmt.Sprintf("feed[%d,%d) commit[%d,%d)", w.start, w.end, w.commitStart, w.commitEnd))
	}
	t.Logf("n=30 size=10 overlap=2:")
	for _, g := range got {
		t.Logf("  %s", g)
	}

	at := 0
	for _, w := range wins {
		if w.commitStart != at {
			t.Fatalf("gap or overlap at %d", at)
		}
		at = w.commitEnd
	}
	if at != 30 {
		t.Fatalf("covered %d of 30", at)
	}
}

// TestMaxConcurrencyIsBounded. Each worker holds its own activations for a
// 917MB model, so the failure mode of an over-large value is not a slow
// request but the daemon being killed — measured: twelve workers were.
func TestMaxConcurrencyIsBounded(t *testing.T) {
	if MaxConcurrency < 1 {
		t.Fatalf("MaxConcurrency = %d, must allow at least one window", MaxConcurrency)
	}
	if MaxConcurrency > 8 {
		t.Errorf("MaxConcurrency = %d; measurement showed throughput collapsing past 4 and the process killed at 12", MaxConcurrency)
	}
}
