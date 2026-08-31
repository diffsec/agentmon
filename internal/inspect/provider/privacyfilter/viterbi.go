package privacyfilter

import (
	"fmt"
	"math"
)

// negInf marks a transition the BIOES grammar forbids. Using a real -Inf
// would make every downstream sum NaN once an all-forbidden column appears;
// a large finite penalty keeps the arithmetic well-behaved while never
// winning against any reachable path.
const negInf = -1e30

// Span is a decoded region of the token sequence.
type Span struct {
	// Category is one of Categories.
	Category string
	// Start and End are TOKEN indices, half-open. They are deliberately not
	// byte offsets: only the tokenizer knows where a token sits in the
	// original text, and a decoder inventing byte offsets is how a redactor
	// ends up cutting the wrong bytes.
	Start, End int
	// Score is the mean probability the model assigned to the labels the
	// decoder chose across the span's tokens.
	//
	// The model card specifies the decoder but not a span-level confidence,
	// so this aggregation is ours. Mean rather than minimum because a long
	// span should not be judged by its weakest token, and rather than the
	// product because that would make score depend on span length.
	Score float64
}

// Decode runs the constrained Viterbi decode over a [numTokens, NumLabels]
// logit grid and returns the spans on the best path.
//
// The constraint is the point. Taking an independent argmax per token
// produces sequences the BIOES grammar forbids -- an I with no B before it,
// a span that begins in one category and ends in another -- and those decode
// into spans whose boundaries are wrong rather than into an obvious error.
// This scores whole label paths instead, so only well-formed sequences are
// reachable.
func Decode(logits []float32, numTokens int, cal Calibration) ([]Span, error) {
	if numTokens < 0 {
		return nil, fmt.Errorf("privacyfilter: negative token count %d", numTokens)
	}
	if numTokens == 0 {
		return nil, nil
	}
	if len(logits) != numTokens*NumLabels {
		return nil, fmt.Errorf("privacyfilter: got %d logits for %d tokens; want %d (%d labels each)",
			len(logits), numTokens, numTokens*NumLabels, NumLabels)
	}

	trans := transitionMatrix(cal)

	// dp[t][l] is the best total score of a valid path ending at token t with
	// label l; back[t][l] is the label at t-1 that achieved it.
	dp := make([][NumLabels]float64, numTokens)
	back := make([][NumLabels]int, numTokens)

	for l := 0; l < NumLabels; l++ {
		if !canStart(l) {
			dp[0][l] = negInf
			continue
		}
		dp[0][l] = float64(logits[l])
	}

	for t := 1; t < numTokens; t++ {
		base := t * NumLabels
		for cur := 0; cur < NumLabels; cur++ {
			best := negInf
			bestPrev := LabelBackground
			for prev := 0; prev < NumLabels; prev++ {
				score := dp[t-1][prev] + trans[prev][cur]
				if score > best {
					best = score
					bestPrev = prev
				}
			}
			dp[t][cur] = best + float64(logits[base+cur])
			back[t][cur] = bestPrev
		}
	}

	// A span cannot be left open at the end of the sequence, so the final
	// token must carry a terminal label.
	last := numTokens - 1
	bestLabel := LabelBackground
	bestScore := negInf
	for l := 0; l < NumLabels; l++ {
		if !canEnd(l) {
			continue
		}
		if dp[last][l] > bestScore {
			bestScore = dp[last][l]
			bestLabel = l
		}
	}

	path := make([]int, numTokens)
	path[last] = bestLabel
	for t := last; t > 0; t-- {
		path[t-1] = back[t][path[t]]
	}

	return spansFromPath(path, logits)
}

// transitionMatrix builds the score added when moving from one label to the
// next. Forbidden moves get negInf, which is what enforces the grammar.
func transitionMatrix(cal Calibration) [NumLabels][NumLabels]float64 {
	var m [NumLabels][NumLabels]float64
	for from := 0; from < NumLabels; from++ {
		for to := 0; to < NumLabels; to++ {
			m[from][to] = transitionScore(from, to, cal)
		}
	}
	return m
}

func transitionScore(from, to int, cal Calibration) float64 {
	fromCat, fromTag, fromBG := DecomposeLabel(from)
	toCat, toTag, toBG := DecomposeLabel(to)

	switch {
	case fromBG:
		// Outside a span: stay outside, or open a new one.
		if toBG {
			return cal.BackgroundStay
		}
		if toTag == TagBegin || toTag == TagSingle {
			return cal.BackgroundToStart
		}
		return negInf

	case fromTag == TagBegin || fromTag == TagInside:
		// Inside an open span: it can only continue or close, and only in
		// the same category. Allowing a category change here is what lets a
		// span start as an email and end as a phone number.
		if toBG || toCat != fromCat {
			return negInf
		}
		if toTag == TagInside {
			return cal.InsideToContinue
		}
		if toTag == TagEnd {
			return cal.InsideToEnd
		}
		return negInf

	default: // TagEnd or TagSingle: the span just closed.
		if toBG {
			return cal.EndToBackground
		}
		if toTag == TagBegin || toTag == TagSingle {
			return cal.EndToStart
		}
		return negInf
	}
}

// canStart reports whether a label may be the first in a sequence. An I or E
// at position zero would continue or close a span that never opened.
func canStart(label int) bool {
	_, tag, bg := DecomposeLabel(label)
	return bg || tag == TagBegin || tag == TagSingle
}

// canEnd reports whether a label may be the last. A B or I at the end leaves
// a span open.
func canEnd(label int) bool {
	_, tag, bg := DecomposeLabel(label)
	return bg || tag == TagEnd || tag == TagSingle
}

// spansFromPath walks a decoded label path and collects its spans.
//
// The path is grammatically valid by construction, so an unopened E or an
// unclosed B here means the decoder itself is wrong. It returns an error
// rather than skipping, because a decoder emitting malformed paths would
// otherwise show up as occasional missing spans.
func spansFromPath(path []int, logits []float32) ([]Span, error) {
	var spans []Span
	open := -1
	openCat := 0

	for t, label := range path {
		cat, tag, bg := DecomposeLabel(label)
		switch {
		case bg:
			if open >= 0 {
				return nil, fmt.Errorf("privacyfilter: decoder left a span open at token %d", t)
			}
		case tag == TagSingle:
			if open >= 0 {
				return nil, fmt.Errorf("privacyfilter: decoder started a span at token %d inside another", t)
			}
			spans = append(spans, Span{
				Category: Categories[cat],
				Start:    t,
				End:      t + 1,
				Score:    meanProbability(logits, path, t, t+1),
			})
		case tag == TagBegin:
			if open >= 0 {
				return nil, fmt.Errorf("privacyfilter: decoder started a span at token %d inside another", t)
			}
			open, openCat = t, cat
		case tag == TagInside:
			if open < 0 || cat != openCat {
				return nil, fmt.Errorf("privacyfilter: decoder continued an unopened span at token %d", t)
			}
		case tag == TagEnd:
			if open < 0 || cat != openCat {
				return nil, fmt.Errorf("privacyfilter: decoder closed an unopened span at token %d", t)
			}
			spans = append(spans, Span{
				Category: Categories[openCat],
				Start:    open,
				End:      t + 1,
				Score:    meanProbability(logits, path, open, t+1),
			})
			open = -1
		}
	}
	if open >= 0 {
		return nil, fmt.Errorf("privacyfilter: decoder left a span open at the end of the sequence")
	}
	return spans, nil
}

// meanProbability is the mean softmax probability of the chosen labels over
// [start, end).
func meanProbability(logits []float32, path []int, start, end int) float64 {
	if end <= start {
		return 0
	}
	total := 0.0
	for t := start; t < end; t++ {
		total += softmaxAt(logits[t*NumLabels:(t+1)*NumLabels], path[t])
	}
	return total / float64(end-start)
}

// softmaxAt returns the probability of one label within a token's row,
// computed with the max subtracted so a large logit cannot overflow.
func softmaxAt(row []float32, label int) float64 {
	max := float64(row[0])
	for _, v := range row {
		if float64(v) > max {
			max = float64(v)
		}
	}
	sum := 0.0
	for _, v := range row {
		sum += math.Exp(float64(v) - max)
	}
	if sum == 0 {
		return 0
	}
	return math.Exp(float64(row[label])-max) / sum
}
