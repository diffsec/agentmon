// Package privacyfilter decodes OpenAI Privacy Filter output into spans.
//
// The model is a bidirectional token classifier, not a generator: one forward
// pass emits [T, 33] logits, and the spans come from decoding that grid. This
// package owns the decode half, which is fully specified by the model card and
// needs no inference runtime -- so it is testable, and tested, without a model
// present.
package privacyfilter

import (
	"encoding/json"
	"fmt"
)

// Categories are the eight privacy span labels, in the exact order the
// model's config.json assigns them. The order is load-bearing: label IDs are
// computed from it, so a re-ordering here silently relabels every span.
//
// Taken verbatim from openai/privacy-filter config.json id2label.
var Categories = []string{
	"account_number",
	"private_address",
	"private_date",
	"private_email",
	"private_person",
	"private_phone",
	"private_url",
	"secret",
}

// NumLabels is the width of the model's output head: one background class
// plus four BIOES tags for each of the eight categories.
//
// Pinned as a literal because it is a property of the trained model, not of
// this slice: a model emitting a different width must be rejected, not
// accommodated. TestNumLabelsMatchesCategories keeps the two in step.
const NumLabels = 33

// Tag identifies a token's position within a span.
type Tag int

// BIOES tags, in the order config.json interleaves them after the background
// class: B, I, E, S for each category.
const (
	TagBegin Tag = iota
	TagInside
	TagEnd
	TagSingle
)

// LabelBackground is the "O" class.
const LabelBackground = 0

// LabelID returns the model's output index for a category and tag.
func LabelID(category int, tag Tag) int {
	return 1 + 4*category + int(tag)
}

// DecomposeLabel splits a model output index into its category and tag.
// background is true for "O", in which case category and tag are meaningless.
func DecomposeLabel(label int) (category int, tag Tag, background bool) {
	if label == LabelBackground {
		return 0, 0, true
	}
	label--
	return label / 4, Tag(label % 4), false
}

// Calibration holds the six transition biases that steer the decoder between
// precision and recall.
//
// The model ships them in viterbi_calibration.json under a named operating
// point, all zero in the "default" point. They are additive scores on
// transitions, so zero means "decide from the logits alone".
type Calibration struct {
	// BackgroundStay biases staying outside any span (O to O). Raising it
	// makes the decoder more reluctant to enter a span at all.
	BackgroundStay float64
	// BackgroundToStart biases entering a span (O to B or O to S).
	BackgroundToStart float64
	// EndToBackground biases leaving a span (E or S to O).
	EndToBackground float64
	// EndToStart biases one span abutting the next (E or S to B or S).
	EndToStart float64
	// InsideToContinue biases extending a span (B or I to I).
	InsideToContinue float64
	// InsideToEnd biases closing a span (B or I to E).
	InsideToEnd float64
}

// calibrationFile mirrors viterbi_calibration.json.
type calibrationFile struct {
	OperatingPoints map[string]struct {
		Biases struct {
			BackgroundStay    *float64 `json:"transition_bias_background_stay"`
			BackgroundToStart *float64 `json:"transition_bias_background_to_start"`
			EndToBackground   *float64 `json:"transition_bias_end_to_background"`
			EndToStart        *float64 `json:"transition_bias_end_to_start"`
			InsideToContinue  *float64 `json:"transition_bias_inside_to_continue"`
			InsideToEnd       *float64 `json:"transition_bias_inside_to_end"`
		} `json:"biases"`
	} `json:"operating_points"`
}

// LoadCalibration reads viterbi_calibration.json and returns the named
// operating point. An empty name selects "default".
//
// A missing bias is an error rather than a zero, because zero is a
// meaningful value here -- "decide from the logits" -- and silently
// substituting it for "the file did not say" would hide a renamed field
// behind a decoder that still returns plausible spans.
func LoadCalibration(data []byte, point string) (Calibration, error) {
	if point == "" {
		point = "default"
	}
	var f calibrationFile
	if err := json.Unmarshal(data, &f); err != nil {
		return Calibration{}, fmt.Errorf("privacyfilter: parsing calibration: %w", err)
	}
	op, ok := f.OperatingPoints[point]
	if !ok {
		return Calibration{}, fmt.Errorf("privacyfilter: calibration has no operating point %q", point)
	}

	b := op.Biases
	fields := []struct {
		name string
		val  *float64
	}{
		{"transition_bias_background_stay", b.BackgroundStay},
		{"transition_bias_background_to_start", b.BackgroundToStart},
		{"transition_bias_end_to_background", b.EndToBackground},
		{"transition_bias_end_to_start", b.EndToStart},
		{"transition_bias_inside_to_continue", b.InsideToContinue},
		{"transition_bias_inside_to_end", b.InsideToEnd},
	}
	for _, f := range fields {
		if f.val == nil {
			return Calibration{}, fmt.Errorf("privacyfilter: operating point %q is missing %s", point, f.name)
		}
	}

	return Calibration{
		BackgroundStay:    *b.BackgroundStay,
		BackgroundToStart: *b.BackgroundToStart,
		EndToBackground:   *b.EndToBackground,
		EndToStart:        *b.EndToStart,
		InsideToContinue:  *b.InsideToContinue,
		InsideToEnd:       *b.InsideToEnd,
	}, nil
}
