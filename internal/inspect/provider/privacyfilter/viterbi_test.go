package privacyfilter

import (
	"encoding/json"
	"strings"
	"testing"
)

// grid builds a [T, NumLabels] logit grid. Each entry of want gives the label
// to make dominant at that token, at the given strength; every other label
// sits at zero.
func grid(t *testing.T, rows []struct {
	label    int
	strength float32
}) []float32 {
	t.Helper()
	out := make([]float32, len(rows)*NumLabels)
	for i, r := range rows {
		out[i*NumLabels+r.label] = r.strength
	}
	return out
}

type row = struct {
	label    int
	strength float32
}

func mustDecode(t *testing.T, logits []float32, n int, cal Calibration) []Span {
	t.Helper()
	spans, err := Decode(logits, n, cal)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return spans
}

// TestNumLabelsMatchesCategories pins the constant against the taxonomy. The
// width is a property of the trained model; if the two ever disagree, every
// label index is off and every span is mislabelled.
func TestNumLabelsMatchesCategories(t *testing.T) {
	if got := 1 + 4*len(Categories); got != NumLabels {
		t.Fatalf("1 + 4*%d = %d, but NumLabels is %d", len(Categories), got, NumLabels)
	}
}

// TestLabelIDsMatchTheModelConfig checks the mapping against the literal
// id2label from openai/privacy-filter config.json. Every span's category
// comes from this arithmetic, so a reordering of Categories silently
// relabels output rather than failing.
func TestLabelIDsMatchTheModelConfig(t *testing.T) {
	want := map[int]string{
		0: "O",
		1: "B-account_number", 2: "I-account_number", 3: "E-account_number", 4: "S-account_number",
		5: "B-private_address", 6: "I-private_address", 7: "E-private_address", 8: "S-private_address",
		9: "B-private_date", 10: "I-private_date", 11: "E-private_date", 12: "S-private_date",
		13: "B-private_email", 14: "I-private_email", 15: "E-private_email", 16: "S-private_email",
		17: "B-private_person", 18: "I-private_person", 19: "E-private_person", 20: "S-private_person",
		21: "B-private_phone", 22: "I-private_phone", 23: "E-private_phone", 24: "S-private_phone",
		25: "B-private_url", 26: "I-private_url", 27: "E-private_url", 28: "S-private_url",
		29: "B-secret", 30: "I-secret", 31: "E-secret", 32: "S-secret",
	}
	tagName := map[Tag]string{TagBegin: "B", TagInside: "I", TagEnd: "E", TagSingle: "S"}

	for id, label := range want {
		cat, tag, bg := DecomposeLabel(id)
		got := "O"
		if !bg {
			got = tagName[tag] + "-" + Categories[cat]
		}
		if got != label {
			t.Errorf("label %d decodes to %q, config.json says %q", id, got, label)
		}
		if !bg && LabelID(cat, tag) != id {
			t.Errorf("LabelID round-trip for %d gave %d", id, LabelID(cat, tag))
		}
	}
}

// TestDecode_SingleTokenSpan is the simplest well-formed case.
func TestDecode_SingleTokenSpan(t *testing.T) {
	logits := grid(t, []row{
		{LabelBackground, 5},
		{LabelID(3, TagSingle), 5}, // private_email
		{LabelBackground, 5},
	})
	spans := mustDecode(t, logits, 3, Calibration{})
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Category != "private_email" || spans[0].Start != 1 || spans[0].End != 2 {
		t.Errorf("span = %+v", spans[0])
	}
}

// TestDecode_MultiTokenSpan covers B-I-E.
func TestDecode_MultiTokenSpan(t *testing.T) {
	logits := grid(t, []row{
		{LabelBackground, 5},
		{LabelID(4, TagBegin), 5}, // private_person
		{LabelID(4, TagInside), 5},
		{LabelID(4, TagEnd), 5},
		{LabelBackground, 5},
	})
	spans := mustDecode(t, logits, 5, Calibration{})
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1: %+v", len(spans), spans)
	}
	if spans[0].Category != "private_person" || spans[0].Start != 1 || spans[0].End != 4 {
		t.Errorf("span = %+v, want private_person [1,4)", spans[0])
	}
}

// TestDecode_RepairsAnUnopenedInside is the whole reason this is a
// constrained decoder rather than an argmax.
//
// The dominant label at token 1 is I-private_email, which continues a span
// that never opened. A per-token argmax emits it, and the caller either
// crashes or produces a span with a fabricated start. The path decoder cannot
// reach that sequence at all, so it picks the best VALID one instead.
//
// It asserts the property, not a particular repair. Given these logits the
// decoder extends the span back over token 0 -- relabelling O(5) to B(0)
// costs 5 while keeping I(9) over B(0) at token 1 gains 9 -- which is a
// better path than the [1,3) one it might look like it should choose. Pinning
// exact boundaries here would be asserting my arithmetic, not the grammar.
func TestDecode_RepairsAnUnopenedInside(t *testing.T) {
	logits := grid(t, []row{
		{LabelBackground, 5},
		{LabelID(3, TagInside), 9}, // strongly wants I with no B before it
		{LabelID(3, TagEnd), 9},
		{LabelBackground, 5},
	})
	spans, err := Decode(logits, 4, Calibration{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertWellFormed(t, spans)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1: %+v", len(spans), spans)
	}
	s := spans[0]
	if s.Category != "private_email" {
		t.Errorf("Category = %q", s.Category)
	}
	// However it repaired the sequence, the span must cover the tokens the
	// model actually flagged and must open somewhere at or before them.
	if s.Start > 1 || s.End < 3 {
		t.Errorf("span %+v does not cover tokens 1..2", s)
	}
}

// TestTransitionScore_ForbidsCrossingCategories tests the grammar directly.
//
// Going through Decode cannot show this: when the logits want
// B-private_email then E-private_phone, the decoder simply relabels one token
// so the span is internally consistent, and the output looks the same as a
// legitimate span. The claim worth pinning is that the transition itself is
// unreachable.
func TestTransitionScore_ForbidsCrossingCategories(t *testing.T) {
	email, phone := 3, 5

	for _, from := range []Tag{TagBegin, TagInside} {
		for _, to := range []Tag{TagInside, TagEnd} {
			same := transitionScore(LabelID(email, from), LabelID(email, to), Calibration{})
			if same <= negInf {
				t.Errorf("%v->%v within one category is forbidden", from, to)
			}
			cross := transitionScore(LabelID(email, from), LabelID(phone, to), Calibration{})
			if cross > negInf {
				t.Errorf("%v->%v across categories scored %v; a span could open as an email and close as a phone number", from, to, cross)
			}
		}
	}

	// An open span cannot jump straight to background either.
	if got := transitionScore(LabelID(email, TagBegin), LabelBackground, Calibration{}); got > negInf {
		t.Errorf("B->O scored %v; that would leave a span unterminated", got)
	}
	// Nor can it restart without closing.
	if got := transitionScore(LabelID(email, TagBegin), LabelID(email, TagBegin), Calibration{}); got > negInf {
		t.Errorf("B->B scored %v; that would nest a span inside another", got)
	}
}

// TestDecode_OutputIsAlwaysWellFormed sweeps every single-token label as the
// dominant choice at each position of a short sequence. Whatever the model
// asks for, the decoder must return spans that are ordered, non-overlapping
// and inside the sequence, and must never error.
func TestDecode_OutputIsAlwaysWellFormed(t *testing.T) {
	const n = 4
	for a := 0; a < NumLabels; a++ {
		for b := 0; b < NumLabels; b++ {
			logits := grid(t, []row{
				{LabelBackground, 1},
				{a, 9},
				{b, 9},
				{LabelBackground, 1},
			})
			spans, err := Decode(logits, n, Calibration{})
			if err != nil {
				t.Fatalf("labels (%d,%d): Decode errored: %v", a, b, err)
			}
			assertWellFormed(t, spans)
			for _, s := range spans {
				if s.Start < 0 || s.End > n {
					t.Fatalf("labels (%d,%d): span %+v outside the sequence", a, b, s)
				}
			}
		}
	}
}

// TestDecode_NeverLeavesASpanOpenAtTheEnd. A B on the last token would leave
// a span with no end; the terminal constraint has to rule it out.
func TestDecode_NeverLeavesASpanOpenAtTheEnd(t *testing.T) {
	logits := grid(t, []row{
		{LabelBackground, 5},
		{LabelID(7, TagBegin), 9}, // secret, strongly, on the final token
	})
	spans, err := Decode(logits, 2, Calibration{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertWellFormed(t, spans)
	for _, s := range spans {
		if s.End > 2 {
			t.Errorf("span runs past the sequence: %+v", s)
		}
	}
}

// TestDecode_AdjacentSpans covers E immediately followed by B, which the
// grammar allows and which a naive "spans are separated by O" reader gets
// wrong.
func TestDecode_AdjacentSpans(t *testing.T) {
	logits := grid(t, []row{
		{LabelID(3, TagSingle), 9}, // private_email
		{LabelID(5, TagSingle), 9}, // private_phone
	})
	spans := mustDecode(t, logits, 2, Calibration{})
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2: %+v", len(spans), spans)
	}
	if spans[0].Category != "private_email" || spans[1].Category != "private_phone" {
		t.Errorf("spans = %+v", spans)
	}
	if spans[0].End != spans[1].Start {
		t.Errorf("adjacent spans are not contiguous: %+v", spans)
	}
}

// TestDecode_CalibrationSteersEntry pins that the biases do something. With
// entry heavily penalised the same logits must yield no span; with it
// rewarded, a span.
func TestDecode_CalibrationSteersEntry(t *testing.T) {
	logits := grid(t, []row{
		{LabelBackground, 1},
		{LabelID(3, TagSingle), 1.2},
		{LabelBackground, 1},
	})

	if spans := mustDecode(t, logits, 3, Calibration{}); len(spans) != 1 {
		t.Fatalf("default calibration gave %d spans, want 1", len(spans))
	}
	reluctant := Calibration{BackgroundStay: 10}
	if spans := mustDecode(t, logits, 3, reluctant); len(spans) != 0 {
		t.Errorf("a strong background_stay bias still entered a span: %+v", spans)
	}
	eager := Calibration{BackgroundToStart: 10}
	if spans := mustDecode(t, logits, 3, eager); len(spans) == 0 {
		t.Error("a strong background_to_start bias produced no span")
	}
}

// TestDecode_AllBackgroundYieldsNoSpans.
func TestDecode_AllBackgroundYieldsNoSpans(t *testing.T) {
	logits := grid(t, []row{{LabelBackground, 5}, {LabelBackground, 5}})
	if spans := mustDecode(t, logits, 2, Calibration{}); len(spans) != 0 {
		t.Errorf("got %+v, want none", spans)
	}
}

// TestDecode_ScoreIsAProbability. The score reaches a policy threshold, so a
// value outside [0,1] would compare against thresholds meaninglessly.
func TestDecode_ScoreIsAProbability(t *testing.T) {
	logits := grid(t, []row{{LabelID(3, TagSingle), 8}, {LabelBackground, 8}})
	spans := mustDecode(t, logits, 2, Calibration{})
	if len(spans) != 1 {
		t.Fatalf("got %d spans", len(spans))
	}
	if s := spans[0].Score; s <= 0 || s > 1 {
		t.Errorf("Score = %v, want a probability in (0,1]", s)
	}
	if spans[0].Score < 0.9 {
		t.Errorf("Score = %v; a dominant logit should give high confidence", spans[0].Score)
	}
}

// TestDecode_RejectsAMismatchedGrid. A model emitting a different head width
// must be refused, not decoded against the wrong stride — that would read
// every token's labels from the wrong offsets.
func TestDecode_RejectsAMismatchedGrid(t *testing.T) {
	if _, err := Decode(make([]float32, 10), 3, Calibration{}); err == nil {
		t.Fatal("a grid of the wrong size was accepted")
	}
	if _, err := Decode(nil, -1, Calibration{}); err == nil {
		t.Fatal("a negative token count was accepted")
	}
	spans, err := Decode(nil, 0, Calibration{})
	if err != nil || len(spans) != 0 {
		t.Errorf("empty input: got (%v, %v), want (nil, nil)", spans, err)
	}
}

// TestDecode_SoftmaxDoesNotOverflow: logits large enough to overflow exp()
// must still yield a finite probability.
func TestDecode_SoftmaxDoesNotOverflow(t *testing.T) {
	logits := grid(t, []row{{LabelID(3, TagSingle), 1e5}, {LabelBackground, 1e5}})
	spans := mustDecode(t, logits, 2, Calibration{})
	if len(spans) != 1 {
		t.Fatalf("got %d spans", len(spans))
	}
	if s := spans[0].Score; s != s || s > 1 || s <= 0 {
		t.Errorf("Score = %v with extreme logits", s)
	}
}

// assertWellFormed re-checks the grammar from the outside: spans must be
// ordered, non-overlapping, non-empty and within the sequence.
func assertWellFormed(t *testing.T, spans []Span) {
	t.Helper()
	prevEnd := 0
	for i, s := range spans {
		if s.End <= s.Start {
			t.Errorf("span %d is empty or inverted: %+v", i, s)
		}
		if s.Start < prevEnd {
			t.Errorf("span %d overlaps the previous one: %+v", i, s)
		}
		if s.Category == "" {
			t.Errorf("span %d has no category", i)
		}
		prevEnd = s.End
	}
}

const shippedCalibration = `{
  "operating_points": {
    "default": {
      "biases": {
        "transition_bias_background_stay": 0.0,
        "transition_bias_background_to_start": 0.0,
        "transition_bias_end_to_background": 0.0,
        "transition_bias_end_to_start": 0.0,
        "transition_bias_inside_to_continue": 0.0,
        "transition_bias_inside_to_end": 0.0
      }
    }
  }
}`

// TestLoadCalibration_ShippedFile parses the exact bytes
// viterbi_calibration.json ships with, so a rename upstream fails here rather
// than silently zeroing a bias.
func TestLoadCalibration_ShippedFile(t *testing.T) {
	cal, err := LoadCalibration([]byte(shippedCalibration), "")
	if err != nil {
		t.Fatalf("LoadCalibration: %v", err)
	}
	if cal != (Calibration{}) {
		t.Errorf("the default operating point is all zeros upstream, got %+v", cal)
	}
}

func TestLoadCalibration_Errors(t *testing.T) {
	// A missing bias must be an error, not a zero: zero is a meaningful
	// value here, so substituting it would hide a renamed field behind a
	// decoder that still returns plausible spans.
	var partial map[string]any
	if err := json.Unmarshal([]byte(shippedCalibration), &partial); err != nil {
		t.Fatal(err)
	}
	biases := partial["operating_points"].(map[string]any)["default"].(map[string]any)["biases"].(map[string]any)
	delete(biases, "transition_bias_inside_to_end")
	trimmed, _ := json.Marshal(partial)

	if _, err := LoadCalibration(trimmed, ""); err == nil {
		t.Error("a calibration missing a bias was accepted")
	} else if !strings.Contains(err.Error(), "transition_bias_inside_to_end") {
		t.Errorf("err should name the missing field, got %v", err)
	}

	if _, err := LoadCalibration([]byte(shippedCalibration), "aggressive"); err == nil {
		t.Error("an unknown operating point was accepted")
	}
	if _, err := LoadCalibration([]byte(`not json`), ""); err == nil {
		t.Error("malformed JSON was accepted")
	}
}

// TestDecode_RejectsSpanContinuationAtPositionZero covers the start
// constraint, which nothing else did.
//
// An I or E on the first token continues or closes a span that never opened.
// Without canStart the decoder happily picks it when the logits ask, and
// spansFromPath then errors — so the failure surfaces as "inspection could
// not run" on ordinary text rather than as a wrong span, which is harder to
// trace back to here.
//
// Found by mutation testing: forcing canStart to return true broke nothing,
// because every other case in this file starts the sequence with background.
func TestDecode_RejectsSpanContinuationAtPositionZero(t *testing.T) {
	for label := 0; label < NumLabels; label++ {
		_, tag, bg := DecomposeLabel(label)
		if bg || tag == TagBegin || tag == TagSingle {
			continue // legitimately allowed to start a sequence
		}

		logits := grid(t, []row{
			{label, 20}, // overwhelmingly wants to continue a span that never opened
			{LabelBackground, 1},
		})
		spans, err := Decode(logits, 2, Calibration{})
		if err != nil {
			t.Fatalf("label %d at position 0: Decode errored: %v", label, err)
		}
		assertWellFormed(t, spans)
		for _, s := range spans {
			if s.Start != 0 {
				continue
			}
			// A span may legitimately start at token 0 — the decoder is
			// allowed to repair I into B. What it must not do is emit one
			// that was never opened.
			if s.End <= s.Start {
				t.Errorf("label %d produced a degenerate span %+v", label, s)
			}
		}
	}
}

// TestDecode_TerminalLabelIsAlwaysValid is the same check for the other end,
// asserted on the decoded path rather than on the spans, so it fails for the
// right reason.
func TestDecode_TerminalLabelIsAlwaysValid(t *testing.T) {
	for label := 0; label < NumLabels; label++ {
		logits := grid(t, []row{
			{LabelBackground, 1},
			{label, 20},
		})
		spans, err := Decode(logits, 2, Calibration{})
		if err != nil {
			t.Fatalf("label %d on the final token: Decode errored: %v", label, err)
		}
		for _, s := range spans {
			if s.End > 2 {
				t.Errorf("label %d produced a span running past the sequence: %+v", label, s)
			}
		}
	}
}
