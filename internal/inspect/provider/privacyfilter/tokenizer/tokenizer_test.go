package tokenizer_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter/tokenizer"
)

// TokenizerEnv names the environment variable holding a path to the model's
// tokenizer.json. It is 27.8MB, far too large to commit, so the tests that
// need it skip without it.
const TokenizerEnv = "AGENTMON_PRIVACY_FILTER_TOKENIZER"

type fixtureFile struct {
	Cases []struct {
		Group string  `json:"group"`
		Text  string  `json:"text"`
		IDs   []int32 `json:"ids"`
	} `json:"cases"`
}

func loadFixtures(t *testing.T) fixtureFile {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var f fixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("fixtures are empty")
	}
	return f
}

func loadTokenizer(t *testing.T) *tokenizer.Tokenizer {
	t.Helper()
	path := os.Getenv(TokenizerEnv)
	if path == "" {
		t.Skipf("set %s to openai/privacy-filter's tokenizer.json to run this", TokenizerEnv)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open tokenizer: %v", err)
	}
	defer f.Close()

	tok, err := tokenizer.Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return tok
}

// TestEncode_MatchesTheReferenceImplementation is the only test that matters
// for correctness.
//
// Tokenizing differently from the training tokenizer does not fail loudly --
// the model happily consumes a sequence it has never seen and returns
// confident nonsense. So "reasonable output" proves nothing, and the fixtures
// hold IDs produced by transformers.js, the reference the model card
// documents.
func TestEncode_MatchesTheReferenceImplementation(t *testing.T) {
	tok := loadTokenizer(t)
	f := loadFixtures(t)

	byGroup := map[string]int{}
	for _, c := range f.Cases {
		byGroup[c.Group]++
	}

	failures := map[string]int{}
	for _, c := range f.Cases {
		got, err := tok.IDs(c.Text)
		if err != nil {
			t.Errorf("[%s] %q: %v", c.Group, c.Text, err)
			failures[c.Group]++
			continue
		}
		if !equalIDs(got, c.IDs) {
			t.Errorf("[%s] %q:\n got  %v\n want %v", c.Group, truncate(c.Text), got, c.IDs)
			failures[c.Group]++
		}
	}
	if len(failures) > 0 {
		// Naming the constructs that failed beats a wall of individual
		// diffs when a whole pre-tokenizer alternative is wrong.
		var b strings.Builder
		for g, n := range failures {
			b.WriteString("\n  " + g + ": " + itoa(n) + "/" + itoa(byGroup[g]))
		}
		t.Errorf("failing groups:%s", b.String())
	}
}

// TestEncode_OffsetsTileTheInput is the property redaction depends on.
//
// Byte offsets here are derived from cumulative token lengths rather than
// reported by the tokenizer, which is only sound while encoding is lossless.
// A gap or overlap would shift every later span, and the redactor would cut
// the wrong bytes out of a request body -- exactly what #30's validateSpan
// exists to catch, but by then the damage is a wrong answer, not an error.
func TestEncode_OffsetsTileTheInput(t *testing.T) {
	tok := loadTokenizer(t)
	f := loadFixtures(t)

	for _, c := range f.Cases {
		toks, err := tok.Encode(c.Text)
		if err != nil {
			t.Errorf("%q: %v", truncate(c.Text), err)
			continue
		}

		at := 0
		var rebuilt strings.Builder
		for i, tk := range toks {
			if tk.Start != at {
				t.Errorf("%q: token %d starts at %d, want %d", truncate(c.Text), i, tk.Start, at)
				break
			}
			if tk.End > len(c.Text) {
				t.Errorf("%q: token %d ends at %d, past the %d-byte input", truncate(c.Text), i, tk.End, len(c.Text))
				break
			}
			rebuilt.WriteString(c.Text[tk.Start:tk.End])
			at = tk.End
		}
		if at != len(c.Text) {
			t.Errorf("%q: tokens cover %d bytes of %d", truncate(c.Text), at, len(c.Text))
		}
		if rebuilt.String() != c.Text {
			t.Errorf("%q: slicing the input by the offsets did not reproduce it", truncate(c.Text))
		}
	}
}

// TestDecode_RoundTrips confirms the lossless property directly.
func TestDecode_RoundTrips(t *testing.T) {
	tok := loadTokenizer(t)
	f := loadFixtures(t)

	for _, c := range f.Cases {
		ids, err := tok.IDs(c.Text)
		if err != nil {
			t.Errorf("%q: %v", truncate(c.Text), err)
			continue
		}
		back, err := tok.Decode(ids)
		if err != nil {
			t.Errorf("%q: decode: %v", truncate(c.Text), err)
			continue
		}
		if back != c.Text {
			t.Errorf("round-trip changed the text:\n got  %q\n want %q", truncate(back), truncate(c.Text))
		}
	}
}

// TestEncode_EmptyInput.
func TestEncode_EmptyInput(t *testing.T) {
	tok := loadTokenizer(t)
	toks, err := tok.Encode("")
	if err != nil {
		t.Fatalf("Encode(\"\"): %v", err)
	}
	if len(toks) != 0 {
		t.Errorf("got %d tokens for empty input", len(toks))
	}
}

// TestEncode_InvalidUTF8 must not hang or drop bytes. The byte-level alphabet
// covers all 256 values, so arbitrary bytes are tokenizable -- and a proxy
// body is arbitrary bytes.
func TestEncode_InvalidUTF8(t *testing.T) {
	tok := loadTokenizer(t)

	for _, s := range []string{"\xff\xfe", "valid\xffinvalid", "\x00null", "\xc3"} {
		toks, err := tok.Encode(s)
		if err != nil {
			t.Errorf("%q: %v", s, err)
			continue
		}
		at := 0
		for _, tk := range toks {
			if tk.Start != at {
				t.Errorf("%q: offsets do not tile", s)
				break
			}
			at = tk.End
		}
		if at != len(s) {
			t.Errorf("%q: covered %d of %d bytes", s, at, len(s))
		}
	}
}

// TestLoad_RejectsUnsupportedConfigurations. Accepting a tokenizer this code
// does not implement produces spans pointing at the wrong bytes, not an
// error, so each unread feature is refused explicitly.
func TestLoad_RejectsUnsupportedConfigurations(t *testing.T) {
	base := `{"normalizer":null,"truncation":null,"added_tokens":[],
	  "model":{"type":"BPE","vocab":{"a":0},"merges":[["a","b"]]}}`

	cases := []struct {
		name string
		json string
		want string
	}{
		{"not BPE", strings.Replace(base, `"type":"BPE"`, `"type":"WordPiece"`, 1), "not supported"},
		{"a normalizer", strings.Replace(base, `"normalizer":null`, `"normalizer":{"type":"NFC"}`, 1), "normalizer"},
		{"truncation", strings.Replace(base, `"truncation":null`, `"truncation":{"max_length":10}`, 1), "truncation"},
		{"dropout", strings.Replace(base, `"merges":[["a","b"]]`, `"merges":[["a","b"]],"dropout":0.1`, 1), "dropout"},
		{"subword prefix", strings.Replace(base, `"merges":[["a","b"]]`, `"merges":[["a","b"]],"continuing_subword_prefix":"##"`, 1), "continuing_subword_prefix"},
		{"empty vocab", strings.Replace(base, `"vocab":{"a":0}`, `"vocab":{}`, 1), "empty vocabulary"},
		{"no merges", strings.Replace(base, `"merges":[["a","b"]]`, `"merges":[]`, 1), "no merges"},
		{"malformed merge", strings.Replace(base, `"merges":[["a","b"]]`, `"merges":[["a"]]`, 1), "want 2"},
		{"not json", `{`, "parsing"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := tokenizer.Load(strings.NewReader(c.json))
			if err == nil {
				t.Fatalf("accepted a tokenizer with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestLoad_AcceptsAMinimalValidFile keeps the refusals above from being
// satisfied by a loader that rejects everything.
func TestLoad_AcceptsAMinimalValidFile(t *testing.T) {
	const min = `{"normalizer":null,"truncation":null,"added_tokens":[],
	  "model":{"type":"BPE","vocab":{"a":0,"b":1,"ab":2},"merges":[["a","b"]]}}`
	tok, err := tokenizer.Load(strings.NewReader(min))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tok.VocabSize() != 3 {
		t.Errorf("VocabSize = %d, want 3", tok.VocabSize())
	}
	ids, err := tok.IDs("ab")
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != 2 {
		t.Errorf("IDs(\"ab\") = %v, want [2]; the merge did not apply", ids)
	}
}

func equalIDs(a, b []int32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func truncate(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:57] + "..."
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
