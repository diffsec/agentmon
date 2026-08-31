package proxy

import (
	"io"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/config"
)

func tokenizeProcessor(t *testing.T) *DLPProcessor {
	t.Helper()
	return NewDLPProcessor(config.DLPConfig{
		Mode:     "tokenize",
		Patterns: config.DLPPatternsConfig{Email: true},
	})
}

// tokenizeOnce runs a value through the request path so the store holds it,
// and returns the token that was minted. Building the mapping by hand would
// let these tests pass against a Detokenize that no request path ever feeds.
func tokenizeOnce(t *testing.T, dp *DLPProcessor, text string) string {
	t.Helper()
	res := dp.Process([]byte(text), DialectOpenAI)
	if !res.Modified {
		t.Fatalf("DLP did not tokenize %q", text)
	}
	out := string(res.ProcessedData)
	i := strings.Index(out, "TOK_")
	if i < 0 {
		t.Fatalf("no token in %q", out)
	}
	return out[i : i+tokenLen]
}

// TestDetokenize_RoundTripsARequestPathToken is the base case: what the
// request path minted, the response path reverses.
func TestDetokenize_RoundTripsARequestPathToken(t *testing.T) {
	dp := tokenizeProcessor(t)
	tok := tokenizeOnce(t, dp, `{"to":"alice@example.com"}`)

	got := dp.Detokenize(`the address ` + tok + ` was fine`)
	if got != "the address alice@example.com was fine" {
		t.Errorf("Detokenize = %q", got)
	}
}

// TestDetokenizeReader_TokenSplitAcrossReads is why the streaming path needs
// its own implementation.
//
// A per-chunk ReplaceAllString leaves "TOK_abcd" at the end of one read and
// the rest at the start of the next. Neither half matches, so the token
// reaches the agent intact and unresolvable — and SSE is how LLM responses
// normally arrive, so this is the common case, not an edge one.
func TestDetokenizeReader_TokenSplitAcrossReads(t *testing.T) {
	dp := tokenizeProcessor(t)
	tok := tokenizeOnce(t, dp, `{"to":"alice@example.com"}`)
	full := "data: {\"text\":\"" + tok + " said hello\"}\n\n"

	// Split at every position, so the boundary lands inside the token, on
	// its first byte, and on its last.
	for cut := 1; cut < len(full); cut++ {
		r := dp.DetokenizeReader(&chunkedReader{chunks: []string{full[:cut], full[cut:]}})
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		want := strings.Replace(full, tok, "alice@example.com", 1)
		if string(out) != want {
			t.Fatalf("cut %d:\n got %q\nwant %q", cut, out, want)
		}
	}
}

// TestDetokenizeReader_ByteAtATime is the pathological case: every read
// boundary is inside the token.
func TestDetokenizeReader_ByteAtATime(t *testing.T) {
	dp := tokenizeProcessor(t)
	tok := tokenizeOnce(t, dp, `{"to":"alice@example.com"}`)
	full := "x" + tok + "y"

	chunks := make([]string, 0, len(full))
	for i := 0; i < len(full); i++ {
		chunks = append(chunks, full[i:i+1])
	}
	out, err := io.ReadAll(dp.DetokenizeReader(&chunkedReader{chunks: chunks}))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(out) != "xalice@example.comy" {
		t.Errorf("got %q", out)
	}
}

// TestDetokenizeReader_PassesThroughUnknownTokens: a TOK_-shaped string this
// store never minted must survive untouched rather than being eaten.
func TestDetokenizeReader_PassesThroughUnknownTokens(t *testing.T) {
	dp := tokenizeProcessor(t)
	in := "before TOK_0123456789abcdef after"
	out, err := io.ReadAll(dp.DetokenizeReader(strings.NewReader(in)))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(out) != in {
		t.Errorf("got %q, want it unchanged", out)
	}
}

// TestDetokenizeReader_TrailingPartialTokenIsFlushed. The reader holds back a
// tail that might grow into a token; at EOF it must emit it rather than drop
// it.
func TestDetokenizeReader_TrailingPartialTokenIsFlushed(t *testing.T) {
	dp := tokenizeProcessor(t)
	for _, in := range []string{"trailing TOK_abc", "ends with TOK_", "T", "", "no tokens here"} {
		out, err := io.ReadAll(dp.DetokenizeReader(strings.NewReader(in)))
		if err != nil {
			t.Fatalf("input %q: %v", in, err)
		}
		if string(out) != in {
			t.Errorf("input %q produced %q; the held-back tail was lost", in, out)
		}
	}
}

// TestDetokenizeReader_DisabledModeDoesNotWrap. When tokenization is off
// there is nothing to reverse, and wrapping would change read boundaries on
// every streamed response for no reason.
func TestDetokenizeReader_DisabledModeDoesNotWrap(t *testing.T) {
	for _, mode := range []string{"redact", "disabled", ""} {
		dp := NewDLPProcessor(config.DLPConfig{Mode: mode, Patterns: config.DLPPatternsConfig{Email: true}})
		src := strings.NewReader("x")
		if got := dp.DetokenizeReader(src); got != io.Reader(src) {
			t.Errorf("mode %q wrapped the reader", mode)
		}
	}
	var nilDP *DLPProcessor
	src := strings.NewReader("x")
	if got := nilDP.DetokenizeReader(src); got != io.Reader(src) {
		t.Error("a nil processor wrapped the reader")
	}
}

// TestDetokenizeReader_PropagatesReadErrors: a truncated upstream must not
// look like a clean end of stream.
func TestDetokenizeReader_PropagatesReadErrors(t *testing.T) {
	dp := tokenizeProcessor(t)
	r := dp.DetokenizeReader(&chunkedReader{chunks: []string{"partial"}, err: io.ErrUnexpectedEOF})
	_, err := io.ReadAll(r)
	if err == nil {
		t.Fatal("a read error was swallowed")
	}
}

// chunkedReader hands out one chunk per Read, then err (default io.EOF).
type chunkedReader struct {
	chunks []string
	err    error
	i      int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.i >= len(c.chunks) {
		if c.err != nil {
			return 0, c.err
		}
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.i])
	if n < len(c.chunks[c.i]) {
		c.chunks[c.i] = c.chunks[c.i][n:]
		return n, nil
	}
	c.i++
	return n, nil
}

// TestDetokenizeReader_DoesNotDelayTokenFreeOutput is what justifies
// partialTokenSuffix over a simpler fixed-width hold-back.
//
// Holding back a flat tokenLen-1 bytes is also correct — Detokenize runs on
// the whole tail before the split, so a complete token is never cut — but it
// delays the last 19 bytes of every chunk until the next one arrives. On a
// token-by-token SSE stream that is a visible stutter on every delta. Without
// this test the simpler version passes everything, and the next person to
// read this file would be right to simplify it back.
func TestDetokenizeReader_DoesNotDelayTokenFreeOutput(t *testing.T) {
	dp := tokenizeProcessor(t)
	chunk := `data: {"delta":"hello there"}`

	r := dp.DetokenizeReader(&chunkedReader{chunks: []string{chunk, "more"}})
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != chunk {
		t.Errorf("first Read returned %q (%d bytes), want the whole chunk (%d bytes) with nothing held back",
			got, n, len(chunk))
	}
}

// TestDetokenizeReader_HoldsBackOnlyAPartialToken is the other half: a chunk
// that DOES end mid-token must hold exactly that suffix and emit the rest,
// or the reader is just passing everything through and the split-token tests
// are passing by luck of buffer size.
func TestDetokenizeReader_HoldsBackOnlyAPartialToken(t *testing.T) {
	dp := tokenizeProcessor(t)
	prefix := `data: {"delta":"see `
	partial := "TOK_abc123"

	r := dp.DetokenizeReader(&chunkedReader{chunks: []string{prefix + partial, "def4567890\"}"}})
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != prefix {
		t.Errorf("first Read returned %q, want %q — the partial token should have been held back and nothing else", got, prefix)
	}
}
