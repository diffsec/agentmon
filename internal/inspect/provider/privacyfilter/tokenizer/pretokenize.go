package tokenizer

import "unicode"

// The pre-tokenizer splits text before BPE runs. openai/privacy-filter's
// tokenizer.json specifies it as this regex, which is the o200k pattern:
//
//	[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?
//	|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?
//	|\p{N}{1,3}
//	| ?[^\s\p{L}\p{N}]+[\r\n/]*
//	|\s*[\r\n]+
//	|\s+(?!\S)
//	|\s+
//
// It is hand-scanned rather than compiled for two reasons. Go's regexp is
// RE2, which has no lookahead, so `\s+(?!\S)` will not compile at all -- and
// that alternative is load-bearing, since it is what makes a run of spaces
// before a word split differently from a run at the end of the input. The
// usual fix is a backtracking engine like dlclark/regexp2, but the input here
// is content the agent controls, and a backtracking matcher on attacker-chosen
// text is a way to stall inspection. This scanner is linear.
//
// Correctness is not argued from the code: testdata/fixtures.json holds token
// sequences produced by transformers.js, the reference implementation the
// model card documents, and the tests require an exact match.

// preTokenize splits s into the pieces BPE is applied to. Offsets are byte
// indices into s; the pieces tile s exactly, with no gaps and no overlap.
func preTokenize(s string, emit func(start, end int)) {
	for i := 0; i < len(s); {
		n := matchAlternative(s, i)
		if n <= 0 {
			// Regex alternation cannot fail here: the final `\s+` catches
			// whitespace and alternative 4 catches everything else that is
			// not a letter or digit, while letters and digits are caught
			// earlier. Advancing by one rune rather than looping forever is
			// the safe response to a case this reasoning missed.
			_, size := decodeRune(s[i:])
			n = size
		}
		emit(i, i+n)
		i += n
	}
}

// matchAlternative returns the length of the leftmost-first match at i, or 0.
//
// Regex alternation is ordered: at each position the first alternative that
// matches wins, regardless of whether a later one would match more. The order
// below is the order in the pattern and must not be rearranged.
func matchAlternative(s string, i int) int {
	if n := matchLetterRun(s, i, true); n > 0 {
		return n
	}
	if n := matchLetterRun(s, i, false); n > 0 {
		return n
	}
	if n := matchDigits(s, i); n > 0 {
		return n
	}
	if n := matchPunctuation(s, i); n > 0 {
		return n
	}
	if n := matchNewlines(s, i); n > 0 {
		return n
	}
	if n := matchTrailingSpace(s, i); n > 0 {
		return n
	}
	return matchSpaces(s, i)
}

// isUpperish matches [\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}].
func isUpperish(r rune) bool {
	return unicode.Is(unicode.Lu, r) || unicode.Is(unicode.Lt, r) ||
		unicode.Is(unicode.Lm, r) || unicode.Is(unicode.Lo, r) || unicode.Is(unicode.M, r)
}

// isLowerish matches [\p{Ll}\p{Lm}\p{Lo}\p{M}].
//
// It overlaps isUpperish on Lm, Lo and M. That overlap is why the two
// alternatives below need real backtracking rather than a single greedy pass:
// a greedy upper-ish run can swallow the characters the lower-ish run
// requires.
func isLowerish(r rune) bool {
	return unicode.Is(unicode.Ll, r) || unicode.Is(unicode.Lm, r) ||
		unicode.Is(unicode.Lo, r) || unicode.Is(unicode.M, r)
}

// isLeadPrefix matches [^\r\n\p{L}\p{N}], the optional single character a word
// may be preceded by -- usually the space in " word".
func isLeadPrefix(r rune) bool {
	if r == '\r' || r == '\n' {
		return false
	}
	return !unicode.IsLetter(r) && !unicode.IsNumber(r)
}

// matchLetterRun handles the first two alternatives, which differ only in
// which of the two letter classes is required and which is optional:
//
//	lowerRequired: [^\r\n\p{L}\p{N}]? A* B+ contraction?
//	otherwise:     [^\r\n\p{L}\p{N}]? A+ B* contraction?
//
// where A is isUpperish and B is isLowerish.
//
// A NOTE ON THE BACKTRACKING BELOW, which is not covered by any test.
//
// Mutation testing could not distinguish two changes here: trying only the
// longest A run instead of backtracking, and swapping the order of the two
// alternatives. Both survive all 511 fixtures, including 400 randomised
// strings sampled specifically from Lu, Ll, Lt, Lm, Lo and combining marks --
// the classes that make the overlap possible.
//
// That matches the reasoning: whenever a shorter A run would let B+ match,
// the second alternative matches the same span anyway, so the two together
// cover the same territory in either order. The backtracking is kept because
// it is what the pattern says, and the pattern is the specification a reader
// checks this against; "I could not find an input that distinguishes them" is
// weaker than "they are equivalent", and this file is not the place to bet on
// the difference.
func matchLetterRun(s string, i int, lowerRequired bool) int {
	p := i

	// The optional lead character is consumed only if a letter run actually
	// follows; regex would backtrack it away otherwise.
	leadEnd := p
	if r, size := decodeRune(s[p:]); size > 0 && isLeadPrefix(r) {
		leadEnd = p + size
	}

	// Greedy A run, remembering every boundary so the backtrack below can
	// step through them.
	aStart := leadEnd
	bounds := []int{aStart}
	q := aStart
	for q < len(s) {
		r, size := decodeRune(s[q:])
		if size == 0 || !isUpperish(r) {
			break
		}
		q += size
		bounds = append(bounds, q)
	}

	if lowerRequired {
		// A* B+ : longest A run first, then shorten until B+ can match.
		for k := len(bounds) - 1; k >= 0; k-- {
			at := bounds[k]
			end := consumeWhile(s, at, isLowerish)
			if end > at {
				return end + contractionLen(s, end) - i
			}
		}
		return 0
	}

	// A+ B* : the A run must be non-empty; B* may match nothing, so the
	// greedy A run never needs shortening.
	aEnd := bounds[len(bounds)-1]
	if aEnd == aStart {
		return 0
	}
	end := consumeWhile(s, aEnd, isLowerish)
	return end + contractionLen(s, end) - i
}

// contractions are the (?i:'s|'t|'re|'ve|'m|'ll|'d) tail. Longer forms come
// first so "'re" is preferred over a bare "'r"-less match; the alternation is
// ordered in the pattern too.
var contractions = []string{"'re", "'ve", "'ll", "'s", "'t", "'m", "'d"}

// contractionLen returns the length of a trailing contraction at i, or 0. The
// match is case-insensitive, so "DON'T" is one piece just as "don't" is.
func contractionLen(s string, i int) int {
	if i >= len(s) || s[i] != '\'' {
		return 0
	}
	for _, c := range contractions {
		if len(s)-i < len(c) {
			continue
		}
		if equalFoldASCII(s[i:i+len(c)], c) {
			return len(c)
		}
	}
	return 0
}

// equalFoldASCII compares with ASCII case folding. The contraction set is
// ASCII-only, so full Unicode folding would add cost and cases (Kelvin sign,
// dotless i) that cannot arise here.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// matchDigits handles \p{N}{1,3}: digits are chunked in threes, so "1234"
// becomes "123" then "4".
func matchDigits(s string, i int) int {
	p := i
	for n := 0; n < 3 && p < len(s); n++ {
		r, size := decodeRune(s[p:])
		if size == 0 || !unicode.IsNumber(r) {
			break
		}
		p += size
	}
	return p - i
}

// matchPunctuation handles ` ?[^\s\p{L}\p{N}]+[\r\n/]*`.
func matchPunctuation(s string, i int) int {
	p := i
	if p < len(s) && s[p] == ' ' {
		p++
	}

	start := p
	for p < len(s) {
		r, size := decodeRune(s[p:])
		if size == 0 || unicode.IsSpace(r) || unicode.IsLetter(r) || unicode.IsNumber(r) {
			break
		}
		p += size
	}
	if p == start {
		return 0 // the optional leading space is backtracked away
	}

	for p < len(s) && (s[p] == '\r' || s[p] == '\n' || s[p] == '/') {
		p++
	}
	return p - i
}

// matchNewlines handles `\s*[\r\n]+`.
//
// The greedy whitespace run can swallow the newlines the second half needs,
// so this walks back to the last position from which a newline run starts.
func matchNewlines(s string, i int) int {
	spaceEnd := consumeWhile(s, i, unicode.IsSpace)
	for p := spaceEnd; p >= i; p-- {
		if p < len(s) && (s[p] == '\r' || s[p] == '\n') {
			q := p
			for q < len(s) && (s[q] == '\r' || s[q] == '\n') {
				q++
			}
			return q - i
		}
	}
	return 0
}

// matchTrailingSpace handles `\s+(?!\S)`: a whitespace run that is not
// followed by a non-whitespace character.
//
// Greedy \s+ always ends at a non-space or at end of input, so the lookahead
// can only be satisfied at end of input, or by giving back the final
// character of the run so the next one is whitespace. That is why " word"
// splits with the space attached to the word rather than standing alone, and
// why "a  b" attaches only the second space.
func matchTrailingSpace(s string, i int) int {
	end := consumeWhile(s, i, unicode.IsSpace)
	if end == i {
		return 0
	}
	if end == len(s) {
		return end - i // the run reaches end of input; nothing follows it
	}
	// Give back the last rune of the run.
	last := lastRuneStart(s, i, end)
	if last <= i {
		return 0 // a single-rune run followed by a non-space: no match
	}
	return last - i
}

// matchSpaces handles the final `\s+`.
func matchSpaces(s string, i int) int {
	return consumeWhile(s, i, unicode.IsSpace) - i
}

// consumeWhile advances over runes satisfying pred.
func consumeWhile(s string, i int, pred func(rune) bool) int {
	p := i
	for p < len(s) {
		r, size := decodeRune(s[p:])
		if size == 0 || !pred(r) {
			break
		}
		p += size
	}
	return p
}

// lastRuneStart returns the start index of the final rune in s[from:to].
func lastRuneStart(s string, from, to int) int {
	p := to - 1
	for p > from && !utf8Start(s[p]) {
		p--
	}
	return p
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
