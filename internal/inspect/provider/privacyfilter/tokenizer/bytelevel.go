package tokenizer

import "unicode/utf8"

// The byte-level alphabet maps each of the 256 byte values to a distinct
// printable rune, so a BPE vocabulary over text can represent arbitrary bytes
// with no unknown token and no byte-fallback path. It is the GPT-2 mapping,
// which openai/privacy-filter inherits: printable ASCII and Latin-1 ranges map
// to themselves, and the remaining 68 bytes map to U+0100 upward in order.
//
// This is why the vocabulary is full of entries like "Ġan" -- U+0120 is the
// stand-in for a space.
var (
	byteToRune [256]rune
	runeToByte map[rune]byte
)

func init() {
	runeToByte = make(map[rune]byte, 256)

	// The three ranges that map to themselves.
	direct := make([]bool, 256)
	for b := '!'; b <= '~'; b++ {
		direct[b] = true
	}
	for b := 0xA1; b <= 0xAC; b++ {
		direct[b] = true
	}
	for b := 0xAE; b <= 0xFF; b++ {
		direct[b] = true
	}

	next := rune(0x100)
	for b := 0; b < 256; b++ {
		if direct[b] {
			byteToRune[b] = rune(b)
			continue
		}
		byteToRune[b] = next
		next++
	}
	for b := 0; b < 256; b++ {
		runeToByte[byteToRune[b]] = byte(b)
	}
}

// encodeBytes maps raw bytes into the byte-level alphabet.
func encodeBytes(s string) string {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); i++ {
		out = append(out, byteToRune[s[i]])
	}
	return string(out)
}

// decodeToken maps a vocabulary entry back to the bytes it stands for.
//
// It returns ok=false for a rune outside the alphabet rather than substituting
// anything. Every token in this vocabulary is byte-level, so a rune that is not
// in the map means the vocabulary is not the one this code expects -- and
// guessing would produce byte offsets that do not line up with the input,
// which is how a redactor cuts the wrong bytes.
func decodeToken(tok string) ([]byte, bool) {
	out := make([]byte, 0, len(tok))
	for _, r := range tok {
		b, ok := runeToByte[r]
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
	return out, true
}

// decodeRune is utf8.DecodeRuneInString with an invalid encoding reported as
// size 0, so callers stop rather than looping on RuneError.
func decodeRune(s string) (rune, int) {
	if s == "" {
		return 0, 0
	}
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size <= 1 {
		// An invalid byte still has to advance, or a caller loops forever.
		// One byte is the right step: the byte-level alphabet covers every
		// byte value, so invalid UTF-8 is tokenizable, just not as a rune.
		return r, 1
	}
	return r, size
}
