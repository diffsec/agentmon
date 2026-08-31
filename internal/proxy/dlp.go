package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"sync"

	"github.com/diffsec/agentmon/internal/config"
)

// DLPProcessor processes data for PII detection and redaction/tokenization.
type DLPProcessor struct {
	cfg      config.DLPConfig
	patterns []*compiledPattern
	tokens   *tokenStore
}

type compiledPattern struct {
	name    string // Internal name for logs/tracking
	display string // Display name for LLM (shown in [REDACTED:display])
	regex   *regexp.Regexp
}

// tokenStore manages tokenization mappings.
type tokenStore struct {
	mu       sync.RWMutex
	forward  map[string]string // original -> token
	backward map[string]string // token -> original
}

func newTokenStore() *tokenStore {
	return &tokenStore{
		forward:  make(map[string]string),
		backward: make(map[string]string),
	}
}

func (ts *tokenStore) getOrCreateToken(original string) string {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if token, ok := ts.forward[original]; ok {
		return token
	}

	// Generate new token
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a counter-based token if crypto/rand fails
		// This should never happen in practice
		b = []byte{0, 0, 0, 0, 0, 0, 0, byte(len(ts.forward))}
	}
	token := "TOK_" + hex.EncodeToString(b)

	ts.forward[original] = token
	ts.backward[token] = original
	return token
}

func (ts *tokenStore) detokenize(token string) (string, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	original, ok := ts.backward[token]
	return original, ok
}

// Built-in regex patterns for PII detection.
var builtinPatterns = map[string]string{
	"email": `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,

	// Phone: US formats (xxx-xxx-xxxx, (xxx) xxx-xxxx, xxx.xxx.xxxx, +1xxxxxxxxxx)
	"phone": `(?:\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`,

	// Credit card: 13-19 digits with optional separators
	"credit_card": `\b(?:\d[ -]*?){13,19}\b`,

	// SSN: xxx-xx-xxxx format
	"ssn": `\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`,

	// API keys: high-entropy strings that look like secrets
	// Matches common patterns: sk-xxx, api-xxx, key_xxx, etc.
	"api_key": `(?i)(?:sk|api|key|secret|token)[-_]?[a-zA-Z0-9]{20,}`,
}

// NewDLPProcessor creates a new DLP processor using config.DLPConfig.
func NewDLPProcessor(cfg config.DLPConfig) *DLPProcessor {
	dp := &DLPProcessor{
		cfg:      cfg,
		patterns: make([]*compiledPattern, 0),
		tokens:   newTokenStore(),
	}

	if cfg.Mode == "disabled" {
		return dp
	}

	// Compile enabled built-in patterns
	// For built-in patterns, name and display are the same
	if cfg.Patterns.Email {
		dp.addPattern("email", "email", builtinPatterns["email"])
	}
	if cfg.Patterns.Phone {
		dp.addPattern("phone", "phone", builtinPatterns["phone"])
	}
	if cfg.Patterns.CreditCard {
		dp.addPattern("credit_card", "credit_card", builtinPatterns["credit_card"])
	}
	if cfg.Patterns.SSN {
		dp.addPattern("ssn", "ssn", builtinPatterns["ssn"])
	}
	if cfg.Patterns.APIKeys {
		dp.addPattern("api_key", "api_key", builtinPatterns["api_key"])
	}

	// Compile custom patterns
	// Custom patterns have separate name (internal) and display (for LLM)
	for _, cp := range cfg.CustomPatterns {
		display := cp.Display
		if display == "" {
			// Fall back to name if display is not set
			display = cp.Name
		}
		dp.addPattern(cp.Name, display, cp.Regex)
	}

	return dp
}

func (dp *DLPProcessor) addPattern(name, display, pattern string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		// Skip invalid patterns
		return
	}
	dp.patterns = append(dp.patterns, &compiledPattern{
		name:    name,
		display: display,
		regex:   re,
	})
}

// DLPResult contains the result of DLP processing.
type DLPResult struct {
	// ProcessedData is the data after DLP processing.
	ProcessedData []byte

	// Redactions is a list of redactions that were applied.
	Redactions []Redaction

	// Modified indicates if any changes were made.
	Modified bool
}

// Redaction describes a single redaction event.
type Redaction struct {
	// Field is the JSON path where the redaction occurred (if applicable).
	Field string `json:"field,omitempty"`

	// Type is the internal type name of PII that was detected (for logs).
	Type string `json:"type"`

	// Count is the number of unique instances redacted.
	Count int `json:"count"`
}

// Process applies DLP to the given data.
func (dp *DLPProcessor) Process(data []byte, dialect Dialect) *DLPResult {
	result := &DLPResult{
		ProcessedData: data,
		Redactions:    make([]Redaction, 0),
		Modified:      false,
	}

	if dp.cfg.Mode == "disabled" || len(dp.patterns) == 0 {
		return result
	}

	// Try to parse as JSON for structured processing
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		// Process JSON structure
		modified := dp.processJSON(jsonData, "", result)
		if modified {
			result.Modified = true
			newData, err := json.Marshal(jsonData)
			if err == nil {
				result.ProcessedData = newData
			}
		}
	} else {
		// Process as plain text
		result.ProcessedData = dp.processText(data, "", result)
		result.Modified = len(result.Redactions) > 0
	}

	return result
}

// processJSON recursively processes JSON structures.
func (dp *DLPProcessor) processJSON(v interface{}, path string, result *DLPResult) bool {
	modified := false

	switch val := v.(type) {
	case map[string]interface{}:
		for k, vv := range val {
			fieldPath := path + "." + k
			if path == "" {
				fieldPath = k
			}

			if s, ok := vv.(string); ok {
				processed := dp.processText([]byte(s), fieldPath, result)
				if string(processed) != s {
					val[k] = string(processed)
					modified = true
				}
			} else {
				if dp.processJSON(vv, fieldPath, result) {
					modified = true
				}
			}
		}
	case []interface{}:
		for i, vv := range val {
			fieldPath := path + "[" + strconv.Itoa(i) + "]"
			if s, ok := vv.(string); ok {
				processed := dp.processText([]byte(s), fieldPath, result)
				if string(processed) != s {
					val[i] = string(processed)
					modified = true
				}
			} else {
				if dp.processJSON(vv, fieldPath, result) {
					modified = true
				}
			}
		}
	}

	return modified
}

// processText applies DLP patterns to text data.
func (dp *DLPProcessor) processText(data []byte, path string, result *DLPResult) []byte {
	text := string(data)

	for _, pattern := range dp.patterns {
		matches := pattern.regex.FindAllString(text, -1)
		if len(matches) == 0 {
			continue
		}

		// Track unique matches for accurate count
		uniqueMatches := make(map[string]bool)
		for _, m := range matches {
			uniqueMatches[m] = true
		}

		// Use internal name for logging/tracking in Redaction result
		result.Redactions = append(result.Redactions, Redaction{
			Field: path,
			Type:  pattern.name, // Internal name for logs
			Count: len(uniqueMatches),
		})

		// Apply redaction or tokenization
		// Use display name in the redacted output
		switch dp.cfg.Mode {
		case "redact":
			text = pattern.regex.ReplaceAllString(text, "[REDACTED:"+pattern.display+"]")
		case "tokenize":
			text = pattern.regex.ReplaceAllStringFunc(text, func(match string) string {
				return dp.tokens.getOrCreateToken(match)
			})
		}
	}

	return []byte(text)
}

// Detokenize reverses tokenization for a given text.
func (dp *DLPProcessor) Detokenize(text string) string {
	if dp.cfg.Mode != "tokenize" {
		return text
	}

	// Simple token pattern: TOK_ followed by hex
	tokenRe := regexp.MustCompile(`TOK_[a-f0-9]{16}`)
	return tokenRe.ReplaceAllStringFunc(text, func(token string) string {
		if original, ok := dp.tokens.detokenize(token); ok {
			return original
		}
		return token
	})
}

// ExportTokenMap exports the token mapping for external storage.
func (dp *DLPProcessor) ExportTokenMap() map[string]string {
	dp.tokens.mu.RLock()
	defer dp.tokens.mu.RUnlock()

	export := make(map[string]string, len(dp.tokens.forward))
	for k, v := range dp.tokens.forward {
		export[k] = v
	}
	return export
}

// ImportTokenMap imports a token mapping.
func (dp *DLPProcessor) ImportTokenMap(m map[string]string) {
	dp.tokens.mu.Lock()
	defer dp.tokens.mu.Unlock()

	for original, token := range m {
		dp.tokens.forward[original] = token
		dp.tokens.backward[token] = original
	}
}

// PatternCount returns the number of active DLP patterns.
func (dp *DLPProcessor) PatternCount() int {
	if dp == nil {
		return 0
	}
	return len(dp.patterns)
}

// Mode returns the DLP mode (redact, tokenize, or disabled).
func (dp *DLPProcessor) Mode() string {
	if dp == nil {
		return "disabled"
	}
	return dp.cfg.Mode
}

// PatternNames returns the names of active DLP patterns.
func (dp *DLPProcessor) PatternNames() []string {
	if dp == nil || len(dp.patterns) == 0 {
		return nil
	}
	names := make([]string, len(dp.patterns))
	for i, p := range dp.patterns {
		names[i] = p.name
	}
	return names
}

// tokenLen is the exact length of a token minted by getOrCreateToken:
// "TOK_" plus 16 hex characters.
const tokenLen = 4 + 16

// DetokenizeReader wraps r so tokens are replaced with their originals as the
// stream is read.
//
// Streaming needs its own path because a token can straddle a chunk boundary.
// A per-chunk ReplaceAllString would leave "TOK_abcd" at the end of one read
// and "ef0123456789" at the start of the next, and neither half matches, so
// the token would reach the client intact and unresolvable. This holds back a
// short tail until either enough bytes arrive to decide or the stream ends.
//
// When tokenization is not the active mode there is nothing to reverse, so r
// is returned unwrapped and the stream keeps its original read boundaries.
func (dp *DLPProcessor) DetokenizeReader(r io.Reader) io.Reader {
	if dp == nil || dp.cfg.Mode != "tokenize" {
		return r
	}
	return &detokenizeReader{src: r, dp: dp}
}

type detokenizeReader struct {
	src io.Reader
	dp  *DLPProcessor

	// pending holds decoded bytes not yet handed to the caller.
	pending []byte
	// tail holds bytes that could still turn out to be the start of a token.
	tail []byte
	// err is the source's terminal error, returned only once pending drains.
	err error
}

func (d *detokenizeReader) Read(p []byte) (int, error) {
	for len(d.pending) == 0 {
		if d.err != nil {
			return 0, d.err
		}

		buf := make([]byte, 32*1024)
		n, readErr := d.src.Read(buf)
		if n > 0 {
			d.tail = append(d.tail, buf[:n]...)
			decoded := d.dp.Detokenize(string(d.tail))
			// Every complete token in decoded has already been replaced, so
			// only a trailing PARTIAL token still needs to wait for more
			// bytes. Holding a fixed-width suffix instead would cut a
			// complete token in half whenever one straddled the boundary --
			// which is the whole failure this reader exists to prevent.
			keep := partialTokenSuffix(decoded)
			d.pending = append(d.pending, decoded[:len(decoded)-keep]...)
			d.tail = []byte(decoded[len(decoded)-keep:])
		}
		if readErr != nil {
			// The stream is over, so the tail can no longer grow into
			// anything. Emit it as it stands.
			if len(d.tail) > 0 {
				d.pending = append(d.pending, []byte(d.dp.Detokenize(string(d.tail)))...)
				d.tail = nil
			}
			// Held until pending drains, so a truncated upstream surfaces as
			// an error rather than as a clean end of stream with the last
			// bytes quietly missing.
			d.err = readErr
		}
	}

	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// partialTokenSuffix returns the length of the longest suffix of s that could
// still grow into a token: some prefix of "TOK_" followed by fewer than 16 hex
// digits. Complete tokens are not partial, so they are never held back.
func partialTokenSuffix(s string) int {
	max := tokenLen - 1
	if len(s) < max {
		max = len(s)
	}
	for keep := max; keep > 0; keep-- {
		if isPartialToken(s[len(s)-keep:]) {
			return keep
		}
	}
	return 0
}

const tokenPrefix = "TOK_"

func isPartialToken(s string) bool {
	if len(s) >= tokenLen {
		return false
	}
	if len(s) < len(tokenPrefix) {
		return s == tokenPrefix[:len(s)]
	}
	if s[:len(tokenPrefix)] != tokenPrefix {
		return false
	}
	for i := len(tokenPrefix); i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
