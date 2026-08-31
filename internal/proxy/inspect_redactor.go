package proxy

import "github.com/diffsec/agentmon/internal/inspect"

// Tokenize mints (or reuses) the reversible pseudonym for a value.
//
// It is the same store the regex DLP path uses, deliberately: one token space
// per session means Detokenize on the response reverses both, and a value
// found by both a regex pattern and an inspection profile gets one token
// rather than two.
func (dp *DLPProcessor) Tokenize(original string) string {
	if dp == nil {
		return original
	}
	return dp.tokens.getOrCreateToken(original)
}

// DLP returns the proxy's DLP processor, or nil.
func (p *Proxy) DLP() *DLPProcessor { return p.dlp }

// tokenizingRedactor replaces an inspection finding with a reversible
// pseudonym from the proxy's DLP token store.
//
// This is what makes `on_violation: redact` useful rather than merely safe.
// The placeholder default destroys the value for everything downstream, not
// just for the model: a request body redacted to [REDACTED:private_email]
// gets a reply about an address that no longer exists anywhere. A token
// survives the round trip and Detokenize puts the real value back before the
// agent sees it.
//
// The store holds the original in memory for the life of the session. That is
// the same exposure the regex DLP path already accepts, and it is why this is
// only used when the operator chose dlp.mode: tokenize.
type tokenizingRedactor struct{ dp *DLPProcessor }

// Replace implements inspect.Redactor.
func (r tokenizingRedactor) Replace(category, matched string) string {
	if r.dp == nil || matched == "" {
		return inspect.PlaceholderRedactor{}.Replace(category, matched)
	}
	return r.dp.Tokenize(matched)
}

// redactorFor picks the redaction strategy for a proxy.
//
// Tokenization is opt-in through the existing dlp.mode knob rather than a new
// one, because the semantics already match: an operator who chose tokenize
// asked for values to survive the round trip, and one who chose redact asked
// for them not to. Any other mode -- including a nil processor -- gets the
// placeholder, which retains nothing.
func redactorFor(dp *DLPProcessor) inspect.Redactor {
	if dp.Mode() == "tokenize" {
		return tokenizingRedactor{dp: dp}
	}
	return inspect.PlaceholderRedactor{}
}
