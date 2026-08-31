package inspect

// Redactor decides what replaces a finding's matched text.
//
// It exists because the right replacement depends on the caller, not on the
// policy. The proxy can mint a reversible pseudonym and restore the real
// value on the way back, so the model never sees it but everything
// downstream still works. A caller with no such machinery can only blank the
// value out. Both are "redact" as far as a rule is concerned.
type Redactor interface {
	// Replace returns the text to substitute for one finding.
	//
	// matched is the exact bytes the finding covers. An implementation that
	// stores it is storing exactly the sensitive material inspection exists
	// to contain, and must be scoped and cleared accordingly.
	Replace(category, matched string) string
}

// PlaceholderRedactor blanks a finding out, keeping only its category.
//
// This is the default because it is the only strategy that is safe without
// knowing anything about the caller: it retains nothing. The cost is that the
// value is destroyed for everything downstream, not just for the model.
type PlaceholderRedactor struct{}

// Replace implements Redactor.
func (PlaceholderRedactor) Replace(category, _ string) string {
	return "[REDACTED:" + category + "]"
}

// options carries per-call settings for Resolve.
type options struct {
	redactor Redactor
}

// Option customises a Resolve call.
type Option func(*options)

// WithRedactor supplies the redaction strategy for this call.
//
// It is per-call rather than per-Checker because a Checker is built from the
// policy, which is shared, while the redaction machinery belongs to one
// caller: the proxy's token store is scoped to a session, and handing a
// session's store to a Checker shared across sessions would let one session's
// values be restored into another's traffic.
func WithRedactor(r Redactor) Option {
	return func(o *options) { o.redactor = r }
}
