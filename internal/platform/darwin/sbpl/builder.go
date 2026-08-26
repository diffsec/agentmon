// Package sbpl constructs valid SBPL (Sandbox Profile Language) strings
// via a typed Go API. It is pure Go with no CGo or build tags so that
// tests can run on any OS.
package sbpl

import (
	"fmt"
	"strings"
)

// PathMatch controls how a path argument is matched in an SBPL rule.
type PathMatch int

const (
	Literal PathMatch = iota // (literal "/exact/path")
	Subpath                  // (subpath "/dir")
	Regex                    // (regex #"/pattern"#)
)

// ruleKind groups rules for deterministic ordering in the output.
type ruleKind int

const (
	kindFileAllow ruleKind = iota
	kindFileDeny
	kindExecAllow
	kindExecDeny
	kindMachAllow
	kindMachDeny
	kindNetworkAllow
	kindNetworkDeny
	kindOther
)

// rule is a single SBPL statement with its kind for ordering.
type rule struct {
	kind ruleKind
	sbpl string
}

// Profile accumulates SBPL rules and renders them into a complete
// sandbox profile string.
type Profile struct {
	rules []rule
	// errs collects problems found while rules are added. The Allow*/Deny*
	// methods return nothing, so a bad argument has to be held until Build.
	errs []error
}

// New creates an empty Profile.
func New() *Profile {
	return &Profile{}
}

// note records a regex pattern problem for Build to report. Called by every
// rule constructor that accepts a Regex match.
func (p *Profile) note(match PathMatch, pattern string) {
	if match != Regex {
		return
	}
	if err := validateRegexPattern(pattern); err != nil {
		p.errs = append(p.errs, err)
	}
}

// AllowFileRead adds a rule allowing file-read* for the given path.
func (p *Profile) AllowFileRead(match PathMatch, path string) {
	p.note(match, path)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowFileReadWrite adds a rule allowing file-read* and file-write*
// for the given path.
func (p *Profile) AllowFileReadWrite(match PathMatch, path string) {
	p.note(match, path)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowFileReadWriteIOctl adds a rule allowing file-read*, file-write*,
// and file-ioctl for the given path.
func (p *Profile) AllowFileReadWriteIOctl(match PathMatch, path string) {
	p.note(match, path)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* file-ioctl (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowProcessExec adds a rule allowing process-exec for the given path.
func (p *Profile) AllowProcessExec(match PathMatch, path string) {
	p.note(match, path)
	p.rules = append(p.rules, rule{
		kind: kindExecAllow,
		sbpl: fmt.Sprintf("(allow process-exec (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// DenyProcessExec adds a rule denying process-exec for the given path.
func (p *Profile) DenyProcessExec(match PathMatch, path string) {
	p.note(match, path)
	p.rules = append(p.rules, rule{
		kind: kindExecDeny,
		sbpl: fmt.Sprintf("(deny process-exec (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowMachLookup adds a rule allowing mach-lookup for the given service name.
func (p *Profile) AllowMachLookup(serviceName string) {
	p.rules = append(p.rules, rule{
		kind: kindMachAllow,
		sbpl: fmt.Sprintf("(allow mach-lookup (global-name %q))", serviceName),
	})
}

// AllowMachLookupPrefix adds a rule allowing mach-lookup for services
// matching the given prefix.
func (p *Profile) AllowMachLookupPrefix(prefix string) {
	p.rules = append(p.rules, rule{
		kind: kindMachAllow,
		sbpl: fmt.Sprintf("(allow mach-lookup (global-name-prefix %q))", prefix),
	})
}

// DenyMachLookup adds a rule denying mach-lookup for the given service name.
func (p *Profile) DenyMachLookup(serviceName string) {
	p.rules = append(p.rules, rule{
		kind: kindMachDeny,
		sbpl: fmt.Sprintf("(deny mach-lookup (global-name %q))", serviceName),
	})
}

// DenyMachLookupPrefix adds a rule denying mach-lookup for services
// matching the given prefix.
func (p *Profile) DenyMachLookupPrefix(prefix string) {
	p.rules = append(p.rules, rule{
		kind: kindMachDeny,
		sbpl: fmt.Sprintf("(deny mach-lookup (global-name-prefix %q))", prefix),
	})
}

// AllowNetworkAll adds a rule allowing all network operations.
func (p *Profile) AllowNetworkAll() {
	p.rules = append(p.rules, rule{
		kind: kindNetworkAllow,
		sbpl: "(allow network*)",
	})
}

// AllowNetworkOutbound adds a rule allowing outbound network connections
// for the given protocol and host:port. The proto parameter must be a valid
// SBPL protocol identifier containing only lowercase letters (e.g., "tcp", "udp").
func (p *Profile) AllowNetworkOutbound(proto, hostPort string) {
	// Validate proto contains only [a-z] to prevent SBPL injection
	for _, c := range proto {
		if c < 'a' || c > 'z' {
			// Invalid proto — skip silently (will be caught by sandbox_init if wrong)
			return
		}
	}
	p.rules = append(p.rules, rule{
		kind: kindNetworkAllow,
		sbpl: fmt.Sprintf(`(allow network-outbound (remote %s "%s"))`, proto, hostPort),
	})
}

// AllowSystemEssentials adds all rules needed for basic macOS process
// operation: process ops, system libraries, dev files, common tool paths,
// TTY access, temp files, and IPC.
func (p *Profile) AllowSystemEssentials() {
	// Process operations
	p.rules = append(p.rules,
		rule{kind: kindOther, sbpl: "(allow process-fork)"},
		rule{kind: kindOther, sbpl: "(allow signal (target self))"},
		rule{kind: kindOther, sbpl: "(allow sysctl-read)"},
	)

	// Root directory. Without this every process under the profile dies with
	// SIGABRT before main runs: resolving any absolute path walks "/", and the
	// dynamic linker aborts rather than reporting the denial, so the failure
	// surfaces as a signal with no output and no sandbox log entry.
	//
	// (literal "/") grants read of the root directory itself, not its
	// subtrees -- the most it reveals is the names of the top-level
	// directories. file-read-metadata is not sufficient here; it was tried and
	// still aborts.
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: `(allow file-read* (literal "/"))`,
	})

	// Dev files + system libraries (combined file-read* rule)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read*\n" +
			"    (subpath \"/usr/lib\")\n" +
			"    (subpath \"/usr/share\")\n" +
			"    (subpath \"/System/Library\")\n" +
			"    (subpath \"/Library/Frameworks\")\n" +
			"    (subpath \"/private/var/db/dyld\")\n" +
			"    (literal \"/dev/random\")\n" +
			"    (literal \"/dev/urandom\"))",
	})

	// /dev/null must be writable, not just readable. It was in the read-only
	// list above, so any program redirecting output to it -- which is most of
	// them; git fails outright -- got EPERM on the open.
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read* file-write*\n" +
			"    (literal \"/dev/null\")\n" +
			"    (literal \"/dev/zero\"))",
	})

	// The xcode-select selector directory. It holds two root-owned symlinks
	// and nothing else; without read access every bash invocation prints
	// "Error opening /private/var/select/sh: Operation not permitted" before
	// doing its work.
	//
	// This does NOT make the /usr/bin Xcode shims (git, python3, clang, xcrun)
	// usable -- see the note on defaultExecAllowPaths in sandbox_compile.go.
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: `(allow file-read* (subpath "/private/var/select"))`,
	})

	// Common tool paths (read-only)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read*\n" +
			"    (subpath \"/usr/bin\")\n" +
			"    (subpath \"/usr/sbin\")\n" +
			"    (subpath \"/bin\")\n" +
			"    (subpath \"/sbin\")\n" +
			"    (subpath \"/usr/local/bin\")\n" +
			"    (subpath \"/opt/homebrew/bin\")\n" +
			"    (subpath \"/opt/homebrew/Cellar\"))",
	})

	// The rest of the Homebrew prefixes. /opt/homebrew/bin is a farm of
	// symlinks into Cellar, and a Homebrew binary loads its libraries from
	// lib/ and reads its own config from etc/ and share/ -- all outside the
	// two directories above, so git, node and anything linking a keg-only
	// library failed once the profile started being enforced.
	//
	// Read-only, and scoped to the directories Homebrew owns: /usr/local is
	// not granted wholesale, only the Intel-Homebrew subtrees within it.
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read*\n" +
			"    (subpath \"/opt/homebrew/opt\")\n" +
			"    (subpath \"/opt/homebrew/lib\")\n" +
			"    (subpath \"/opt/homebrew/etc\")\n" +
			"    (subpath \"/opt/homebrew/share\")\n" +
			"    (subpath \"/usr/local/Cellar\")\n" +
			"    (subpath \"/usr/local/opt\")\n" +
			"    (subpath \"/usr/local/lib\")\n" +
			"    (subpath \"/usr/local/etc\")\n" +
			"    (subpath \"/usr/local/share\"))",
	})

	// TTY access
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read* file-write*\n" +
			"    (regex " + quotePathForMatch(Regex, `^/dev/ttys[0-9]+$`) + ")\n" +
			"    (regex " + quotePathForMatch(Regex, `^/dev/pty[pqrs][0-9a-f]$`) + ")\n" +
			"    (literal \"/dev/tty\"))",
	})

	// Temp files
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read* file-write*\n" +
			"    (subpath \"/private/tmp\")\n" +
			"    (subpath \"/tmp\")\n" +
			"    (subpath \"/var/folders\"))",
	})

	// IPC
	p.rules = append(p.rules,
		rule{kind: kindOther, sbpl: "(allow ipc-posix*)"},
		rule{kind: kindOther, sbpl: "(allow mach-register)"},
	)
}

// Build renders the accumulated rules into a complete SBPL profile string.
// It returns an error if any non-regex path is relative.
func (p *Profile) Build() (string, error) {
	if len(p.errs) > 0 {
		return "", p.errs[0]
	}
	for _, r := range p.rules {
		if err := validateRule(r); err != nil {
			return "", err
		}
	}

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")

	// Allow rules first, then deny rules. SBPL evaluates rules in order and the
	// LAST matching rule decides, so a deny must come after any allow it is
	// meant to override.
	//
	// This used to be the other way round -- denies first, "for readability" --
	// which silently disabled every deny in the profile. defaultExecBlocklist
	// denies /usr/bin/tccutil, /usr/sbin/csrutil, /usr/bin/security and
	// /usr/sbin/systemsetup, but defaultExecAllowPaths then subpath-allows
	// /usr/bin and /usr/sbin, so each of those executables was allowed again by
	// a later rule. The same applied to every `decision: deny` command rule.
	//
	// Verified against sandbox-exec: with an allow(subpath /bin) after a
	// deny(literal /bin/echo), echo runs; with the deny last, execvp fails with
	// "Operation not permitted".
	for _, r := range p.rules {
		if !isDeny(r.kind) {
			b.WriteString(r.sbpl)
			b.WriteByte('\n')
		}
	}
	for _, r := range p.rules {
		if isDeny(r.kind) {
			b.WriteString(r.sbpl)
			b.WriteByte('\n')
		}
	}

	return b.String(), nil
}

// isDeny returns true for deny-class rule kinds.
func isDeny(k ruleKind) bool {
	switch k {
	case kindFileDeny, kindExecDeny, kindMachDeny, kindNetworkDeny:
		return true
	default:
		return false
	}
}

// matchStr returns the SBPL match keyword for the given PathMatch.
func matchStr(m PathMatch) string {
	switch m {
	case Literal:
		return "literal"
	case Subpath:
		return "subpath"
	case Regex:
		return "regex"
	default:
		return "literal"
	}
}

// quotePathForMatch escapes and quotes a path based on its PathMatch type.
// For Regex, the path is passed through unchanged (caller must provide valid
// SBPL regex syntax like #"pattern"#). For Literal and Subpath, backslashes
// and quotes are escaped and the result is wrapped in double quotes.
// This function never content-sniffs — the match type alone determines quoting.
// validateRegexPattern rejects patterns that cannot be expressed in an SBPL
// raw string.
//
// #"..." has no escape mechanism: the string ends at the first ". A pattern
// containing a double quote does not fail to parse -- it terminates early and
// whatever follows is read as further SBPL, so one rule silently becomes a
// different, valid one. This also catches a caller that supplies its own
// Swift-style #"..."# delimiters, which the sandbox parser rejects outright,
// taking the entire profile with it.
func validateRegexPattern(pattern string) error {
	if strings.Contains(pattern, `"`) {
		return fmt.Errorf(`regex pattern contains a double quote, which SBPL raw strings cannot escape (pass a bare pattern, not #"..."): %s`, pattern)
	}
	return nil
}

func quotePathForMatch(match PathMatch, path string) string {
	if match == Regex {
		// SBPL raw string: a leading #" and a plain closing ". The trailing-#
		// form (#"..."#) is Swift syntax, not SBPL, and the sandbox parser
		// rejects the whole profile with "undefined sharp expression" the
		// moment it reaches one -- which meant sandbox_init failed for every
		// profile CompileDarwinSandbox produced, since it always emits the TTY
		// regex rules. Raw strings are used rather than plain "..." so regex
		// backslashes reach the matcher instead of being consumed as string
		// escapes.
		//
		// The delimiters are added here rather than by the caller: this bug
		// existed because callers passed pre-delimited patterns straight
		// through, so nothing in the package ever checked them.
		return `#"` + path + `"`
	}
	escaped := strings.ReplaceAll(path, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// validateRule checks that non-regex paths in a rule are absolute.
// Only file and exec rules contain filesystem paths that must be absolute;
// mach-lookup and network rules use service names / host:port strings.
func validateRule(r rule) error {
	// Only validate path-based rule kinds.
	switch r.kind {
	case kindFileAllow, kindFileDeny, kindExecAllow, kindExecDeny:
		// These contain filesystem paths; validate below.
	default:
		return nil
	}

	// Regex rules carry patterns, not paths, so the path checks below do not
	// apply. Their own validation happens when the rule is added, in
	// validateRegexPattern -- not here, where only the rendered string is
	// available and the pattern boundaries are no longer recoverable.
	if strings.Contains(r.sbpl, "(regex ") {
		return nil
	}

	// Extract the quoted path from the rule.
	// Find the last quoted string in the rule.
	lastQuote := strings.LastIndex(r.sbpl, `"`)
	if lastQuote < 0 {
		return nil
	}

	// Walk backward to find the opening quote.
	openQuote := -1
	for i := lastQuote - 1; i >= 0; i-- {
		if r.sbpl[i] == '"' && (i == 0 || r.sbpl[i-1] != '\\') {
			openQuote = i
			break
		}
	}
	if openQuote < 0 {
		return nil
	}

	path := r.sbpl[openQuote+1 : lastQuote]
	// Unescape for validation.
	path = strings.ReplaceAll(path, `\"`, `"`)
	path = strings.ReplaceAll(path, `\\`, `\`)

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sbpl: path must be absolute, got %q", path)
	}
	return nil
}
