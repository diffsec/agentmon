//go:build darwin

package sbpl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDenyIsActuallyEnforced runs a profile this package generated through the
// real sandbox, rather than asserting where substrings land in the output.
//
// It exists because the ordering bug was invisible to string-position tests:
// the profile looked correct and every unit test passed while the deny it
// contained did nothing. SBPL evaluates rules in order and the last match wins,
// so a deny emitted before a covering allow is silently discarded.
func TestDenyIsActuallyEnforced(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}

	p := New()
	p.AllowFileRead(Subpath, "/")
	// The allow is deliberately broad and registered first: it is the covering
	// rule the deny has to beat.
	p.AllowProcessExec(Subpath, "/bin")
	p.DenyProcessExec(Literal, "/bin/echo")

	profile, err := p.Build()
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}

	path := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	out, err := exec.Command("sandbox-exec", "-f", path, "/bin/echo", "ECHO_RAN").CombinedOutput()
	if err == nil || strings.Contains(string(out), "ECHO_RAN") {
		t.Fatalf("denied executable ran under the generated profile; the deny was ignored.\noutput: %s\nprofile:\n%s",
			out, profile)
	}
	if !strings.Contains(string(out), "not permitted") {
		t.Fatalf("expected an EPERM-style refusal, got: %s\nprofile:\n%s", out, profile)
	}
}

// TestSystemEssentialsProfileLoadsAndRuns checks that a profile built from
// AllowSystemEssentials is one the sandbox will actually accept and run a
// process under.
//
// Two bugs made it into the tree behind assertions that only read the
// generated text, and neither weakened the sandbox -- both disabled it:
//
//   - The TTY rules used Swift raw-string delimiters, #"..."#. The parser
//     rejects the whole profile with "undefined sharp expression", so
//     sandbox_init failed and agentmon-macwrap exited before exec'ing
//     anything.
//   - No rule granted read of the root directory. Resolving any absolute path
//     walks "/", and the dynamic linker aborts on the denial rather than
//     reporting it, so every process died with SIGABRT, no output, no log.
//
// TestDenyIsActuallyEnforced above cannot catch either: it builds a minimal
// profile with no system-essentials rules in it.
func TestSystemEssentialsProfileLoadsAndRuns(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}

	p := New()
	p.AllowSystemEssentials()
	p.AllowProcessExec(Subpath, "/bin")

	profile, err := p.Build()
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}

	path := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	out, err := exec.Command("sandbox-exec", "-f", path, "/bin/echo", "ESSENTIALS_OK").CombinedOutput()
	if err != nil {
		t.Fatalf("a profile built from AllowSystemEssentials could not run /bin/echo: %v\noutput: %s\nprofile:\n%s",
			err, out, profile)
	}
	if !strings.Contains(string(out), "ESSENTIALS_OK") {
		t.Fatalf("expected ESSENTIALS_OK, got: %s\nprofile:\n%s", out, profile)
	}
}
