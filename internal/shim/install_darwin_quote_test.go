//go:build darwin

package shim

import (
	"os/exec"
	"strings"
	"testing"
)

// TestShellQuote_NeutralisesInjection pins AUDIT M57. The agentmon binary path
// is interpolated into a 0755 shell script that runs on every wrapped shell
// start, so a path containing shell metacharacters used to execute them with
// the user's privileges.
//
// Each case is checked by asking a real shell to print the quoted word back.
// Byte-for-byte equality is the whole test: if the shell had expanded,
// substituted or executed any part of the word, the output would differ. (An
// earlier version of this test also grepped the output for marker strings,
// which was wrong -- the inputs contain those markers literally, so correct
// quoting reproduces them.)
func TestShellQuote_NeutralisesInjection(t *testing.T) {
	cases := []string{
		"/usr/local/bin/agentmon",
		"/opt/my apps/agentmon",
		"/tmp/x'; echo INJECTED; '",
		"/a'b",
		`/weird/$(echo SUBSTITUTED)`,
		"/back`echo TICKED`tick",
		`/dollar$HOME/agentmon`,
	}

	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			script := "printf '%s' " + shellQuote(in)
			out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("shell rejected quoted word %q: %v (%s)", shellQuote(in), err, out)
			}
			if string(out) != in {
				t.Errorf("quoting failed -- the shell altered or executed part of the word:\n  in:     %q\n  out:    %q\n  quoted: %s", in, out, shellQuote(in))
			}
		})
	}
}

func TestValidShellName(t *testing.T) {
	valid := []string{"sh", "bash", "zsh", "fish", "dash", "bash-5"}
	for _, n := range valid {
		if !validShellName(n) {
			t.Errorf("validShellName(%q) = false, want true", n)
		}
	}
	invalid := []string{"", "sh; rm -rf ~", "../../etc/passwd", "sh space", "a'b", "$(id)", strings.Repeat("x", 33)}
	for _, n := range invalid {
		if validShellName(n) {
			t.Errorf("validShellName(%q) = true, want false", n)
		}
	}
}
