//go:build darwin && cgo

package main

import (
	"slices"
	"testing"
)

// TestSandboxedEnv_StripsWrapperConfig pins AUDIT M58. The wrapper used to hand
// os.Environ() straight to syscall.Exec, so the sandboxed process inherited the
// full policy constraining it -- the compiled SBPL profile, the allowed paths
// and the mach-service lists -- and could read the exact shape of its own
// sandbox.
func TestSandboxedEnv_StripsWrapperConfig(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"AGENTMON_SANDBOX_CONFIG={\"compiled_profile\":\"(version 1)(deny default)\"}",
		"AGENTMON_SESSION_ID=session-1",
		"AGENTMON_SANDBOX_CONFIG_FILE=/tmp/cfg.json",
		"HOME=/Users/test",
	}

	got := sandboxedEnv(in)

	for _, banned := range sandboxConfigVars {
		for _, kv := range got {
			if len(kv) > len(banned) && kv[:len(banned)+1] == banned+"=" {
				t.Errorf("%s leaked to the sandboxed child: %q", banned, kv)
			}
		}
	}

	// Everything else must survive: the child still needs its session marker
	// and a working environment.
	for _, want := range []string{"PATH=/usr/bin", "AGENTMON_SESSION_ID=session-1", "HOME=/Users/test"} {
		if !slices.Contains(got, want) {
			t.Errorf("sandboxedEnv dropped %q; got %v", want, got)
		}
	}
}

// A value containing "=" must not confuse the split.
func TestSandboxedEnv_HandlesEqualsInValue(t *testing.T) {
	in := []string{"FOO=a=b=c", "AGENTMON_SANDBOX_CONFIG=x=y"}
	got := sandboxedEnv(in)
	if !slices.Contains(got, "FOO=a=b=c") {
		t.Errorf("value containing '=' was mangled or dropped: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("expected only FOO to survive, got %v", got)
	}
}
