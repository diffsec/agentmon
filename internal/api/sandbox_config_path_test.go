package api

import (
	"strings"
	"testing"
)

// TestSandboxConfigDir_IsNotUnderTmp pins the move off the old path.
//
// The sandbox config is the policy constraining the child: the compiled SBPL
// profile, the allowed paths, the mach-service lists. It was written to
// /tmp/agentmon-sandbox-<session>.json, where the name is predictable and the
// parent is world-writable, so any account on the host could pre-create the
// path and read the policy the daemon then wrote into it.
func TestSandboxConfigDir_IsNotUnderTmp(t *testing.T) {
	dir := sandboxConfigDir()
	if dir == "" {
		t.Fatal("sandboxConfigDir() is empty")
	}
	if strings.HasPrefix(dir, "/tmp/") || dir == "/tmp" {
		t.Fatalf("sandboxConfigDir() = %q, which is back under the world-writable parent", dir)
	}
	if !strings.HasSuffix(dir, "/sandbox") {
		t.Errorf("sandboxConfigDir() = %q, want a dedicated subdirectory", dir)
	}
}
