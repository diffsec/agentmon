package helperbin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve_PrefersSiblingOverPath(t *testing.T) {
	// A binary next to the running executable must win over one on PATH, so a
	// bundle always runs its own helper rather than a stray copy installed
	// elsewhere on the machine.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	selfDir := filepath.Dir(self)

	name := "agentmon-helperbin-sibling-test"
	sibling := filepath.Join(selfDir, name)
	if err := os.WriteFile(sibling, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Skipf("cannot write next to the test binary (%v)", err)
	}
	t.Cleanup(func() { os.Remove(sibling) })

	pathDir := t.TempDir()
	decoy := filepath.Join(pathDir, name)
	if err := os.WriteFile(decoy, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	t.Setenv("PATH", pathDir)

	got := Resolve(name)
	if got == decoy {
		t.Fatalf("Resolve(%q) returned the PATH copy %q; the sibling next to the executable must win", name, got)
	}
	if got == "" {
		t.Fatalf("Resolve(%q) found nothing despite a sibling at %s", name, sibling)
	}
}

func TestResolve_FallsBackToPath(t *testing.T) {
	// The Linux packages install helpers into a PATH directory rather than
	// alongside the daemon, so the fallback has to keep working.
	dir := t.TempDir()
	name := "agentmon-helperbin-path-test"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("PATH", dir)

	if got := Resolve(name); got != p {
		t.Fatalf("Resolve(%q) = %q, want %q", name, got, p)
	}
}

func TestResolve_MissingReturnsEmpty(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := Resolve("agentmon-helperbin-definitely-absent"); got != "" {
		t.Fatalf("Resolve of an absent binary = %q, want empty", got)
	}
}

func TestResolve_NonExecutableIsNotAMatch(t *testing.T) {
	// A same-named data file must not be reported as the helper: callers exec
	// whatever this returns.
	dir := t.TempDir()
	name := "agentmon-helperbin-nonexec-test"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not a program"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("PATH", dir)

	if got := Resolve(name); got != "" {
		t.Fatalf("Resolve returned a non-executable file: %q", got)
	}
}

func TestResolve_AbsolutePathIsChecked(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "prog")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := Resolve(exe); got != exe {
		t.Fatalf("Resolve(%q) = %q, want the same path", exe, got)
	}
	if got := Resolve(filepath.Join(dir, "absent")); got != "" {
		t.Fatalf("Resolve of an absent absolute path = %q, want empty", got)
	}
}
