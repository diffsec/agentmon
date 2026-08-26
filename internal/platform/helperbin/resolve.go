// Package helperbin resolves the auxiliary binaries agentmon execs at runtime
// (agentmon-macwrap, agentmon-stub, agentmon-shell-shim).
package helperbin

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Resolve locates a helper binary that ships alongside the running
// agentmon executable, falling back to PATH.
//
// Callers used to use exec.LookPath(name) alone, which only searches PATH. That
// is wrong for the primary macOS distribution: the binaries live inside
// /Applications/AgentMon.app/Contents/MacOS/, a directory that is not on PATH
// for a daemon launched by launchd. agentmon-macwrap could therefore be present
// in the bundle and still be reported "not found", silently skipping seatbelt
// enforcement -- the same class of silent degradation Phase 2 removed.
//
// The executable's own directory is checked first so a bundle always resolves
// its own helper rather than an unrelated copy earlier on PATH. Symlinks are
// resolved because the Homebrew cask symlinks these binaries into its bin
// directory; without EvalSymlinks the sibling lookup would search the symlink
// farm instead of Contents/MacOS.
//
// Returns an absolute path, or "" if the binary cannot be found.
func Resolve(name string) string {
	if filepath.IsAbs(name) {
		if isExecutableFile(name) {
			return name
		}
		return ""
	}

	if self, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		candidate := filepath.Join(filepath.Dir(self), name)
		if isExecutableFile(candidate) {
			return candidate
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	return ""
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}
