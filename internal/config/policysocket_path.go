package config

import (
	"os"
	"path/filepath"
)

// defaultPolicySocketPath returns where the macOS policy socket lives.
//
// os.UserConfigDir is $HOME/Library/Application Support on darwin, a directory
// the daemon owns. If it cannot be determined -- no HOME -- the fallback is a
// path under the process's own temporary directory rather than a shared one,
// because a world-writable rendezvous point is the thing being moved away from.
//
// macos/AgentMon/PolicySocketClient.swift derives the same path from the
// console user's home directory. The two must agree; there is no negotiation.
func defaultPolicySocketPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return filepath.Join(os.TempDir(), "agentmon", "policy.sock")
	}
	return filepath.Join(dir, "agentmon", "policy.sock")
}

// PolicySocketPathIsDefault reports whether the configured path is the one the
// system extension will look for.
//
// The extension cannot be told a custom path: it runs as root, starts
// independently of the daemon, and has no channel to the daemon that does not
// itself run over this socket. So a custom path silently costs all macOS
// enforcement, and callers use this to say so rather than leaving the operator
// to discover it.
func PolicySocketPathIsDefault(path string) bool {
	return path == defaultPolicySocketPath()
}
