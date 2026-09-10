//go:build unix

package shim

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFileExclusive acquires an exclusive lock on the file.
func lockFileExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

// unlockFile releases the lock on the file.
func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}

// defaultSessionBaseDirs returns the directories a file-backed session id may
// live in, most preferred first.
//
// The /tmp fallback is per-uid. It used to be the shared "/tmp/agentmon", and
// /tmp is world-writable, so on a multi-user host any account could create
// that directory first and plant a symlink at session-global.sid: the shim
// then read the target's bytes as a session id and truncated the target when
// it wrote a new one (AUDIT H22). A per-uid name does not make the path
// unguessable -- nothing under /tmp is -- but it means the squatter has to
// win the race for one specific user, and EnsurePrivateDir refuses a
// directory it does not own, so losing that race is a fall-through to the
// next base dir rather than a compromise.
func defaultSessionBaseDirs(workspaceRoot string) []string {
	return []string{
		"/run/agentmon",
		fmt.Sprintf("/tmp/agentmon-%d", os.Geteuid()),
		workspaceRoot + "/.agentmon",
	}
}
