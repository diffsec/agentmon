//go:build darwin

package policysock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// socketFileMode is the mode the policy socket is created with.
//
// It used to be 0666, justified in a comment as being needed "so the system
// extension (running as root in a sandbox) can connect". That is not how unix
// sockets work: connect() needs write permission on the socket file, and root
// bypasses that check. Measured -- the extension runs as uid 0 while the daemon
// runs as the logged-in user -- so 0666 bought nothing and exposed the socket
// to every account on the machine.
const socketFileMode = 0o600

// socketDirMode is the mode the socket's parent directory is created with.
const socketDirMode = 0o700

// prepareSocketPath makes the socket's directory safe to bind in and clears any
// stale socket, refusing rather than adopting anything it does not own.
//
// The previous code did an unconditional os.Remove followed by net.Listen on
// /tmp/agentmon-policy.sock. Two things were wrong with that. /tmp is
// world-writable, so any account on the machine could interfere with the
// rendezvous point that carries every policy decision. And removing whatever is
// at the path, sight unseen, means the daemon will happily take over a path
// another process placed there -- the one case where stopping is the correct
// response.
//
// What this does NOT defend against, stated plainly: the daemon is installed as
// a LaunchAgent and runs as the logged-in user, so the socket must live
// somewhere that user can write. A process running as that same user -- which
// includes a sandboxed agent that escapes its policy -- can still bind the path
// while the daemon is not holding it. Filesystem permissions cannot fix that
// for a user-level daemon; running the daemon as root would. The peer checks on
// both ends limit the damage to denial of enforcement rather than forged
// policy: ValidatePeer requires clients signed by the expected team, and the
// extension validates the server's signature before sending anything.
func prepareSocketPath(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, socketDirMode); err != nil {
		return fmt.Errorf("create policy socket directory %s: %w", dir, err)
	}
	if err := checkDirOwnership(dir); err != nil {
		return err
	}
	// Tighten rather than refuse. MkdirAll leaves an existing directory's mode
	// alone, so a directory created before this check existed would be loose --
	// and refusing would leave the daemon unable to start with no obvious
	// remedy. Ownership was verified above, so fixing the mode is ours to do.
	if err := os.Chmod(dir, socketDirMode); err != nil {
		return fmt.Errorf("tighten policy socket directory %s: %w", dir, err)
	}

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect policy socket path %s: %w", path, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to use policy socket path %s: it exists and is not a socket (mode %s), so removing it could destroy unrelated data", path, info.Mode())
	}
	if err := checkOwnedByUs(path, info); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale policy socket %s: %w", path, err)
	}
	return nil
}

// checkDirOwnership refuses a socket directory that someone else owns, or that
// is a symlink. A symlink is refused because the ownership of the link says
// nothing about the ownership of its target: a link we own can point at a
// world-writable directory, which is precisely the arrangement being moved away
// from.
func checkDirOwnership(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect policy socket directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use policy socket directory %s: it is a symlink, and owning the link says nothing about who owns its target", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use policy socket directory %s: it exists and is not a directory", dir)
	}
	return checkOwnedByUs(dir, info)
}

// checkOwnedByUs reports an error unless the path is owned by the effective
// user, or by root while we are root.
func checkOwnedByUs(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine the owner of %s, so it cannot be trusted", path)
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("refusing to use %s: it is owned by uid %d, not by this process (uid %d)", path, st.Uid, uid)
	}
	return nil
}
