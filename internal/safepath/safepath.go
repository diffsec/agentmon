// Package safepath opens files and directories that live where an untrusted
// process can also write, without adopting whatever it finds there.
//
// The threat is a symlink planted at a path the daemon is about to write. An
// open that follows it hands the attacker two things: the daemon reads the
// target's bytes as though they were its own, and the daemon truncates and
// overwrites a file it never meant to touch. A predictable name under /tmp is
// all that is needed, because /tmp is world-writable and the attacker gets to
// go first.
//
// The rules here are the ones internal/platform/darwin/policysock already
// applies to the policy socket (AUDIT M25): create private directories 0700,
// refuse anything not owned by the effective user, and never follow a symlink
// at the final component.
//
// What this does NOT defend against, stated plainly: a process running as the
// same user. Ownership checks distinguish users, not processes, so an agent
// that escapes its sandbox and runs as the daemon's user can still plant a
// file the daemon will accept. Only running the daemon as a different user
// closes that, and it is the same limit policysock documents.
package safepath

import (
	"fmt"
	"os"
	"syscall"
)

// PrivateDirMode is the mode a private directory is created and kept at.
const PrivateDirMode os.FileMode = 0o700

// PrivateFileMode is the mode a private file is created with.
const PrivateFileMode os.FileMode = 0o600

// EnsurePrivateDir creates dir and every parent, then verifies dir is a real
// directory this user owns and tightens its mode.
//
// Tightening rather than refusing on a loose mode is deliberate, and matches
// prepareSocketPath: MkdirAll leaves an existing directory's mode alone, so a
// directory created before this check existed would be loose, and refusing
// would leave the daemon unable to start with no obvious remedy. Ownership is
// verified first, so fixing the mode is ours to do.
//
// Only dir itself is checked. A symlink further up the tree is not detectable
// this way, which is why callers put private directories under a root the user
// controls rather than under /tmp.
func EnsurePrivateDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("safepath: empty directory")
	}
	if err := os.MkdirAll(dir, PrivateDirMode); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use %s: it is a symlink, and owning the link says nothing about who owns its target", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use %s: it exists and is not a directory", dir)
	}
	if err := CheckOwnedByUs(dir, info); err != nil {
		return err
	}
	if err := os.Chmod(dir, PrivateDirMode); err != nil {
		return fmt.Errorf("tighten directory %s: %w", dir, err)
	}
	return nil
}

// CheckOwnedByUs reports an error unless path is owned by the effective user.
func CheckOwnedByUs(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine the owner of %s, so it cannot be trusted", path)
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("refusing to use %s: it is owned by uid %d, not by this process (uid %d)", path, st.Uid, uid)
	}
	return nil
}

// OpenPrivate opens path with O_NOFOLLOW and verifies what it got.
//
// O_NOFOLLOW refuses a symlink at the final component, which is the component
// an attacker can plant. The check after the open is against the file
// descriptor, not the path, so nothing can be swapped in between: a rename
// after the open leaves the descriptor pointing at what was verified.
func OpenPrivate(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		// A fifo here would block the daemon on open-for-read; a device could
		// be worse. Neither is something this code ever creates.
		return nil, fmt.Errorf("refusing to use %s: it is not a regular file (mode %s)", path, info.Mode())
	}
	if err := CheckOwnedByUs(path, info); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// WritePrivate writes data to path, replacing only a regular file this user
// owns.
//
// os.WriteFile is O_WRONLY|O_CREATE|O_TRUNC, which does two unwanted things at
// a predictable path: it follows a symlink, so the write lands wherever the
// attacker points it, and without O_EXCL it opens a file the attacker created
// first -- where the 0600 argument is ignored, because the mode applies only
// on creation. The attacker then reads whatever was written.
//
// The create is exclusive. An existing entry is inspected and removed only
// when it is a regular file this user owns; anything else is refused rather
// than deleted, because removing something sight unseen is how the previous
// bug got there.
func WritePrivate(path string, data []byte, perm os.FileMode) error {
	f, err := createExclusive(path, perm)
	if os.IsExist(err) {
		if rerr := removeIfOurs(path); rerr != nil {
			return rerr
		}
		f, err = createExclusive(path, perm)
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// createExclusive creates path, failing if anything is already there.
//
// O_NOFOLLOW is redundant next to O_EXCL -- an exclusive create fails with
// EEXIST on a symlink whether or not it is set, which is why no test
// distinguishes them. It stays because the flag says what the call means, and
// because a later edit that drops O_EXCL should not silently reintroduce
// symlink following.
func createExclusive(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
}

// removeIfOurs deletes path only when it is a regular file owned by this user.
func removeIfOurs(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// It went away between the failed create and now. The retry will
			// either succeed or fail on its own terms.
			return nil
		}
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace %s: it is a symlink, so removing it would be acting on a path someone else chose", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace %s: it is not a regular file (mode %s)", path, info.Mode())
	}
	if err := CheckOwnedByUs(path, info); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale %s: %w", path, err)
	}
	return nil
}
