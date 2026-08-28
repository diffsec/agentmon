//go:build darwin

package policysock

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrepareSocketPath_CreatesTightDirectory pins the directory mode. A
// group- or world-writable directory lets another account replace the socket
// between daemon restarts, which is the whole reason this moved off /tmp.
func TestPrepareSocketPath_CreatesTightDirectory(t *testing.T) {
	base := t.TempDir()
	sock := filepath.Join(base, "agentmon", "policy.sock")

	if err := prepareSocketPath(sock); err != nil {
		t.Fatalf("prepareSocketPath: %v", err)
	}

	info, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != socketDirMode {
		t.Errorf("directory mode = %#o, want %#o", perm, socketDirMode)
	}
}

// TestPrepareSocketPath_TightensLooseDirectory covers the upgrade path.
// MkdirAll leaves an existing directory's mode alone, so a directory created
// before this check existed -- or by anything else -- would have stayed
// writable by other accounts. Tightening beats refusing here: ownership is
// verified separately, and refusing would leave the daemon unable to start.
func TestPrepareSocketPath_TightensLooseDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "agentmon")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := prepareSocketPath(filepath.Join(dir, "policy.sock")); err != nil {
		t.Fatalf("prepareSocketPath: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != socketDirMode {
		t.Errorf("directory mode = %#o, want %#o -- a loose directory was left loose", perm, socketDirMode)
	}
}

// TestPrepareSocketPath_RemovesOurStaleSocket: a socket left by a previous run
// of this daemon is ours to clear, and refusing it would make the daemon
// unable to restart.
func TestPrepareSocketPath_RemovesOurStaleSocket(t *testing.T) {
	// Not t.TempDir(): macOS puts it under /var/folders/... and the resulting
	// path exceeds sun_path's 104 bytes, so the bind fails with
	// "invalid argument" before the code under test is reached.
	base, err := os.MkdirTemp("/tmp", "amsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	sock := filepath.Join(base, "policy.sock")

	// SetUnlinkOnClose(false) is required: Go's unix listener removes the
	// socket file on Close, so a plain Close would leave nothing stale to find.
	addr, aerr := net.ResolveUnixAddr("unix", sock)
	if aerr != nil {
		t.Fatal(aerr)
	}
	ln, lerr := net.ListenUnix("unix", addr)
	if lerr != nil {
		t.Fatal(lerr)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()

	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("test setup: no socket at %s: %v", sock, err)
	}
	if err := prepareSocketPath(sock); err != nil {
		t.Fatalf("prepareSocketPath refused our own stale socket: %v", err)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Error("stale socket was not removed, so the listen would fail")
	}
}

// TestPrepareSocketPath_RefusesNonSocket is the destructive case. The old code
// called os.Remove unconditionally, so a regular file -- or anything else -- at
// the configured path was simply deleted.
func TestPrepareSocketPath_RefusesNonSocket(t *testing.T) {
	base := t.TempDir()
	sock := filepath.Join(base, "policy.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := prepareSocketPath(sock)
	if err == nil {
		t.Fatal("prepareSocketPath accepted a regular file at the socket path")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("error should say what it found, got: %v", err)
	}
	if _, statErr := os.Stat(sock); statErr != nil {
		t.Error("the file was destroyed despite the refusal")
	}
}

// TestPrepareSocketPath_RefusesUnwritableParent: MkdirAll failing must surface
// as a startup error naming the directory, not as a bare listen failure.
func TestPrepareSocketPath_RefusesUnwritableParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	base := t.TempDir()
	locked := filepath.Join(base, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	err := prepareSocketPath(filepath.Join(locked, "agentmon", "policy.sock"))
	if err == nil {
		t.Fatal("prepareSocketPath succeeded under an unwritable parent")
	}
	if !strings.Contains(err.Error(), "policy socket directory") {
		t.Errorf("error should name the directory, got: %v", err)
	}
}

// TestSocketModes documents the two constants against the reason they changed.
// 0666 was justified by a comment claiming the extension needed it; the
// extension runs as root, and root bypasses the permission check on connect().
func TestSocketModes(t *testing.T) {
	if socketFileMode&0o077 != 0 {
		t.Errorf("socketFileMode = %#o; group and other must have no access", socketFileMode)
	}
	if socketDirMode&0o077 != 0 {
		t.Errorf("socketDirMode = %#o; group and other must have no access", socketDirMode)
	}
}

// TestPrepareSocketPath_RefusesSymlinkedDirectory: owning a symlink says
// nothing about who owns its target, so a link we own pointing at a
// world-writable directory would reinstate exactly what this moved away from.
func TestPrepareSocketPath_RefusesSymlinkedDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(real, 0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "agentmon")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	err := prepareSocketPath(filepath.Join(link, "policy.sock"))
	if err == nil {
		t.Fatal("prepareSocketPath accepted a symlinked socket directory")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should name the symlink, got: %v", err)
	}
}
