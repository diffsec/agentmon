package safepath

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEnsurePrivateDir_CreatesAt0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The session id in here is a capability. 0755 published it to every
	// account on the host.
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %o, want 700", perm)
	}
}

func TestEnsurePrivateDir_TightensALooseExistingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	// Refusing instead would leave a daemon that ran before this check
	// existed unable to start, with no obvious remedy.
	info, _ := os.Stat(dir)
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %o after tightening, want 700", perm)
	}
}

func TestEnsurePrivateDir_RefusesASymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := EnsurePrivateDir(link)
	if err == nil {
		t.Fatal("a symlinked directory was accepted")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v", err)
	}
}

func TestEnsurePrivateDir_RefusesAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := EnsurePrivateDir(path); err == nil {
		t.Fatal("a regular file was accepted as a directory")
	}
}

// TestOpenPrivate_RefusesASymlink is AUDIT H22: the shim opened its session
// file with O_RDWR|O_CREATE and no O_NOFOLLOW, so a symlink planted at a
// predictable /tmp path was read as the session id and then truncated.
func TestOpenPrivate_RefusesASymlink(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("secret contents\n"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	planted := filepath.Join(root, "session-global.sid")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	f, err := OpenPrivate(planted, os.O_RDWR|os.O_CREATE, PrivateFileMode)
	if err == nil {
		f.Close()
		t.Fatal("the symlink was followed")
	}
	if !errors.Is(err, syscall.ELOOP) && !strings.Contains(err.Error(), "too many levels") {
		t.Errorf("error = %v, want ELOOP from O_NOFOLLOW", err)
	}

	// The victim must be untouched: not read, and above all not truncated.
	body, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("read victim: %v", rerr)
	}
	if string(body) != "secret contents\n" {
		t.Fatalf("victim was modified: %q", body)
	}
}

func TestOpenPrivate_CreatesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sid")
	f, err := OpenPrivate(path, os.O_RDWR|os.O_CREATE, PrivateFileMode)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.WriteString("session-1\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	again, err := OpenPrivate(path, os.O_RDWR|os.O_CREATE, PrivateFileMode)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	buf := make([]byte, 32)
	n, _ := again.Read(buf)
	if string(buf[:n]) != "session-1\n" {
		t.Errorf("read %q, want the written id", buf[:n])
	}
}

func TestOpenPrivate_RefusesANonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Opening a fifo for read blocks until a writer arrives, which would hang
	// the daemon. O_NONBLOCK lets the open return so the type check can run.
	f, err := OpenPrivate(path, os.O_RDONLY|syscall.O_NONBLOCK, PrivateFileMode)
	if err == nil {
		f.Close()
		t.Fatal("a fifo was accepted")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error = %v", err)
	}
}

// TestWritePrivate_RefusesASymlink is the sandbox-config half: os.WriteFile
// followed a planted symlink and overwrote whatever it pointed at.
func TestWritePrivate_RefusesASymlink(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("important\n"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	planted := filepath.Join(root, "sandbox-abc.json")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := WritePrivate(planted, []byte(`{"policy":"secret"}`), PrivateFileMode); err == nil {
		t.Fatal("the symlink was followed and the victim overwritten")
	}
	body, _ := os.ReadFile(victim)
	if string(body) != "important\n" {
		t.Fatalf("victim was overwritten: %q", body)
	}
}

// TestWritePrivate_DoesNotFillInAPreCreatedFile is the other half of the same
// bug. os.WriteFile has no O_EXCL, so a file the attacker created first is
// opened rather than created, and the 0600 argument is ignored -- the mode
// applies only on creation, so the attacker's 0666 stands and they read the
// policy back out.
func TestWritePrivate_DoesNotFillInAPreCreatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-abc.json")
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	// Same uid in a test, so the file is ours and replacing it is correct.
	// What must not happen is writing into the file as it stands.
	if err := WritePrivate(path, []byte(`{"policy":"secret"}`), PrivateFileMode); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600: the pre-created mode survived, so the policy is readable", perm)
	}
}

func TestWritePrivate_WritesAndIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	body := []byte(`{"allow":["/tmp"]}`)
	if err := WritePrivate(path, body, PrivateFileMode); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content = %q", got)
	}
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestWritePrivate_RefusesToReplaceANonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Removing something sight unseen is how the previous bug got there.
	if err := WritePrivate(path, []byte("x"), PrivateFileMode); err == nil {
		t.Fatal("a fifo was replaced")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Error("the fifo was removed anyway")
	}
}

func TestCheckOwnedByUs_AcceptsOurOwnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mine")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, _ := os.Lstat(path)
	if err := CheckOwnedByUs(path, info); err != nil {
		t.Errorf("our own file was refused: %v", err)
	}
}

func TestCheckOwnedByUs_RejectsAnotherUsersFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; /etc/passwd is ours")
	}
	// A file this user demonstrably does not own.
	info, err := os.Lstat("/etc/passwd")
	if err != nil {
		t.Skipf("stat /etc/passwd: %v", err)
	}
	if err := CheckOwnedByUs("/etc/passwd", info); err == nil {
		t.Fatal("a file owned by another uid was accepted")
	}
}

func TestOpenPrivate_RefusesAnotherUsersFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; /etc/passwd is ours")
	}
	// The helper is tested separately; this pins that OpenPrivate actually
	// calls it. Read-only, so nothing is at risk if the check is missing --
	// which is the point: it must be refused anyway.
	f, err := OpenPrivate("/etc/passwd", os.O_RDONLY, PrivateFileMode)
	if err == nil {
		f.Close()
		t.Fatal("a file owned by another uid was opened")
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("error = %v, want the ownership refusal", err)
	}
}

func TestEnsurePrivateDir_RefusesADirectoryWeDoNotOwn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; every directory is ours")
	}
	// /usr is root-owned and a real directory on both Linux and macOS, where
	// /tmp is a symlink to /private/tmp and would trip the symlink check
	// first. This is the shape of a squatted base directory: present, and
	// someone else's.
	const notOurs = "/usr"
	err := EnsurePrivateDir(notOurs)
	if err == nil {
		t.Fatal("a directory owned by another uid was accepted")
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("error = %v, want the ownership refusal", err)
	}
	// And it must not have been chmodded on the way past: the ownership check
	// has to run before the tighten, or this "fix" would break the host.
	if info, serr := os.Stat(notOurs); serr == nil && info.Mode().Perm() == 0o700 {
		t.Fatalf("%s was tightened to 0700", notOurs)
	}
}
