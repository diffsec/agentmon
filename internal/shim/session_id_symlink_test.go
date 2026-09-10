//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveSessionID_SymlinkedSessionFileIsRefused is AUDIT H22 end to end.
//
// The session file used to be opened with O_RDWR|O_CREATE under a 0755
// directory in world-writable /tmp. An attacker who created the path first as
// a symlink got the shim reading the target's bytes back as the session id and
// then truncating the target to write a new one.
func TestResolveSessionID_SymlinkedSessionFileIsRefused(t *testing.T) {
	base := t.TempDir()
	workspace := t.TempDir()

	victim := filepath.Join(t.TempDir(), "victim")
	const victimBody = "not a session id\n"
	if err := os.WriteFile(victim, []byte(victimBody), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(base, "session-global.sid")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// scope=global, so the file is base/session-global.sid. The default scope
	// is workspace, and a symlink planted at the global name is simply never
	// opened -- which is how the first version of this test passed against the
	// unfixed code.
	id, path, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv: func(k string) string {
			if k == "AGENTMON_SESSION_SCOPE" {
				return "global"
			}
			return ""
		},
		WorkDir:  workspace,
		BaseDirs: []string{base},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID: %v", err)
	}
	if strings.TrimSpace(id) == strings.TrimSpace(victimBody) {
		t.Fatalf("the victim's contents were returned as the session id: %q", id)
	}
	if path == filepath.Join(base, "session-global.sid") {
		t.Errorf("the symlinked path was adopted as the session file")
	}

	body, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("read victim: %v", rerr)
	}
	if string(body) != victimBody {
		t.Fatalf("the victim file was overwritten: %q", body)
	}
}

func TestEnsureSessionFilePath_CreatesPrivateDirectories(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base")
	path, err := ensureSessionFilePath(base, "workspace", "abc123")
	if err != nil {
		t.Fatalf("ensureSessionFilePath: %v", err)
	}
	for _, dir := range []string{base, filepath.Dir(path)} {
		info, serr := os.Stat(dir)
		if serr != nil {
			t.Fatalf("stat %s: %v", dir, serr)
		}
		// The session id is a capability: whoever reads it can act as that
		// session against the daemon.
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s mode = %o, want 700", dir, perm)
		}
	}
}

func TestEnsureSessionFilePath_RefusesADirectoryWeDoNotOwn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; every directory is ours")
	}
	// /usr is root-owned and a real directory on both Linux and macOS (/tmp
	// is a symlink on macOS and would trip a different check). This is the
	// shape of a squatted base directory: present, and someone else's.
	if _, err := ensureSessionFilePath("/usr", "global", ""); err == nil {
		t.Fatal("a base directory owned by another uid was accepted")
	}
}

func TestDefaultSessionBaseDirs_TmpFallbackIsPerUser(t *testing.T) {
	dirs := defaultSessionBaseDirs("/workspace")
	var tmp string
	for _, d := range dirs {
		if strings.HasPrefix(d, "/tmp/") {
			tmp = d
		}
	}
	if tmp == "" {
		t.Fatal("no /tmp fallback")
	}
	// The shared "/tmp/agentmon" meant one squatter denied every user on the
	// host, and won the race against all of them at once.
	if tmp == "/tmp/agentmon" {
		t.Fatal("the /tmp fallback is still shared across users")
	}
	if !strings.HasPrefix(tmp, "/tmp/agentmon-") {
		t.Errorf("/tmp fallback = %q", tmp)
	}
}

// TestResolveSessionID_SymlinkedWorkspaceFileIsRefused covers the default
// scope, whose filename is derived from the workspace root.
func TestResolveSessionID_SymlinkedWorkspaceFileIsRefused(t *testing.T) {
	base := t.TempDir()
	workspace := t.TempDir()

	victim := filepath.Join(t.TempDir(), "victim")
	const victimBody = "not a session id\n"
	if err := os.WriteFile(victim, []byte(victimBody), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	// Ask for the path the resolver will use, then plant the symlink there.
	target, err := ensureSessionFilePath(base, "workspace", hashKey(workspace))
	if err != nil {
		t.Fatalf("ensureSessionFilePath: %v", err)
	}
	if err := os.Symlink(victim, target); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	id, _, err := ResolveSessionID(ResolveSessionIDOptions{
		Getenv:   func(string) string { return "" },
		WorkDir:  workspace,
		BaseDirs: []string{base},
	})
	if err != nil {
		t.Fatalf("ResolveSessionID: %v", err)
	}
	if strings.TrimSpace(id) == strings.TrimSpace(victimBody) {
		t.Fatalf("the victim's contents were returned as the session id: %q", id)
	}
	if body, rerr := os.ReadFile(victim); rerr != nil || string(body) != victimBody {
		t.Fatalf("the victim file was modified: %q (%v)", body, rerr)
	}
}
