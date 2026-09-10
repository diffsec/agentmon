package cli

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// writeConfig writes a config file and points AGENTMON_CONFIG at it.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func checkpointCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "checkpoint"}
	addCheckpointStorageFlag(cmd)
	return cmd
}

func TestResolveCheckpointDir_FlagWins(t *testing.T) {
	cmd := checkpointCmd(t)
	if err := cmd.Flags().Set("storage-dir", "/srv/checkpoints"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	if got := resolveCheckpointDir(cmd); got != "/srv/checkpoints" {
		t.Errorf("got %q, want the flag value", got)
	}
}

// TestResolveCheckpointDir_ReadsTheConfiguredStorageDir is the bug: the flag
// help promised "config sessions.checkpoints.storage_dir" and the code used a
// hardcoded /var/lib/agentmon/checkpoints, so a configured directory was
// ignored and `agentmon checkpoint list` looked somewhere nothing wrote.
func TestResolveCheckpointDir_ReadsTheConfiguredStorageDir(t *testing.T) {
	cfgPath := writeConfig(t, "sessions:\n  checkpoints:\n    storage_dir: \"/srv/ckpt\"\n")
	cmd := checkpointCmd(t)
	if err := cmd.Flags().Set("config", cfgPath); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	if got := resolveCheckpointDir(cmd); got != "/srv/ckpt" {
		t.Errorf("got %q, want the configured storage_dir", got)
	}
}

func TestResolveCheckpointDir_FallsBackToTheResolvedDataDir(t *testing.T) {
	cfgPath := writeConfig(t, "sessions:\n  max_sessions: 5\n")
	cmd := checkpointCmd(t)
	if err := cmd.Flags().Set("config", cfgPath); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	got := resolveCheckpointDir(cmd)
	if !strings.HasSuffix(got, "/checkpoints") {
		t.Fatalf("got %q, want a checkpoints directory", got)
	}
	// A non-root user cannot create /var/lib/agentmon, and both shipped units
	// run the daemon as the logged-in user.
	if os.Geteuid() != 0 && strings.HasPrefix(got, "/var/lib/") {
		t.Errorf("got %q, which this user cannot write", got)
	}
}

func TestResolveCheckpointDir_NoConfigStillReturnsADirectory(t *testing.T) {
	cmd := checkpointCmd(t)
	if err := cmd.Flags().Set("config", filepath.Join(t.TempDir(), "absent.yml")); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	// The checkpoint commands operate on a directory; a reachable default
	// beats refusing to run.
	if got := resolveCheckpointDir(cmd); got == "" {
		t.Fatal("no directory was resolved")
	}
}

func backupCmd(t *testing.T) *cobra.Command {
	t.Helper()
	return &cobra.Command{Use: "backup"}
}

func TestResolveBackupPaths_UsesTheConfiguredLocations(t *testing.T) {
	cfgPath := writeConfig(t, `audit:
  storage:
    sqlite_path: "/srv/agentmon/events.db"
policies:
  dir: "/srv/agentmon/policies"
`)
	p := resolveBackupPaths(backupCmd(t), cfgPath)
	if p.auditDB != "/srv/agentmon/events.db" {
		t.Errorf("auditDB = %q", p.auditDB)
	}
	if p.policies != "/srv/agentmon/policies" {
		t.Errorf("policies = %q", p.policies)
	}
	if p.config != cfgPath {
		t.Errorf("config = %q, want %q", p.config, cfgPath)
	}
}

// TestResolveBackupPaths_FallbackIsNotTheSystemPath: restore wrote to
// /etc/agentmon/config.yaml and /var/lib/agentmon/events.db whatever the
// installation looked like, so it either failed for a non-root user or, run as
// root against a user installation, wrote files the daemon never reads.
func TestResolveBackupPaths_FallbackIsNotTheSystemPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the system paths are writable")
	}
	p := resolveBackupPaths(backupCmd(t), filepath.Join(t.TempDir(), "absent.yml"))
	if strings.HasPrefix(p.auditDB, "/var/lib/") {
		t.Errorf("auditDB = %q, which this user cannot write", p.auditDB)
	}
	if p.auditDB == "" || p.policies == "" {
		t.Fatalf("paths = %+v, both must be set", p)
	}
	if !strings.HasSuffix(p.auditDB, "events.db") {
		t.Errorf("auditDB = %q", p.auditDB)
	}
}

// TestNoHardcodedSystemPathsInCLI is a source check over the three sites this
// change removed.
func TestNoHardcodedSystemPathsInCLI(t *testing.T) {
	for _, file := range []string{"checkpoint.go", "backup.go"} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Skipf("%s not readable: %v", file, err)
		}
		for _, bad := range []string{`"/var/lib/agentmon`, `"/etc/agentmon/config.yaml"`, `"/etc/agentmon/policies"`} {
			if strings.Contains(string(body), bad) {
				t.Errorf("%s hardcodes %s; resolve it from the config instead", file, bad)
			}
		}
	}
}

// makeBackupTar writes a minimal backup archive with the three entry names
// restore recognises.
func makeBackupTar(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar: %v", err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	entries := map[string]string{
		"config.yaml":           "sessions:\n  max_sessions: 1\n",
		"events.db":             "SQLite format 3\x00",
		"policies/default.yaml": "version: 1\nname: default\n",
	}
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)), ModTime: time.Now(),
		}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
}

// TestRestoreBackup_WritesWhereTheConfigSays drives the whole command.
//
// Restore hardcoded /etc/agentmon/config.yaml, /var/lib/agentmon/events.db and
// /etc/agentmon/policies, so it either failed for a non-root user or, run as
// root against a user installation, wrote files the daemon never reads.
func TestRestoreBackup_WritesWhereTheConfigSays(t *testing.T) {
	dest := t.TempDir()
	auditDB := filepath.Join(dest, "events.db")
	policies := filepath.Join(dest, "policies")
	cfgPath := writeConfig(t, "audit:\n  storage:\n    sqlite_path: \""+auditDB+"\"\npolicies:\n  dir: \""+policies+"\"\n")

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	makeBackupTar(t, archive)

	cmd := &cobra.Command{Use: "restore"}
	var out, errOut strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	if err := restoreBackup(cmd, archive, cfgPath, false, false); err != nil {
		t.Fatalf("restoreBackup: %v", err)
	}
	for _, want := range []string{auditDB, filepath.Join(policies, "default.yaml"), cfgPath} {
		if _, err := os.Stat(want); err != nil {
			t.Errorf("%s was not restored: %v", want, err)
		}
	}
	// Nothing may have gone to the system locations.
	if strings.Contains(out.String(), "/etc/agentmon") || strings.Contains(out.String(), "/var/lib/agentmon") {
		t.Errorf("restore reported a system path:\n%s", out.String())
	}
}

func TestRestoreBackup_DryRunReportsTheConfiguredDestinations(t *testing.T) {
	dest := t.TempDir()
	auditDB := filepath.Join(dest, "events.db")
	cfgPath := writeConfig(t, "audit:\n  storage:\n    sqlite_path: \""+auditDB+"\"\npolicies:\n  dir: \""+filepath.Join(dest, "policies")+"\"\n")

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	makeBackupTar(t, archive)

	cmd := &cobra.Command{Use: "restore"}
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&strings.Builder{})

	if err := restoreBackup(cmd, archive, cfgPath, false, true); err != nil {
		t.Fatalf("restoreBackup: %v", err)
	}
	if !strings.Contains(out.String(), auditDB) {
		t.Errorf("dry run did not name the configured audit db:\n%s", out.String())
	}
	if _, err := os.Stat(auditDB); err == nil {
		t.Error("a dry run wrote a file")
	}
}
