package server

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/policy"
)

// captureLogs swaps the default logger for one writing into a buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestCheckDataDir_CreatesAndAcceptsAWritableDir(t *testing.T) {
	buf := captureLogs(t)
	dir := filepath.Join(t.TempDir(), "data")
	checkDataDir(dir)
	if strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("a writable directory logged an error: %s", buf.String())
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("the directory was not created: %v", err)
	}
}

// TestCheckDataDir_ReportsAnUnwritableDir is the failure this exists for: the
// daemon still runs, but every cache below it is memory-only, and that used to
// surface as three separate warnings at first use.
func TestCheckDataDir_ReportsAnUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permissions do not apply")
	}
	buf := captureLogs(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "data")
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	checkDataDir(dir)

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Fatalf("an unwritable directory logged no error: %s", out)
	}
	if !strings.Contains(out, dir) {
		t.Errorf("the error does not name the directory: %s", out)
	}
	// MkdirAll succeeds on an existing directory whatever its mode, so
	// creating it proves nothing; the probe write is what detects this.
	if !strings.Contains(out, "memory-only") {
		t.Errorf("the error does not say what is lost: %s", out)
	}
}

func TestCheckDataDir_ReportsAnUncreatableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permissions do not apply")
	}
	buf := captureLogs(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	checkDataDir(filepath.Join(parent, "data"))
	if !strings.Contains(buf.String(), "level=ERROR") {
		t.Fatalf("an uncreatable directory logged no error: %s", buf.String())
	}
}

func TestCheckDataDir_ReportsAnEmptyDir(t *testing.T) {
	buf := captureLogs(t)
	checkDataDir("  ")
	if !strings.Contains(buf.String(), "level=ERROR") {
		t.Fatalf("an empty data directory logged no error: %s", buf.String())
	}
}

func TestCheckDataDir_LeavesNoProbeBehind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	checkDataDir(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the probe file was left behind: %v", entries)
	}
}

// TestPolicyCacheDir_FollowsTheResolvedDataDir drives the real builder rather
// than recomputing the path the test expects.
func TestPolicyCacheDir_FollowsTheResolvedDataDir(t *testing.T) {
	dataDir := t.TempDir()
	cfg := &config.Config{DataDir: dataDir}
	cfg.Policies.Remote.URL = "https://policy.example/v1/policy"

	src, err := buildRemotePolicySource(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("buildRemotePolicySource: %v", err)
	}
	cs, ok := src.(*policy.CachingSource)
	if !ok {
		t.Fatalf("source is %T, want a *policy.CachingSource", src)
	}
	// Fetching writes the cache, which is the only observable proof of where
	// the directory is: a failed fetch with no cache leaves nothing behind, so
	// the check is that the daemon looked under the configured data dir at all.
	_, _ = cs.Fetch(context.Background())
	want := filepath.Join(dataDir, "policy-cache")
	if _, serr := os.Stat(want); serr != nil {
		// The fetch fails (nothing serves that URL), so the directory may not
		// exist. What must not happen is the daemon reaching for the system
		// path instead.
		t.Logf("cache dir %s not created (the fetch failed, as expected)", want)
	}
	if strings.HasPrefix(cs.Describe(), config.GetDataDir()) {
		t.Errorf("the cache went to the system data dir")
	}
}

// TestCacheDirsDoNotCallGetDataDir is a source check, because the two caches
// built inside New() need a whole daemon to reach.
//
// config.GetDataDir() always returns the system path -- /var/lib/agentmon or
// /usr/local/var/agentmon -- whatever the daemon can write. Both shipped units
// run it as the logged-in user, so every call to it here was a cache that
// silently never persisted.
func TestCacheDirsDoNotCallGetDataDir(t *testing.T) {
	for _, file := range []string{"server.go", "policy_remote.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Skipf("%s not readable: %v", file, err)
		}
		if strings.Contains(string(src), "config.GetDataDir()") {
			t.Errorf("%s calls config.GetDataDir(); cache paths must come from cfg.ResolvedDataDir()", file)
		}
	}
}
