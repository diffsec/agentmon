package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvedDataDir_UsesTheConfiguredValue(t *testing.T) {
	cfg := &Config{DataDir: "/srv/agentmon"}
	if got := cfg.ResolvedDataDir(); got != "/srv/agentmon" {
		t.Errorf("ResolvedDataDir() = %q, want the configured value", got)
	}
}

func TestResolvedDataDir_FallsBackForAZeroConfig(t *testing.T) {
	// Tests across the tree build Config{} directly; a daemon always goes
	// through Load, which fills DataDir in.
	var cfg Config
	if got := cfg.ResolvedDataDir(); got != GetDataDir() {
		t.Errorf("ResolvedDataDir() = %q, want %q", got, GetDataDir())
	}
	if got := (*Config)(nil).ResolvedDataDir(); got != GetDataDir() {
		t.Errorf("nil receiver: %q", got)
	}
	blank := &Config{DataDir: "   "}
	if got := blank.ResolvedDataDir(); got != GetDataDir() {
		t.Errorf("whitespace data_dir: %q", got)
	}
}

// TestSystemOrUserDataDir_NonRootGetsAWritablePath is the bug: a user-level
// daemon reading a system config still cannot create /var/lib/agentmon, and
// both shipped units run the daemon as the logged-in user.
func TestSystemOrUserDataDir_NonRootGetsAWritablePath(t *testing.T) {
	got := systemOrUserDataDir()
	if os.Geteuid() == 0 {
		if got != GetDataDir() {
			t.Errorf("running as root: got %q, want the system path %q", got, GetDataDir())
		}
		return
	}
	if got == GetDataDir() {
		t.Fatalf("non-root resolved to the system path %q, which it cannot write", got)
	}
	if got != GetUserDataDir() {
		t.Errorf("got %q, want the user data dir %q", got, GetUserDataDir())
	}
}

func TestApplyDefaults_FillsDataDirAndDerivesFromIt(t *testing.T) {
	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceUser, "")
	if cfg.DataDir == "" {
		t.Fatal("data_dir was not defaulted")
	}
	if cfg.DataDir != GetUserDataDir() {
		t.Errorf("data_dir = %q, want %q for a user config", cfg.DataDir, GetUserDataDir())
	}
	// Everything derived from the data dir has to move with it, or an override
	// is one setting for the caches and another for sessions.
	if want := filepath.Join(cfg.DataDir, "sessions"); cfg.Sessions.BaseDir != want {
		t.Errorf("sessions.base_dir = %q, want %q", cfg.Sessions.BaseDir, want)
	}
}

func TestApplyDefaults_ExplicitDataDirWins(t *testing.T) {
	cfg := &Config{DataDir: "/srv/agentmon"}
	applyDefaultsWithSource(cfg, ConfigSourceSystem, "")
	if cfg.DataDir != "/srv/agentmon" {
		t.Fatalf("data_dir = %q, the explicit value was overwritten", cfg.DataDir)
	}
	// One setting, not one per consumer.
	if want := filepath.Join("/srv/agentmon", "sessions"); cfg.Sessions.BaseDir != want {
		t.Errorf("sessions.base_dir = %q, want %q derived from the override", cfg.Sessions.BaseDir, want)
	}
}

func TestRepoConfigYML_DataDirIsCommentedOut(t *testing.T) {
	data, err := os.ReadFile("../../config.yml")
	if err != nil {
		t.Skipf("config.yml not readable: %v", err)
	}
	// An uncommented data_dir in the shipped config would pin every
	// deployment to one path and undo the euid-aware default.
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "data_dir:") {
			t.Fatalf("config.yml sets data_dir: %q", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(string(data), "data_dir") {
		t.Error("config.yml does not mention data_dir at all")
	}
}
