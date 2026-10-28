//go:build darwin

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shipped file sets approvals.mode gui, which validateConfig refuses on
// any other OS, so this test runs on macOS only.

// shippedMacOSConfig is the file that scripts/assemble-macos-bundle.sh copies
// to AgentMon.app/Contents/Resources/config.yml.
const shippedMacOSConfig = "../../macos/AgentMon-files/config.yml"

// TestShippedMacOSConfig_LoadsUnderLaunchd loads the bundled config the way
// the LaunchAgent daemon does on a fresh install: from the bundle, with no
// user config, and with / as the working directory.
//
// The bundle used to ship the repository's config.yml. Its relative paths
// resolved against /, so the daemon exited with "mkdir data: read-only file
// system", and policies.dir pointed at /configs/policies.
func TestShippedMacOSConfig_LoadsUnderLaunchd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	src, err := filepath.Abs(shippedMacOSConfig)
	if err != nil {
		t.Fatal(err)
	}
	resources := filepath.Join(t.TempDir(), "AgentMon.app", "Contents", "Resources")
	if err := os.MkdirAll(resources, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknownFUSEKeys(b)) != 0 {
		t.Errorf("the shipped config has unknown sandbox.fuse keys: %v", unknownFUSEKeys(b))
	}
	path := filepath.Join(resources, "config.yml")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Chdir("/")
	cfg, _, err := LoadWithSource(path, ConfigSourceBundle)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	dataDir := GetUserDataDir()
	for name, p := range map[string]string{
		"server.unix_socket.path":     cfg.Server.UnixSocket.Path,
		"audit.output":                cfg.Audit.Output,
		"audit.storage.sqlite_path":   cfg.Audit.Storage.SQLitePath,
		"sessions.base_dir":           cfg.Sessions.BaseDir,
		"sandbox.fuse.mount_base_dir": cfg.Sandbox.FUSE.MountBaseDir,
	} {
		if !strings.HasPrefix(p, dataDir+string(filepath.Separator)) {
			t.Errorf("%s = %q, want a path under %s", name, p, dataDir)
		}
	}
	if want := filepath.Join(resources, "configs", "policies"); cfg.Policies.Dir != want {
		t.Errorf("policies.dir = %q, want the bundle's own policies at %q", cfg.Policies.Dir, want)
	}
	if cfg.Auth.Type != "local" {
		t.Errorf("auth.type = %q, want local: with none, an agent can call the API", cfg.Auth.Type)
	}
	if !cfg.Approvals.Enabled || cfg.Approvals.Mode != "gui" {
		t.Errorf("approvals = enabled %v, mode %q; want enabled gui, or approve rules allow without asking",
			cfg.Approvals.Enabled, cfg.Approvals.Mode)
	}
	if !strings.HasPrefix(cfg.Server.HTTP.Addr, "127.0.0.1:") {
		t.Errorf("server.http.addr = %q, want loopback", cfg.Server.HTTP.Addr)
	}
	if !cfg.Audit.Enabled {
		t.Error("audit is off")
	}
	if !cfg.Sandbox.Network.Enabled {
		t.Error("sandbox.network is off, so sessions get no network proxy")
	}
}
