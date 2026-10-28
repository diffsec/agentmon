package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadWithSource_UserConfigRelativePaths covers a user config with
// relative paths, such as a copy of the repository's config.yml in
// ~/Library/Application Support/agentmon.
func TestLoadWithSource_UserConfigRelativePaths(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(`
auth:
  api_key:
    keys_file: "./configs/api_keys.yaml"
sessions:
  base_dir: "./data/sessions"
sandbox:
  fuse:
    mount_base_dir: "./data/mounts"
policies:
  dir: "./configs/policies"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir("/")
	cfg, _, err := LoadWithSource(path, ConfigSourceUser)
	if err != nil {
		t.Fatal(err)
	}
	dataDir, configDir := GetUserDataDir(), GetUserConfigDir()
	for _, c := range []struct{ name, got, want string }{
		{"sessions.base_dir", cfg.Sessions.BaseDir, filepath.Join(dataDir, "data", "sessions")},
		{"sandbox.fuse.mount_base_dir", cfg.Sandbox.FUSE.MountBaseDir, filepath.Join(dataDir, "data", "mounts")},
		{"policies.dir", cfg.Policies.Dir, filepath.Join(configDir, "configs", "policies")},
		{"auth.api_key.keys_file", cfg.Auth.APIKey.KeysFile, filepath.Join(configDir, "configs", "api_keys.yaml")},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestLoadWithSource_ExplicitConfigKeepsRelativePaths: --config and
// AGENTMON_CONFIG keep paths relative to the working directory, which
// development runs from the repository rely on.
func TestLoadWithSource_ExplicitConfigKeepsRelativePaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("sessions:\n  base_dir: \"./data/sessions\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadWithSource(path, ConfigSourceEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sessions.BaseDir != "./data/sessions" {
		t.Errorf("sessions.base_dir = %q, want it unchanged", cfg.Sessions.BaseDir)
	}
}
