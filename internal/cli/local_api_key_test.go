package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/diffsec/agentmon/internal/auth"
	"github.com/diffsec/agentmon/internal/config"
)

// TestResolvedAPIKey: the client options carry an explicit key first, and otherwise the
// key a daemon with auth.type local stored, so that local use needs no flag.
func TestResolvedAPIKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", "")

	c := &clientConfig{}
	if got := c.cliOptions().APIKey; got != "" {
		t.Errorf("no key anywhere: got %q, want \"\"", got)
	}

	path := filepath.Join(config.GetUserDataDir(), auth.LocalKeyFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stored-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.cliOptions().APIKey; got != "stored-key" {
		t.Errorf("stored key: got %q, want \"stored-key\"", got)
	}

	c.apiKey = "flag-key"
	if got := c.cliOptions().APIKey; got != "flag-key" {
		t.Errorf("explicit key: got %q, want \"flag-key\"", got)
	}
}
