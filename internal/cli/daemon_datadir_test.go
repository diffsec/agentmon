package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/config"
)

// TestSystemdUnit_GrantsTheDirectoryTheDaemonResolves.
//
// The unit sets ProtectSystem=strict and ProtectHome=read-only, so the daemon
// can write nothing except what ReadWritePaths grants. The installer used to
// hardcode ~/.local/share/agentmon while the daemon resolved its data
// directory through config.GetUserDataDir(); the two agree only while
// XDG_DATA_HOME is unset, and nothing enforced that.
func TestSystemdUnit_GrantsTheDirectoryTheDaemonResolves(t *testing.T) {
	src, err := os.ReadFile("daemon.go")
	if err != nil {
		t.Skipf("daemon.go not readable: %v", err)
	}
	body := string(src)
	if strings.Contains(body, `filepath.Join(home, ".local", "share", "agentmon")`) {
		t.Error("the data directory is hardcoded again; it must come from config.GetUserDataDir()")
	}
	if !strings.Contains(body, "dataDir := config.GetUserDataDir()") {
		t.Error("the installer does not resolve the data directory through config.GetUserDataDir()")
	}
	if !strings.Contains(body, "ReadWritePaths=%s") {
		t.Error("the unit no longer grants a ReadWritePaths directory")
	}
}

// TestSystemdUnit_ReadWritePathsFollowsXDG is the case the hardcode got wrong.
func TestSystemdUnit_ReadWritePathsFollowsXDG(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	if got := config.GetUserDataDir(); got != "/xdg/data/agentmon" {
		if strings.Contains(got, "Library/Application Support") {
			t.Skip("darwin ignores XDG_DATA_HOME")
		}
		t.Fatalf("GetUserDataDir() = %q, want /xdg/data/agentmon", got)
	}
}
