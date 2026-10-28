package config

import (
	"strings"
	"testing"
)

func TestApprovalsValidate(t *testing.T) {
	cases := []struct {
		mode, goos, team, wantErr string
	}{
		{"", "linux", "", ""},
		{"local_tty", "linux", "", ""},
		{"api", "darwin", "", ""},
		{"totp", "linux", "", ""},
		{"webauthn", "linux", "", ""},
		{"gui", "darwin", "LWSYS6YTUZ", ""},
		{"gui", "linux", "LWSYS6YTUZ", "not available on linux"},
		{"gui", "darwin", "", "requires policy_socket.team_id"},
		{"tty", "linux", "", "is not one of"},
		{"GUI", "darwin", "LWSYS6YTUZ", "is not one of"},
	}
	for _, c := range cases {
		err := (&ApprovalsConfig{Mode: c.mode}).Validate(c.goos, c.team)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("mode %q on %s: %v", c.mode, c.goos, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("mode %q on %s: err = %v, want %q", c.mode, c.goos, err, c.wantErr)
		}
	}
}

func TestValidateConfig_RejectsAnUnknownApprovalMode(t *testing.T) {
	cfg := Config{}
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Network.InterceptMode = "all"
	cfg.Approvals.Mode = "slack"
	if err := validateConfig(&cfg); err == nil || !strings.Contains(err.Error(), "approvals.mode") {
		t.Fatalf("validateConfig = %v, want an approvals.mode error", err)
	}
}
