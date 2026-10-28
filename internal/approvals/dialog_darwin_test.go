//go:build darwin

package approvals

import (
	"net/url"
	"strings"
	"testing"
)

func TestDialogURL_EscapesTheID(t *testing.T) {
	got := dialogURL("approval-1&x=y")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	if u.Scheme != "agentmon-approval" || u.Host != "approve" {
		t.Errorf("url = %q", got)
	}
	if id := u.Query().Get("id"); id != "approval-1&x=y" {
		t.Errorf("id round-trips as %q", id)
	}
}

// TestDialogLauncher_MissingDialogFailsStartup: the test binary has no
// approval-dialog.app beside it, which is exactly a daemon running outside
// AgentMon.app.
func TestDialogLauncher_MissingDialogFailsStartup(t *testing.T) {
	_, err := DialogLauncher()
	if err == nil {
		t.Fatal("DialogLauncher succeeded without a dialog to launch")
	}
	if !strings.Contains(err.Error(), "approval-dialog.app") {
		t.Errorf("error = %v, want it to name the missing bundle", err)
	}
}
