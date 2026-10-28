//go:build darwin

package approvals

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// DialogAppName is the approval dialog's bundle name inside AgentMon.app.
const DialogAppName = "approval-dialog.app"

// openTimeout bounds `open`, which returns once Launch Services has the app
// starting, not once the window is up.
const openTimeout = 10 * time.Second

// DialogLauncher returns a Launcher that opens the approval dialog shipped in
// the same bundle as this binary.
//
// The dialog sits at AgentMon.app/Contents/Resources/approval-dialog.app, and
// the daemon at AgentMon.app/Contents/MacOS/agentmon, so the path is derived
// from the running executable rather than configured. A missing dialog is an
// error here, at startup, rather than a denial on the first approval.
func DialogLauncher() (Launcher, error) {
	app, err := locateDialog()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, req Request) error {
		return openDialog(ctx, app, req.ID)
	}, nil
}

func locateDialog() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate the approval dialog: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	app := filepath.Join(filepath.Dir(exe), "..", "Resources", DialogAppName)
	app = filepath.Clean(app)
	info, err := os.Stat(app)
	if err != nil {
		return "", fmt.Errorf("approvals.mode is gui, but the approval dialog is not at %s: %w", app, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("approvals.mode is gui, but %s is not an app bundle", app)
	}
	return app, nil
}

// dialogURL is the URL the dialog reads its request ID from.
func dialogURL(id string) string {
	return "agentmon-approval://approve?id=" + url.QueryEscape(id)
}

// openDialog starts a new instance of the dialog for one request. -n gives
// each request its own window, so two concurrent approvals cannot overwrite
// each other.
func openDialog(ctx context.Context, app, id string) error {
	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/open", "-n", "-a", app, "--args", dialogURL(id))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("open %s: %w: %s", app, err, out)
	}
	return nil
}
