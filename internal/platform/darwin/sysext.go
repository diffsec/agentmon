//go:build darwin

// Package darwin provides the macOS platform implementation for agentmon.
package darwin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SysExtStatus represents the state of the System Extension.
type SysExtStatus struct {
	Installed   bool   `json:"installed"`              // true once systemextensionsctl reports the extension activated; does not imply Running
	Running     bool   `json:"running"`                // true only on positive proof the launchd service state is "running"
	ProbeFailed bool   `json:"probe_failed,omitempty"` // a liveness probe command failed or its output was unparseable
	State       string `json:"state,omitempty"`        // raw launchd state ("running", "spawn scheduled", ...); "" if unknown
	LastExit    string `json:"last_exit,omitempty"`    // last recorded launchd exit; suppressed while Running is true
	Version     string `json:"version,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
	ExtensionID string `json:"extension_id,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SysExtManager manages the agentmon System Extension lifecycle.
type SysExtManager struct {
	bundlePath string
	bundleID   string
}

// NewSysExtManager creates a new System Extension manager.
func NewSysExtManager() *SysExtManager {
	// Find the app bundle - either we're running from it or it's adjacent
	execPath, _ := os.Executable()
	bundlePath := findAppBundle(execPath)

	return &SysExtManager{
		bundlePath: bundlePath,
		bundleID:   sysExtBundleID,
	}
}

// findAppBundle locates the AgentMon.app bundle.
func findAppBundle(execPath string) string {
	// If running from within .app bundle
	if idx := strings.Index(execPath, ".app/"); idx >= 0 {
		return execPath[:idx+4]
	}

	// Check common locations
	candidates := []string{
		"/Applications/AgentMon.app",
		filepath.Join(filepath.Dir(execPath), "AgentMon.app"),
		filepath.Join(filepath.Dir(execPath), "..", "AgentMon.app"),
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}

	return ""
}

// Status returns the current System Extension status.
// This method never returns an error - any errors are reported via status.Error.
//
// The m.bundlePath == "" early return below is a bundle-presence
// precondition, not a liveness statement: an extension orphaned by app
// deletion persists in /Library/SystemExtensions and would still report
// Installed=false here because the .app bundle is gone. Surfaces that need
// the ground truth regardless of the app bundle call CheckSysExtLiveness
// directly and do not pass through this gate.
//
// Installed reflects activation (systemextensionsctl), not readiness: an
// extension still awaiting user approval in System Settings reports
// Installed=false. LastExit is suppressed while Running is true, since a
// historical exit on an otherwise healthy running service is misleading.
func (m *SysExtManager) Status() (*SysExtStatus, error) {
	status := &SysExtStatus{
		BundleID: m.bundleID,
	}

	if m.bundlePath == "" {
		status.Error = "AgentMon.app bundle not found"
		return status, nil
	}

	liveness := CheckSysExtLiveness()
	status.Installed = liveness.Activated
	status.Running = liveness.Running
	status.ProbeFailed = liveness.ProbeFailed
	status.State = liveness.State
	if !liveness.Running {
		// A historical exit on a healthy running service is misleading in
		// status output; surface it only when the process is not up.
		status.LastExit = liveness.LastExit
	}
	if liveness.ProbeFailed || (liveness.Activated && !liveness.Running) {
		status.Error = liveness.Detail
	}

	return status, nil
}

// Install requests installation of the System Extension.
func (m *SysExtManager) Install() error {
	if m.bundlePath == "" {
		return fmt.Errorf("AgentMon.app bundle not found; install it first")
	}

	extPath := filepath.Join(m.bundlePath, "Contents", "Library", "SystemExtensions",
		m.bundleID+".systemextension")

	if _, err := os.Stat(extPath); err != nil {
		return fmt.Errorf("System Extension not found at %s", extPath)
	}

	return fmt.Errorf("not implemented: use Activate() instead")
}

// Activate submits an activation request for the system extension via
// OSSystemExtensionManager. Requires CGO and the system-extension.install
// entitlement on the calling binary.
func (m *SysExtManager) Activate() (ActivateResult, error) {
	if m.bundlePath == "" {
		return ActivateFailed, fmt.Errorf("AgentMon.app bundle not found; install it first")
	}
	return activateExtension()
}

// Deactivate submits a deactivation request for the system extension.
//
// This is the only way to remove the extension while SIP is enabled:
// `systemextensionsctl uninstall` refuses to run under SIP, and until the
// extension is deregistered macOS denies writes into the app bundle it was
// staged from -- so an in-place upgrade fails with "Operation not permitted"
// and an uninstall leaves the extension running with no app behind it.
//
// The calling binary must be running from an app inside /Applications.
// Verified: invoking it from a build directory is rejected with
// OSSystemExtensionErrorUnsupportedParentBundleLocation (Code=3), "App
// containing System Extension to be activated must be in /Applications
// folder". So this cannot rescue a bundle that has already been emptied --
// deactivate BEFORE touching the app, not after. Once the app is gone the
// only route left is removing the extension in System Settings.
func (m *SysExtManager) Deactivate() (ActivateResult, error) {
	return deactivateExtension()
}

// Uninstall removes the System Extension.
//
// Deprecated: use Deactivate. Kept so existing callers keep compiling; it
// previously returned "not implemented: requires Swift integration", which
// was wrong -- OSSystemExtensionRequest.deactivationRequest does this from Go
// through the same cgo bridge Activate already used.
func (m *SysExtManager) Uninstall() error {
	result, err := m.Deactivate()
	if err != nil {
		return err
	}
	if result == ActivateFailed {
		return fmt.Errorf("deactivation failed")
	}
	return nil
}
