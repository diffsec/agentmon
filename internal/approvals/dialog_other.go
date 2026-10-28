//go:build !darwin

package approvals

import "fmt"

// DialogLauncher reports that the approval dialog exists only on macOS.
// Configuration validation refuses approvals.mode: gui elsewhere, so this is
// reached only by a caller that skipped validation.
func DialogLauncher() (Launcher, error) {
	return nil, fmt.Errorf("approvals.mode gui is available only on macOS")
}
