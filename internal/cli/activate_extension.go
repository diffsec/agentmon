//go:build darwin

package cli

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/diffsec/agentmon/internal/platform/darwin"
	"github.com/spf13/cobra"
)

func newActivateExtensionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate-extension",
		Short: "Activate the AgentMon system extension",
		Long:  "Submits an activation request for the AgentMon system extension. Requires user approval in System Settings.",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := darwin.NewSysExtManager()

			fmt.Println("Activating AgentMon system extension...")
			result, err := mgr.Activate()

			switch result {
			case darwin.ActivateOK:
				fmt.Println("System extension activated successfully.")
				openFullDiskAccessSettings()
				return nil
			case darwin.ActivateNeedsApproval:
				fmt.Println("System extension requires approval.")
				fmt.Println("Opening System Settings — please allow the AgentMon extension.")
				openEndpointSecuritySettings()
				// Wait a bit then prompt for FDA
				fmt.Println("\nAfter approving the extension, you also need to grant Full Disk Access.")
				fmt.Println("Press Enter when you've approved the extension to open Full Disk Access settings...")
				fmt.Scanln()
				openFullDiskAccessSettings()
				return nil
			default:
				if err != nil {
					return fmt.Errorf("activation failed: %w", err)
				}
				return fmt.Errorf("activation failed")
			}
		},
	}
}

// openFullDiskAccessSettings opens System Settings to the Full Disk Access pane.
func openFullDiskAccessSettings() {
	fmt.Println("Opening Full Disk Access settings...")
	fmt.Println("Please enable Full Disk Access for the AgentMon system extension.")
	// Small delay to let the extension launch before user navigates
	time.Sleep(500 * time.Millisecond)
	exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles").Run()
}

// openEndpointSecuritySettings opens System Settings to the Endpoint Security Extensions pane.
func openEndpointSecuritySettings() {
	exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_EndpointSecurity").Run()
}

func newDeactivateExtensionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deactivate-extension",
		Short: "Deactivate the AgentMon system extension",
		Long: "Submits a deactivation request for the AgentMon system extension.\n\n" +
			"Run this before removing or replacing /Applications/AgentMon.app. Removing\n" +
			"the app without deactivating leaves the extension registered and running\n" +
			"with nothing behind it, and `systemextensionsctl uninstall` is not an\n" +
			"alternative -- it refuses to run while System Integrity Protection is\n" +
			"enabled, leaving System Settings as the only way out.\n\n" +
			"The request must come from an app inside /Applications, so deactivate\n" +
			"before deleting, not after. Removal completes at the next reboot; until\n" +
			"then the extension shows as \"terminated waiting to uninstall on reboot\".",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := darwin.NewSysExtManager()

			fmt.Println("Deactivating AgentMon system extension...")
			result, err := mgr.Deactivate()

			switch result {
			case darwin.ActivateOK:
				// Deliberately not "deactivated": the extension is terminated
				// and deregisters at the next boot, and saying otherwise
				// invites a bug report when systemextensionsctl still lists it.
				fmt.Println("System extension terminated; it is removed at the next reboot.")
				return nil
			case darwin.ActivateNeedsApproval:
				// Not a failure: macOS wants the user to confirm the removal.
				// The extension stays registered until they do, so say so
				// rather than reporting success and leaving them to discover
				// the bundle is still locked.
				fmt.Println("Removal requires approval in System Settings.")
				fmt.Println("The extension stays active until you confirm it there.")
				openEndpointSecuritySettings()
				return nil
			default:
				if err != nil {
					return fmt.Errorf("deactivation failed: %w", err)
				}
				return fmt.Errorf("deactivation failed")
			}
		},
	}
}
