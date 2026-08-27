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
				return installFilterAfterActivation()
			case darwin.ActivateNeedsApproval:
				fmt.Println("System extension requires approval.")
				fmt.Println("Opening System Settings — please allow the AgentMon extension.")
				openEndpointSecuritySettings()
				// Wait a bit then prompt for FDA
				fmt.Println("\nAfter approving the extension, you also need to grant Full Disk Access.")
				fmt.Println("Press Enter when you've approved the extension to open Full Disk Access settings...")
				fmt.Scanln()
				openFullDiskAccessSettings()
				return installFilterAfterActivation()
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
			"Run this before replacing or removing /Applications/AgentMon.app. While the\n" +
			"extension is registered, macOS denies writes into the bundle it was staged\n" +
			"from, so an in-place upgrade fails with \"Operation not permitted\"; and\n" +
			"removing the app without deactivating leaves the extension running with\n" +
			"nothing behind it. `systemextensionsctl uninstall` is not an alternative --\n" +
			"it refuses to run while System Integrity Protection is enabled.",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := darwin.NewSysExtManager()

			// Remove the filter configuration first, while the provider it
			// points at still exists. A configuration that outlives its
			// extension leaves a dead entry in System Settings > Network >
			// Filters, and the next install inherits it. A failure here is
			// reported but does not stop the deactivation -- leaving the
			// extension registered is the worse outcome, because it is what
			// locks the app bundle against replacement.
			if fr, ferr := darwin.RemoveContentFilter(); ferr != nil {
				fmt.Printf("Warning: could not remove the content filter configuration: %v\n", ferr)
				fmt.Println("Remove it manually in System Settings > Network > Filters.")
			} else if fr == darwin.ActivateOK {
				fmt.Println("Content filter configuration removed.")
			}

			fmt.Println("Deactivating AgentMon system extension...")
			result, err := mgr.Deactivate()

			switch result {
			case darwin.ActivateOK:
				fmt.Println("System extension deactivated.")
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

// installFilterAfterActivation installs the content filter once the extension
// is activated.
//
// This runs as part of activation because the two are not independently useful:
// an activated extension with no filter configuration enforces file and exec
// rules but silently ignores every network rule, and that gap is invisible from
// `systemextensionsctl list`. A filter failure does not fail the activation --
// file and exec enforcement is real and worth keeping -- but it is printed, and
// `agentmon network-filter status` reports the resulting state.
func installFilterAfterActivation() error {
	fmt.Println()
	result, err := installContentFilterWithMessages()
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
		fmt.Println("File and exec enforcement are unaffected; network rules stay unenforced.")
		fmt.Println("Retry with `agentmon network-filter enable`.")
		return nil
	}
	if result != darwin.ActivateOK {
		fmt.Println("Check `agentmon network-filter status` once you have approved it.")
	}
	return nil
}
