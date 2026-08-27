//go:build darwin

package cli

import (
	"fmt"

	"github.com/diffsec/agentmon/internal/platform/darwin"
	"github.com/spf13/cobra"
)

func newNetworkFilterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network-filter",
		Short: "Manage the AgentMon content filter configuration (macOS)",
		Long: "The system extension can only filter network flows once an NEFilterManager\n" +
			"configuration exists and is enabled. Registering the provider is not enough:\n" +
			"macOS calls FilterDataProvider.startFilter only for an enabled configuration,\n" +
			"so without one every network_rules entry is silently unenforced.\n\n" +
			"`activate-extension` installs the filter for you; these subcommands exist to\n" +
			"inspect and repair it without a full activation cycle.",
	}
	cmd.AddCommand(newNetworkFilterStatusCmd())
	cmd.AddCommand(newNetworkFilterEnableCmd())
	cmd.AddCommand(newNetworkFilterDisableCmd())
	return cmd
}

func newNetworkFilterStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the content filter is installed and enabled",
		RunE: func(cmd *cobra.Command, args []string) error {
			state := darwin.CheckContentFilter()
			if state.Error != "" {
				return fmt.Errorf("reading the content filter configuration failed: %s", state.Error)
			}
			switch {
			case state.Enforcing():
				fmt.Println("Content filter: installed and enabled — network flows reach the extension.")
			case state.Installed:
				fmt.Println("Content filter: installed but DISABLED — startFilter is not called, so network rules are unenforced.")
				fmt.Println("Run `agentmon network-filter enable` to turn it on.")
			default:
				fmt.Println("Content filter: not installed — network rules are unenforced.")
				fmt.Println("Run `agentmon network-filter enable` to install it.")
			}
			return nil
		},
	}
}

func newNetworkFilterEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: "Install and enable the content filter configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := installContentFilterWithMessages()
			if err != nil {
				return err
			}
			if result != darwin.ActivateOK {
				return &ExitError{code: 1, message: "content filter is not enabled"}
			}
			return nil
		},
	}
}

func newNetworkFilterDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Remove the content filter configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := darwin.RemoveContentFilter()
			if err != nil {
				return fmt.Errorf("removing the content filter failed: %w", err)
			}
			if result != darwin.ActivateOK {
				return &ExitError{code: 1, message: "removing the content filter did not complete"}
			}
			fmt.Println("Content filter removed. Network rules are no longer enforced.")
			return nil
		},
	}
}

// installContentFilterWithMessages installs the filter and reports what actually
// happened. Shared by `activate-extension` and `network-filter enable` so both
// describe the pending-approval case the same way -- it is not a success, and
// reporting it as one is how a machine ends up believing it enforces network
// policy while every flow passes.
func installContentFilterWithMessages() (darwin.ActivateResult, error) {
	fmt.Println("Installing the content filter configuration...")
	fmt.Println("macOS may ask you to allow AgentMon to filter network content.")

	result, err := darwin.InstallContentFilter()
	switch result {
	case darwin.ActivateOK:
		fmt.Println("Content filter enabled. Network flows now reach the extension.")
		return result, nil
	case darwin.ActivateNeedsApproval:
		fmt.Println("The content filter is waiting on your approval.")
		fmt.Println("Allow it when macOS prompts, then run `agentmon network-filter status` to confirm.")
		fmt.Println("Until then, network rules are NOT enforced.")
		return result, nil
	default:
		if err != nil {
			return result, fmt.Errorf("installing the content filter failed: %w", err)
		}
		return result, fmt.Errorf("installing the content filter failed")
	}
}
