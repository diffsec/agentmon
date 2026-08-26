//go:build !darwin

package cli

import "github.com/spf13/cobra"

func newActivateExtensionCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "activate-extension",
		Short:  "Activate the AgentMon system extension (macOS only)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return &ExitError{code: 1, message: "activate-extension is only available on macOS"}
		},
	}
}

func newDeactivateExtensionCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "deactivate-extension",
		Short:  "Deactivate the AgentMon system extension (macOS only)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return &ExitError{code: 1, message: "deactivate-extension is only available on macOS"}
		},
	}
}
