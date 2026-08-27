//go:build !darwin

package cli

import "github.com/spf13/cobra"

func newNetworkFilterCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "network-filter",
		Short:  "Manage the AgentMon content filter configuration (macOS only)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return &ExitError{code: 1, message: "network-filter is only available on macOS"}
		},
	}
}
