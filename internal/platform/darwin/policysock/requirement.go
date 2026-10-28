//go:build darwin

package policysock

import "fmt"

// teamRequirement is the code requirement for any binary signed by the team.
func teamRequirement(teamID string) string {
	return fmt.Sprintf(`anchor apple generic and certificate leaf[subject.OU] = "%s"`, teamID)
}

// approvalDialogRequirement adds the dialog's signing identifier to the team
// requirement, so that another team-signed binary does not pass as the
// dialog.
func approvalDialogRequirement(teamID string) string {
	return fmt.Sprintf(`anchor apple generic and identifier "%s" and certificate leaf[subject.OU] = "%s"`,
		ApprovalDialogIdentifier, teamID)
}
