//go:build darwin

package api

import "github.com/diffsec/agentmon/internal/platform/darwin"

func notifySessionRegistered() {
	darwin.NotifySessionRegistered()
}

// notifyPolicyUpdated tells the system extension to fetch every session's
// policy again.
func notifyPolicyUpdated() {
	darwin.NotifyPolicyUpdated()
}
