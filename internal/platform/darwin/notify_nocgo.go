//go:build darwin && !cgo

package darwin

const PolicyUpdatedNotification = "dev.diffsec.agentmon.policy-updated"

// NotifyPolicyUpdated is a no-op when CGO is disabled.
func NotifyPolicyUpdated() {}

const SessionRegisteredNotification = "dev.diffsec.agentmon.session-registered"

// NotifySessionRegistered is a no-op when CGO is disabled.
func NotifySessionRegistered() {}
