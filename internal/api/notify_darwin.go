//go:build darwin

package api

import "github.com/diffsec/agentmon/internal/platform/darwin"

func notifySessionRegistered() {
	darwin.NotifySessionRegistered()
}
