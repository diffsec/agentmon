//go:build linux

package api

// Import Linux platform to trigger init() registration
import _ "github.com/diffsec/agentmon/internal/platform/linux"
