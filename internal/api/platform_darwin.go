//go:build darwin

package api

// Import Darwin platform to trigger init() registration
import _ "github.com/diffsec/agentmon/internal/platform/darwin"
