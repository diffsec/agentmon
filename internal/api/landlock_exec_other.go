//go:build !linux

package api

import (
	"github.com/diffsec/agentmon/internal/capabilities"
	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/policy"
)

// MakeLandlockPostStartHook returns nil on non-Linux platforms.
func MakeLandlockPostStartHook(
	cfg *config.LandlockConfig,
	secCaps *capabilities.SecurityCapabilities,
	workspace string,
	pol *policy.Policy,
) postStartHook {
	return nil
}

// GetLandlockEnvVars returns nil on non-Linux platforms.
func GetLandlockEnvVars(cfg *config.LandlockConfig, workspace string, abi int) map[string]string {
	return nil
}
