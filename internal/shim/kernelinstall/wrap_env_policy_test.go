//go:build linux

package kernelinstall

import (
	"slices"
	"testing"

	"github.com/diffsec/agentmon/internal/wrapenv"
	"github.com/diffsec/agentmon/pkg/types"
)

// Issue #379: filtering applies to the inherited base BEFORE agentmon markers and
// env_inject are added, so a denied var is dropped while markers and injected
// values survive.
func TestAssembleWrapperEnv_FiltersBaseKeepsMarkersAndInject(t *testing.T) {
	base := []string{"PATH=/bin", "SECRET_TOKEN=x"}
	wire := &types.EnvPolicyWire{Deny: []string{"SECRET_*"}}

	filtered := wrapenv.Filter(base, wire)
	env := assembleWrapperEnv(filtered, "", map[string]string{}, map[string]string{"INJECTED": "1"})

	for _, kv := range env {
		if kv == "SECRET_TOKEN=x" {
			t.Error("denied var must not survive filtering")
		}
	}
	if !slices.Contains(env, "INJECTED=1") {
		t.Error("env_inject value must survive (applied after filter)")
	}
	if !slices.Contains(env, "AGENTMON_NOTIFY_SOCK_FD=3") {
		t.Error("agentmon marker must survive (appended after filter)")
	}
	if !slices.Contains(env, "PATH=/bin") {
		t.Error("non-denied inherited var must survive")
	}
}
