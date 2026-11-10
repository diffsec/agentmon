//go:build darwin

package cli

import (
	"context"
	"slices"
	"testing"

	"github.com/diffsec/agentmon/pkg/types"
)

// Before, macOS wrap passed the inherited environment unchanged: the server
// sent no env_policy or env_inject, and the client applied neither.
func TestPlatformSetupWrapAppliesEnvPolicyAndInject(t *testing.T) {
	t.Setenv("WRAPTEST_SECRET", "s3cret")
	t.Setenv("WRAPTEST_KEEP", "yes")
	resp := types.WrapInitResponse{
		EnvPolicy: &types.EnvPolicyWire{Deny: []string{"WRAPTEST_SECRET"}},
		EnvInject: map[string]string{"WRAPTEST_INJECTED": "1", "WRAPTEST_KEEP": "injected"},
	}
	lc, err := platformSetupWrap(context.Background(), resp, "sess-1", "/bin/echo", nil, &clientConfig{serverAddr: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(lc.env, "WRAPTEST_SECRET=s3cret") {
		t.Error("env_policy deny did not remove WRAPTEST_SECRET")
	}
	if !slices.Contains(lc.env, "WRAPTEST_INJECTED=1") {
		t.Error("env_inject did not add WRAPTEST_INJECTED")
	}
	if !slices.Contains(lc.env, "WRAPTEST_KEEP=injected") || slices.Contains(lc.env, "WRAPTEST_KEEP=yes") {
		t.Error("env_inject did not replace WRAPTEST_KEEP")
	}
}
