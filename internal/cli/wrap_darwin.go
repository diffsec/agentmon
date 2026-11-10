//go:build darwin

package cli

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/diffsec/agentmon/internal/envinject"
	"github.com/diffsec/agentmon/internal/wrapenv"
	"github.com/diffsec/agentmon/pkg/types"
)

// platformSetupWrap on macOS sets up ES-based interception.
// Unlike Linux (seccomp per-process), macOS ES is system-wide via the System Extension.
// The wrap command registers the session with the server, which configures the ESF client
// to intercept execs from this session's process tree.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
	// env_policy filters the inherited environment, and env_inject is laid
	// over the result, in the same order as on Linux.
	env := envinject.Apply(
		buildWrapEnv(wrapenv.Filter(os.Environ(), wrapResp.EnvPolicy), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim),
		wrapResp.EnvInject)

	if wrapResp.WrapperBinary == "" {
		// No wrapper needed on macOS — ES interception is handled by System Extension.
		// The agent runs directly, and the ESF client intercepts its execs.
		return &wrapLaunchConfig{
			command: agentPath,
			args:    agentArgs,
			env:     env,
			sysProcAttr: &syscall.SysProcAttr{
				Setpgid: true,
			},
		}, nil
	}

	// If the server returns a wrapper binary (e.g., agentmon-macwrap for sandboxing),
	// use it as the launch command.
	for k, v := range wrapResp.WrapperEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	wrapperArgs := append([]string{"--", agentPath}, agentArgs...)

	return &wrapLaunchConfig{
		command: wrapResp.WrapperBinary,
		args:    wrapperArgs,
		env:     env,
		sysProcAttr: &syscall.SysProcAttr{
			Setpgid: true,
		},
	}, nil
}
