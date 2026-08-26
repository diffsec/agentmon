//go:build darwin && cgo

// Package e2e holds macOS runtime enforcement tests: tests that build a real
// agentmon binary, hand it a real policy, and check the kernel actually
// refused the operation.
//
// Everything else in the macOS tree is tested by asserting on the shape of a
// generated artifact -- the text of an SBPL profile, the fields of a decision
// struct. That is how Phase 2's deny-ordering bug survived: the builder tests
// asserted the profile contained "(deny process-exec (literal ...))", which it
// did, while the kernel discarded every one of those rules because they came
// before the allows. A test that only reads the output of the thing under test
// cannot catch a mistake about what the output means.
//
// These tests need no system extension, no signing and no privileges:
// sandbox_init_with_parameters applies to the calling process. That makes this
// the enforcement layer that can be tested on an ordinary CI runner, and it is
// the layer agentmon relies on for every exec on macOS.
package e2e

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/platform/darwin"
	"github.com/diffsec/agentmon/internal/policy"
)

// buildMacwrap compiles cmd/agentmon-macwrap with cgo and returns its path.
//
// CGO_ENABLED=1 is explicit: with cgo off the build silently selects
// main_nocgo.go, a stub that prints an error and exits non-zero. Every
// assertion below would then "pass" for the wrong reason -- a denied command
// failing because the wrapper is broken, not because the sandbox worked.
// buildMacwrap therefore also asserts the built binary is the real one.
func buildMacwrap(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "agentmon-macwrap")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/agentmon-macwrap")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build agentmon-macwrap: %v\n%s", err, out)
	}

	// Prove this is the cgo build and not the stub, so a broken toolchain
	// fails here with a clear message instead of turning every enforcement
	// assertion into a false pass.
	nm, err := exec.Command("nm", "-u", bin).Output()
	if err != nil {
		t.Fatalf("nm -u %s: %v", bin, err)
	}
	if !strings.Contains(string(nm), "_sandbox_init_with_parameters") {
		t.Fatal("built agentmon-macwrap does not link sandbox_init_with_parameters: this is the nocgo stub, not the sandboxing binary")
	}
	return bin
}

// runUnderMacwrap execs argv through macwrap with the given compiled profile
// and returns combined output plus the exit code.
func runUnderMacwrap(t *testing.T, bin, profile string, argv ...string) (string, int) {
	t.Helper()

	cfg := writeWrapperConfig(t, profile)
	args := append([]string{"--"}, argv...)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "AGENTMON_SANDBOX_CONFIG_FILE="+cfg)

	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", argv, err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

// writeWrapperConfig writes a WrapperConfig JSON carrying only the compiled
// profile. The file form is used rather than AGENTMON_SANDBOX_CONFIG because
// compiled profiles routinely exceed the env-var size the wrapper accepts.
func writeWrapperConfig(t *testing.T, profile string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wrapper.json")
	// macwrap deletes the config file after reading it, so each run gets its
	// own copy under its own TempDir.
	body := struct {
		CompiledProfile string `json:"compiled_profile"`
		MachServices    struct {
			DefaultAction string `json:"default_action"`
		} `json:"mach_services"`
	}{CompiledProfile: profile}
	body.MachServices.DefaultAction = "allow"

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal wrapper config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write wrapper config: %v", err)
	}
	return path
}

// TestPolicyDenyIsEnforcedByKernel drives the whole macOS sandbox path:
// a policy.Policy, compiled by CompileDarwinSandbox into SBPL, applied by the
// real agentmon-macwrap binary, checked against what the kernel then permits.
//
// This is the regression test for the Phase 2 deny-ordering fix. Reverting
// sbpl.Build to emit denies before allows makes the "denied command" subtest
// fail, because /bin/echo would be re-allowed by the (subpath "/bin") exec
// allow that CompileDarwinSandbox always emits.
func TestPolicyDenyIsEnforcedByKernel(t *testing.T) {
	bin := buildMacwrap(t)

	workspace := t.TempDir()
	// EvalSymlinks: t.TempDir() hands back /var/folders/..., a symlink to
	// /private/var/folders/.... The kernel matches SBPL paths after resolution,
	// so an unresolved workspace path would produce rules that never match and
	// a test that passes for the wrong reason.
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}

	inside := filepath.Join(workspace, "allowed.txt")
	if err := os.WriteFile(inside, []byte("INSIDE_WORKSPACE"), 0o600); err != nil {
		t.Fatalf("write workspace file: %v", err)
	}

	outsideDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve outside dir: %v", err)
	}
	outside := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outside, []byte("OUTSIDE_WORKSPACE"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	pol := &policy.Policy{
		Version: 1,
		Name:    "macwrap-e2e",
		CommandRules: []policy.CommandRule{
			{
				Name:     "deny-echo",
				Commands: []string{"/bin/echo"},
				Decision: "deny",
			},
		},
	}

	sb, err := darwin.CompileDarwinSandbox(pol, workspace)
	if err != nil {
		t.Fatalf("compile sandbox: %v", err)
	}
	if sb.Profile == "" {
		t.Fatal("compiled profile is empty")
	}

	t.Run("workspace file is readable", func(t *testing.T) {
		out, code := runUnderMacwrap(t, bin, sb.Profile, "/bin/cat", inside)
		if code != 0 || !strings.Contains(out, "INSIDE_WORKSPACE") {
			t.Fatalf("reading a file inside the workspace should succeed; exit=%d out=%q", code, out)
		}
	})

	t.Run("file outside the workspace is denied", func(t *testing.T) {
		// The compiled profile opens with (deny default) and grants no rule
		// covering this path, so the kernel must refuse the read. If this ever
		// passes, deny-by-default has stopped holding and every unlisted path
		// on the machine is readable from inside the sandbox.
		out, code := runUnderMacwrap(t, bin, sb.Profile, "/bin/cat", outside)
		if code == 0 || strings.Contains(out, "OUTSIDE_WORKSPACE") {
			t.Fatalf("reading a file outside the workspace should be denied; exit=%d out=%q", code, out)
		}
	})

	t.Run("denied command cannot exec", func(t *testing.T) {
		// /bin/echo is denied by the policy above and simultaneously allowed by
		// the (subpath "/bin") rule CompileDarwinSandbox emits by default.
		// SBPL is last-match-wins, so this only fails to exec if the deny is
		// emitted after the allow.
		out, code := runUnderMacwrap(t, bin, sb.Profile, "/bin/echo", "SHOULD_NOT_RUN")
		if code == 0 || strings.Contains(out, "SHOULD_NOT_RUN") {
			t.Fatalf("policy denied /bin/echo but it executed; exit=%d out=%q", code, out)
		}
	})

	t.Run("undenied command still execs", func(t *testing.T) {
		// Guards against the opposite failure: a profile so broken that
		// nothing runs would make the deny subtests pass for free.
		out, code := runUnderMacwrap(t, bin, sb.Profile, "/bin/cat", inside)
		if code != 0 {
			t.Fatalf("/bin/cat is not denied and must still exec; exit=%d out=%q", code, out)
		}
	})
}

// TestWrapperConfigIsNotInheritedByChild verifies AUDIT M58 end to end: the
// sandboxed process must not be able to read the policy constraining it.
func TestWrapperConfigIsNotInheritedByChild(t *testing.T) {
	bin := buildMacwrap(t)

	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	sb, err := darwin.CompileDarwinSandbox(&policy.Policy{Version: 1}, workspace)
	if err != nil {
		t.Fatalf("compile sandbox: %v", err)
	}

	out, code := runUnderMacwrap(t, bin, sb.Profile, "/usr/bin/env")
	if code != 0 {
		t.Fatalf("/usr/bin/env should run; exit=%d out=%q", code, out)
	}
	for _, name := range []string{"AGENTMON_SANDBOX_CONFIG", "AGENTMON_SANDBOX_CONFIG_FILE"} {
		if strings.Contains(out, name+"=") {
			t.Errorf("%s leaked to the sandboxed child; it describes the sandbox the child is confined by", name)
		}
	}
}

// TestHomebrewToolsCanExec checks that a tool installed by Homebrew actually
// runs under a compiled profile.
//
// /opt/homebrew/bin is a farm of symlinks into ../Cellar/<pkg>/<version>/bin,
// and SBPL matches the resolved executable path. Exec-allowing only
// /opt/homebrew/bin therefore allowed nothing at all: every Homebrew tool --
// git, node, ripgrep, the majority of what an agent reaches for on a Mac --
// failed at execvp with EPERM. Nothing caught it, because no test had ever run
// a real command under a real compiled profile.
//
// Skips when Homebrew is absent rather than failing: the GitHub macOS runners
// have it, but a developer machine need not.
func TestHomebrewToolsCanExec(t *testing.T) {
	const prefix = "/opt/homebrew"
	if _, err := os.Stat(prefix); err != nil {
		t.Skipf("no Homebrew prefix at %s", prefix)
	}

	bin := buildMacwrap(t)
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	sb, err := darwin.CompileDarwinSandbox(&policy.Policy{Version: 1}, workspace)
	if err != nil {
		t.Fatalf("compile sandbox: %v", err)
	}

	// Pick whatever this machine happens to have; the point is that a binary
	// reached through the symlink farm can exec, not which one it is.
	var tool string
	for _, name := range []string{"jq", "git", "node", "rg", "bash"} {
		candidate := filepath.Join(prefix, "bin", name)
		if _, err := os.Stat(candidate); err == nil {
			tool = candidate
			break
		}
	}
	if tool == "" {
		t.Skip("no known Homebrew tool installed to test with")
	}

	out, code := runUnderMacwrap(t, bin, sb.Profile, tool, "--version")
	// A tool may exit non-zero for its own reasons (git reads a gitconfig the
	// sandbox correctly denies). What must not happen is failing to exec.
	if strings.Contains(out, "exec") && strings.Contains(out, "not permitted") {
		t.Fatalf("%s could not exec under the compiled profile; the Homebrew symlink farm resolves into Cellar, which must be exec-allowed.\nexit=%d out=%q", tool, code, out)
	}
}
