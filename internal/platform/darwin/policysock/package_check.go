//go:build darwin

package policysock

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/diffsec/agentmon/internal/approvals"
	"github.com/diffsec/agentmon/internal/pkgcheck"
)

// PackageChecker checks a package install. *pkgcheck.Checker implements it.
// It returns a nil verdict for a command that is not an install.
type PackageChecker interface {
	Check(ctx context.Context, command string, args []string, workDir string) (*pkgcheck.Verdict, error)
}

// SetPackageChecker makes CheckExec check package installs, as the exec API
// does for the command that it starts. With it, an install that an agent
// starts under `agentmon wrap`, or from inside a command, is checked too.
func (a *PolicyAdapter) SetPackageChecker(c PackageChecker) {
	a.packages = c
}

const (
	// packageCheckFallback is the time for a package check when the
	// extension does not say how long it waits. Its own default wait is 2s.
	packageCheckFallback = 1500 * time.Millisecond

	// packageCheckMargin is kept free before the extension stops waiting,
	// so that the daemon answers before the extension denies on its own.
	packageCheckMargin = 500 * time.Millisecond

	// packageRule names the rule in a deny that the package check caused.
	packageRule = "package-check"
)

// installCommand returns the command and arguments to classify as an
// install, from an exec as ES reports it. args holds argv, with argv[0].
//
// For a script, ES reports the interpreter as the executable. The kernel
// puts the script path, as the caller named it, in argv[1]. So `pip3
// install x` arrives as python3.15 with argv [python3.15, /opt/homebrew/bin/
// pip3, install, x], and the install command is pip3 with [install, x].
func installCommand(executable string, args []string, script string) (string, []string) {
	if script != "" && len(args) >= 2 {
		return args[1], args[2:]
	}
	if len(args) >= 1 {
		return executable, args[1:]
	}
	return executable, nil
}

// checkPackageInstall runs the package check on an exec that the command
// rules allow. ok is false when the exec is not an install, or when the
// check allows it. Then the command rules' verdict stands.
func (a *PolicyAdapter) checkPackageInstall(sessionID, executable string, args []string, ec ExecContext) (ExecCheckResult, bool) {
	if a.packages == nil {
		return ExecCheckResult{}, false
	}
	command, cmdArgs := installCommand(executable, args, ec.Script)

	budget := packageCheckFallback
	if ec.Deadline > 0 {
		budget = ec.Deadline - packageCheckMargin
	}
	if budget <= 0 {
		return packageDeny("package check: no time left before the system extension stops waiting"), true
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	verdict, err := a.packages.Check(ctx, command, cmdArgs, ec.CWDPath)
	if err != nil {
		// The exec API denies on the same error (api/core.go).
		slog.Warn("policy socket: package check failed, denying the exec",
			"command", command, "session_id", sessionID, "error", err)
		return packageDeny("package check failed: " + err.Error()), true
	}
	if verdict == nil {
		return ExecCheckResult{}, false
	}

	switch verdict.Action {
	case pkgcheck.VerdictBlock:
		return packageDeny(verdict.Summary), true
	case pkgcheck.VerdictApprove:
		return a.packageApproval(sessionID, command, cmdArgs, verdict), true
	case pkgcheck.VerdictWarn:
		slog.Warn("policy socket: package install warning", "session_id", sessionID, "summary", verdict.Summary)
	}
	return ExecCheckResult{}, false
}

func packageDeny(message string) ExecCheckResult {
	return ExecCheckResult{Decision: "deny", Action: "deny", Rule: packageRule, Message: message}
}

// packageApproval handles an approve verdict as execApproval handles an
// approve rule. The extension cannot hold an exec while a person reads a
// dialog, so the install is denied and a dialog opens. If the person
// approves, the same install succeeds when the agent tries it again.
func (a *PolicyAdapter) packageApproval(sessionID, command string, args []string, verdict *pkgcheck.Verdict) ExecCheckResult {
	target := strings.Join(append([]string{filepath.Base(command)}, args...), " ")
	if a.approvals == nil || sessionID == "" {
		return packageDeny("package install needs approval, and no approval dialog is available: " + verdict.Summary)
	}
	if a.approvals.Granted(sessionID, "package", target, "install") {
		return ExecCheckResult{Decision: "approve", Action: "continue", Rule: packageRule, Message: verdict.Summary}
	}
	a.approvals.Ask(approvals.Request{
		SessionID: sessionID,
		Kind:      "package",
		Target:    target,
		Rule:      packageRule,
		Message:   verdict.Summary,
		Fields:    map[string]any{"operation": "install"},
	})
	return packageDeny("package install needs approval: " + verdict.Summary)
}
