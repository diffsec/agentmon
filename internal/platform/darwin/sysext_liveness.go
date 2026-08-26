//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	sysExtBundleID     = "dev.diffsec.agentmon.SysExt"
	livenessCmdTimeout = 5 * time.Second
)

// SysExtLiveness reports two separate facts about the system extension:
// whether it is activated (systemextensionsctl) and whether its process is
// actually running (launchd service state). Running is set only on positive
// proof (state = running); every probe failure fails closed (issue #441 —
// an activated-but-AMFI-blocked extension must not report as healthy).
type SysExtLiveness struct {
	Activated   bool   // systemextensionsctl row for our bundle ID says "activated enabled"
	Running     bool   // launchctl service state is "running"
	ProbeFailed bool   // a probe command failed or its output was unparseable (Running stays false)
	State       string // raw launchd state ("running", "spawn scheduled", ...); "" if unknown
	LastExit    string // "exit code 1", "OS_REASON_EXEC ...", ...; "" if none
	Detail      string // human-readable one-liner; tips.go matches substrings of this

	// Connected reports whether the extension currently holds a connection to
	// the policy socket. ConnectionChecked says whether that could be
	// determined at all -- it can only be answered inside the process running
	// the policy socket server, so a standalone `agentmon detect` leaves it
	// false.
	//
	// This exists because launchd state answers the wrong question. It reports
	// whether the PROCESS is up, and a crash-looping extension is up for part
	// of every cycle: an extension denied Full Disk Access fails
	// es_new_client, retries three times, exits 1, and launchd respawns it.
	// Sampling `agentmon detect` through that loop returned 40/100, 65/100,
	// 40/100 in nine seconds while the ES client was dead throughout.
	//
	// A connection is stronger evidence. main.swift connects here only after
	// ESFClient.create() and subscribe() have both succeeded, and the
	// connection is persistent with reconnect-on-failure, so holding one means
	// the ES client exists and is subscribed.
	Connected         bool
	ConnectionChecked bool
	LastContact       time.Time
}

// extensionPresence is set by the policy socket server when it starts, so
// CheckSysExtLiveness can consult it without internal/platform/darwin
// importing policysock (which would be an import cycle).
//
// Left nil in any process that is not running the server -- `agentmon detect`
// on the command line, for instance -- in which case ConnectionChecked stays
// false and callers fall back to the launchd state, knowing it is weaker.
var (
	extensionPresenceMu sync.RWMutex
	extensionPresence   func() (bool, time.Time)
)

// SetExtensionPresenceProbe registers the source of truth for whether the
// system extension is connected. Pass nil to clear it.
func SetExtensionPresenceProbe(fn func() (bool, time.Time)) {
	extensionPresenceMu.Lock()
	extensionPresence = fn
	extensionPresenceMu.Unlock()
}

func checkExtensionPresence() (checked, connected bool, last time.Time) {
	extensionPresenceMu.RLock()
	fn := extensionPresence
	extensionPresenceMu.RUnlock()
	if fn == nil {
		return false, false, time.Time{}
	}
	connected, last = fn()
	return true, connected, last
}

// runLivenessCommand executes a probe command with a timeout. Package-level
// var so tests can inject fixture output (tests swapping it must not use
// t.Parallel()). Captured stderr is collapsed to a single line before being
// folded into the returned error, so probe failures carry the tool's actual
// message while Detail stays a one-liner.
var runLivenessCommand = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), livenessCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("timed out after %v", livenessCmdTimeout)
		} else {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				if msg := strings.Join(strings.Fields(string(exitErr.Stderr)), " "); msg != "" {
					err = fmt.Errorf("%w: %s", err, msg)
				}
			}
		}
	}
	return string(out), err
}

// parseSysExtList scans systemextensionsctl list output line by line for an
// "activated enabled" row whose fields contain the exact bundle-ID token
// (the row repeats the bundle ID as its display name, so the team ID is the
// field immediately preceding the FIRST occurrence; matching the last would
// return the version column). Exact-token matching prevents both a different
// extension's "activated enabled" row and a prefix-sibling bundle ID (e.g. a
// future ...SysExtBeta) from satisfying the check, and scanning continues
// past rows that yield no team ID so a transient extra row cannot mask a
// healthy one. A "*" in the preceding field is the `active` column marker of
// a blank team-ID row, not a team ID.
func parseSysExtList(output string) (activated bool, teamID string) {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "activated enabled") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != sysExtBundleID {
				continue
			}
			activated = true
			if i > 0 && fields[i-1] != "*" {
				teamID = fields[i-1]
			}
			break
		}
		if activated && teamID != "" {
			return true, teamID
		}
	}
	return activated, teamID
}

// parseLaunchdState extracts the service-level state and last-exit info from
// `launchctl print system/<label>` output. Only the FIRST "state =" line is
// the service state: nested sub-sections (event triggers, XPC endpoints)
// contain their own "state = active" lines. "last exit reason" (present on
// exec-level failures like AMFI rejection, per #436) is preferred over
// "last exit code"; a code of "(never exited)" or "0" is not an exit signal.
// The reported last exit is the most recent exit launchd ever recorded for
// the service and may predate the current state.
func parseLaunchdState(output string) (state, lastExit string) {
	var exitCode, exitReason string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if state == "" {
			if v, ok := strings.CutPrefix(trimmed, "state = "); ok {
				state = strings.TrimSpace(v)
				continue
			}
		}
		if v, ok := strings.CutPrefix(trimmed, "last exit reason = "); ok && exitReason == "" {
			exitReason = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(trimmed, "last exit code = "); ok && exitCode == "" {
			exitCode = strings.TrimSpace(v)
		}
	}
	switch {
	case exitReason != "":
		lastExit = exitReason
	case exitCode != "" && exitCode != "0" && exitCode != "(never exited)":
		lastExit = "exit code " + exitCode
	}
	return state, lastExit
}

// CheckSysExtLiveness probes whether the agentmon system extension is
// activated AND its process is actually running. Decision table (fail
// closed — Running requires positive proof of state = running):
//
//	systemextensionsctl        launchctl                      -> result
//	not activated / cmd fails  (skipped)                      Activated=false, Running=false
//	activated                  state = running                Running=true
//	activated                  any other state                Running=false, Detail has state + last exit
//	activated                  cmd fails / no state / no team  Running=false, Detail "could not be verified"
func CheckSysExtLiveness() SysExtLiveness {
	out, err := runLivenessCommand("systemextensionsctl", "list")
	if err != nil {
		return SysExtLiveness{ProbeFailed: true, Detail: "not activated (liveness could not be verified: systemextensionsctl failed: " + err.Error() + ")"}
	}
	activated, teamID := parseSysExtList(out)
	if !activated {
		return SysExtLiveness{Detail: "not activated"}
	}

	liveness := SysExtLiveness{Activated: true}
	if teamID == "" {
		liveness.ProbeFailed = true
		liveness.Detail = "activated but liveness could not be verified (no team ID in systemextensionsctl output)"
		return liveness
	}

	label := "system/" + teamID + "." + sysExtBundleID
	lout, err := runLivenessCommand("launchctl", "print", label)
	if err != nil {
		liveness.ProbeFailed = true
		liveness.Detail = "activated but liveness could not be verified (launchctl print " + label + " failed: " + err.Error() + ")"
		return liveness
	}

	state, lastExit := parseLaunchdState(lout)
	liveness.State = state
	liveness.LastExit = lastExit
	checked, connected, last := checkExtensionPresence()
	liveness.ConnectionChecked = checked
	liveness.Connected = connected
	liveness.LastContact = last

	switch state {
	case "running":
		// "running" alone is not proof of anything useful. An extension denied
		// Full Disk Access fails es_new_client, retries three times, exits 1,
		// and is respawned by launchd -- so for part of every cycle it reads
		// as running while enforcing nothing. Sampling `agentmon detect`
		// through that loop on a real machine returned 40/100, 65/100, 40/100
		// in nine seconds.
		//
		// A respawn changes the pid, so sampling it twice separates a healthy
		// extension from a crash-looping one. This is deliberately not keyed
		// on a policy-socket connection: policy checks use short-lived
		// connections (PolicySocketClient.sendSync opens and closes one per
		// request), so there is nothing to observe at idle, and the persistent
		// event-stream connection was measured NOT to re-establish after a
		// server restart -- gating on it refused wrap on a demonstrably
		// healthy extension.
		// Only pay for the pid sample when there is a reason to suspect a
		// loop. A crash-looping extension always leaves a non-empty last exit
		// -- it is exiting, repeatedly -- while a healthy one that has never
		// died leaves it empty, so this skips the wait in the common case.
		// Without the guard every liveness call slept, and the internal/api
		// suite went from about 7 seconds to over 300.
		if lastExit == "" {
			liveness.Running = true
			liveness.Detail = "running"
			if checked && connected {
				liveness.Detail = "running (extension connected to the policy socket)"
			}
			break
		}
		if stable, detail := pidIsStable(label); !stable {
			liveness.Detail = detail
			if lastExit != "" {
				liveness.Detail += " (last exit: " + lastExit + ")"
			}
			break
		}
		liveness.Running = true
		liveness.Detail = "running"
		if checked && connected {
			liveness.Detail = "running (extension connected to the policy socket)"
		}
	case "":
		liveness.ProbeFailed = true
		liveness.Detail = "activated but liveness could not be verified (no state in launchctl output)"
		if lastExit != "" {
			liveness.Detail += " (last exit: " + lastExit + ")"
		}
	default:
		detail := "activated but not running (state: " + state
		if lastExit != "" {
			detail += ", last exit: " + lastExit
		}
		liveness.Detail = detail + ")"
	}
	return liveness
}

// pidStabilityWindow is how long to wait between pid samples. A crash-looping
// extension turns over in roughly seven seconds (three es_new_client retries
// two seconds apart, then exit), so a shorter wait can straddle one pid and
// miss the loop.
var pidStabilityWindow = 3 * time.Second

// pidIsStable samples the launchd job's pid twice and reports whether it held.
//
// Returns a human-readable reason when it did not, for Detail.
func pidIsStable(label string) (bool, string) {
	first, ok := launchdPID(label)
	if !ok {
		// No pid to compare. Do not claim instability on a missing field --
		// callers already treat an unparseable probe as fail-closed elsewhere.
		return true, ""
	}
	time.Sleep(pidStabilityWindow)
	second, ok := launchdPID(label)
	if !ok {
		return false, "process disappeared while being checked, so the extension is restarting rather than running"
	}
	if first != second {
		return false, fmt.Sprintf("process is restarting repeatedly (pid %s then %s within %s), so its Endpoint Security client never becomes active", first, second, pidStabilityWindow)
	}
	return true, ""
}

func launchdPID(label string) (string, bool) {
	out, err := runLivenessCommand("launchctl", "print", label)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "pid = "); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}
