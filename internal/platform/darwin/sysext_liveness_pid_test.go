//go:build darwin

package darwin

import (
	"strings"
	"testing"
	"time"
)

// TestPidStability_DetectsCrashLoop is the regression test for the fail-open
// that shipped in the wrap gate.
//
// An extension denied Full Disk Access fails es_new_client, retries three
// times, exits 1 and is respawned. launchd reports it as "running" for part of
// every cycle, so `agentmon detect` sampled 40/100, 65/100, 40/100 in nine
// seconds on a real machine while the ES client was dead throughout -- and
// `agentmon wrap` gated on the same signal, so it would intermittently launch
// an agent against an extension enforcing nothing.
func TestPidStability_DetectsCrashLoop(t *testing.T) {
	orig := runLivenessCommand
	origWindow := pidStabilityWindow
	t.Cleanup(func() { runLivenessCommand = orig; pidStabilityWindow = origWindow })
	pidStabilityWindow = 10 * time.Millisecond

	pids := []string{"111", "222"}
	i := 0
	runLivenessCommand = func(name string, args ...string) (string, error) {
		if name == "ps" {
			// Young enough that the uptime shortcut cannot apply, so the
			// sampling path under test actually runs.
			return "00:03\n", nil
		}
		p := pids[i%len(pids)]
		i++
		return "\tstate = running\n\tpid = " + p + "\n", nil
	}

	stable, detail := pidIsStable("system/anything")
	if stable {
		t.Fatal("a process whose pid changed between samples was reported stable; that is a respawning extension and enforcement is not happening")
	}
	if !strings.Contains(detail, "restarting repeatedly") {
		t.Errorf("detail should explain the restart loop, got: %q", detail)
	}
}

// TestPidStability_AcceptsSteadyProcess is the other half: a healthy extension
// keeps one pid, and must not be reported as restarting. Without this, the
// test above is satisfied by a check that always fails.
func TestPidStability_AcceptsSteadyProcess(t *testing.T) {
	orig := runLivenessCommand
	origWindow := pidStabilityWindow
	t.Cleanup(func() { runLivenessCommand = orig; pidStabilityWindow = origWindow })
	pidStabilityWindow = 10 * time.Millisecond

	runLivenessCommand = func(name string, args ...string) (string, error) {
		return "\tstate = running\n\tpid = 4242\n", nil
	}

	if stable, detail := pidIsStable("system/anything"); !stable {
		t.Fatalf("a steady process was reported as restarting: %q", detail)
	}
}

// TestPidStability_MissingPidIsNotInstability: an unparseable probe must not be
// reported as a crash loop. Probe failure is handled by ProbeFailed elsewhere,
// and conflating the two would produce a misleading reason.
func TestPidStability_MissingPidIsNotInstability(t *testing.T) {
	orig := runLivenessCommand
	t.Cleanup(func() { runLivenessCommand = orig })
	runLivenessCommand = func(name string, args ...string) (string, error) {
		return "\tstate = running\n", nil
	}
	if stable, _ := pidIsStable("system/anything"); !stable {
		t.Fatal("missing pid field was reported as a restart loop")
	}
}

// TestCheckSysExtLiveness_CrashLoopIsNotRunning exercises the guarded path end
// to end: launchd says "running", but there is a last exit AND the pid moves,
// which is exactly what a crash loop looks like. Running must come back false.
func TestCheckSysExtLiveness_CrashLoopIsNotRunning(t *testing.T) {
	orig := runLivenessCommand
	origWindow := pidStabilityWindow
	t.Cleanup(func() { runLivenessCommand = orig; pidStabilityWindow = origWindow })
	pidStabilityWindow = 10 * time.Millisecond

	pids := []string{"111", "222", "333", "444"}
	i := 0
	runLivenessCommand = func(name string, args ...string) (string, error) {
		if name == "systemextensionsctl" {
			return "1 extension(s)\n--- com.apple.system_extension.endpoint_security\n" +
				"*\t*\tLWSYS6YTUZ\t" + sysExtBundleID + " (1.0/1)\t" + sysExtBundleID + "\t[activated enabled]\n", nil
		}
		if name == "ps" {
			// Three seconds old: too young for the uptime shortcut, so the
			// sampling path is the one under test.
			return "00:03\n", nil
		}
		p := pids[i%len(pids)]
		i++
		return "\tstate = running\n\tpid = " + p + "\n\tlast exit code = 1\n", nil
	}

	live := CheckSysExtLiveness()
	if live.Running {
		t.Fatal("a crash-looping extension was reported as Running; wrap gates on this and would launch an agent against an extension enforcing nothing")
	}
	if !strings.Contains(live.Detail, "restarting repeatedly") {
		t.Errorf("Detail should explain the restart loop, got: %q", live.Detail)
	}
}

// TestParseETime pins the format `ps -o etime=` actually emits.
//
// This exists because the first implementation used `-o etimes=`, which yields
// plain seconds and needs no parsing at all -- and which macOS ps does not
// have. It exits 1 with "keyword not found", the caller treats any failure as
// "fall back to sampling", and the only visible symptom was the 3s wait the
// shortcut was written to avoid.
func TestParseETime(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"16:10", 16*time.Minute + 10*time.Second, true},
		{"00:03", 3 * time.Second, true},
		{"01:02:03", time.Hour + 2*time.Minute + 3*time.Second, true},
		{"2-03:04:05", 48*time.Hour + 3*time.Hour + 4*time.Minute + 5*time.Second, true},
		{"  16:10  \n", 16*time.Minute + 10*time.Second, true},
		{"", 0, false},
		{"10", 0, false},
		{"1:2:3:4", 0, false},
		{"ps: etimes: keyword not found", 0, false},
		{"aa:bb", 0, false},
		{"-1:00", 0, false},
	}
	for _, c := range cases {
		got, ok := parseETime(c.in)
		if ok != c.ok {
			t.Errorf("parseETime(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseETime(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestPidStability_SkipsSampleForSettledProcess pins the shortcut. Without it,
// every liveness call costs pidStabilityWindow on any machine whose extension
// has ever exited -- which is every machine that has ever upgraded one, because
// launchd remembers the last exit forever.
func TestPidStability_SkipsSampleForSettledProcess(t *testing.T) {
	orig := runLivenessCommand
	origWindow := pidStabilityWindow
	t.Cleanup(func() { runLivenessCommand = orig; pidStabilityWindow = origWindow })
	// Long enough that a sample would be obvious in the elapsed time.
	pidStabilityWindow = 2 * time.Second

	samples := 0
	runLivenessCommand = func(name string, args ...string) (string, error) {
		if name == "ps" {
			return "10:00\n", nil // ten minutes: settled
		}
		samples++
		return "\tstate = running\n\tpid = 4242\n", nil
	}

	start := time.Now()
	if stable, detail := pidIsStable("system/anything"); !stable {
		t.Fatalf("a settled process was reported as restarting: %q", detail)
	}
	if elapsed := time.Since(start); elapsed >= pidStabilityWindow {
		t.Errorf("took %s; the sample was not skipped", elapsed)
	}
	if samples != 1 {
		t.Errorf("launchctl was queried %d times, want 1 (no second sample)", samples)
	}
}
