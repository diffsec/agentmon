#!/usr/bin/env bash
# Hardware test: the extension enforces resource_limits.pids_max. An exec in
# a session that holds more processes than pids_max is denied, and an
# execve event records it.
#
# agent-default sets pids_max to 500. The probe forks children that sleep,
# so that the session holds more than 500 processes, and then runs
# /bin/echo. ES has no AUTH event for fork, so the forks themselves work.
# After the children exit, /bin/echo runs again.
#
# Run it on a Mac where AgentMon.app is installed, its extension is enabled,
# and the daemon is running. Run it before each release.
set -euo pipefail

A=${AGENTMON:-/Applications/AgentMon.app/Contents/MacOS/agentmon}
PY=${PYTHON:-}
if [ -z "$PY" ]; then
    for p in /opt/homebrew/bin/python3 /usr/local/bin/python3; do
        if [ -x "$p" ]; then PY=$p; break; fi
    done
fi
[ -n "$PY" ] || { echo "no python3 found; set PYTHON" >&2; exit 2; }

START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
WS=$(mktemp -d "${TMPDIR:-/tmp}/ampids.XXXXXX")
WS=$(cd "$WS" && pwd -P)
status=0
trap 'rm -rf "$WS"' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

# The probe prints one word for each run of /bin/echo: "ran" or "denied".
# A denied exec after a fork ends the child with SIGKILL.
cat > "$WS/pids.py" <<'PY'
import os, signal, subprocess, sys, time

def echo():
    r = subprocess.run(["/bin/echo", "x"], capture_output=True)
    return "ran" if r.returncode == 0 else "denied"

before = echo()
children = []
for _ in range(int(sys.argv[1])):
    pid = os.fork()
    if pid == 0:
        time.sleep(60)
        os._exit(0)
    children.append(pid)
time.sleep(1)
over = echo()
for pid in children:
    os.kill(pid, signal.SIGKILL)
for pid in children:
    os.waitpid(pid, 0)
time.sleep(1)
print(before, over, echo())
PY

got=$(cd "$WS" && "$A" wrap --policy agent-default --report=false -- "$PY" "$WS/pids.py" 520 2>>"$WS/err" | tail -n 1) || true
if [ "$got" = "ran denied ran" ]; then
    ok "/bin/echo runs, is denied above pids_max 500, and runs again after the children exit"
else
    fail "got '$got', want 'ran denied ran'"
fi

# The events search runs on compact JSON, with no space after a colon.
n=$("$A" events query --since "$START" --type execve --text-like '%resource-limit-pids-max%' 2>/dev/null \
    | grep -c '"type": "execve"' || true)
if [ "$n" -ge 1 ]; then ok "$n execve event from the pids_max limit"; else fail "no execve event from the pids_max limit"; fi

if [ $status -ne 0 ] && [ -s "$WS/err" ]; then
    echo "wrap stderr:"
    sed 's/^/      /' "$WS/err"
fi
exit $status
