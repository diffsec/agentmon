#!/usr/bin/env bash
# Hardware test: a session process cannot get the task port of a process
# outside its session, or suspend it.
#
# macOS refuses task_for_pid, task_read_for_pid and pid_suspend from a normal
# user. Root can use them on any process that is not a platform binary and
# not hardened. So the session process in this test runs as root: the script
# runs `sudo agentmon wrap`, which asks for your password. The same calls
# from root outside the session must succeed.
#
# Run it as your own user, not with sudo, on a Mac where AgentMon.app is
# installed, its extension is enabled, and the daemon is running. Run it
# before each release.
set -euo pipefail

A=${AGENTMON:-/Applications/AgentMon.app/Contents/MacOS/agentmon}
# The target must not be a platform binary or hardened, so it is a Python
# that Homebrew or python.org installed. /usr/bin/python3 does not work.
PY=${PYTHON:-}
if [ -z "$PY" ]; then
    for p in /opt/homebrew/bin/python3 /usr/local/bin/python3; do
        if [ -x "$p" ]; then PY=$p; break; fi
    done
fi
[ -n "$PY" ] || { echo "no python3 found; set PYTHON" >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo "run this as your own user; it calls sudo itself" >&2; exit 2; }

KEY_FILE="$HOME/Library/Application Support/agentmon/local-api.key"
API_KEY=${AGENTMON_API_KEY:-}
if [ -z "$API_KEY" ] && [ -r "$KEY_FILE" ]; then API_KEY=$(cat "$KEY_FILE"); fi

WS=$(mktemp -d "${TMPDIR:-/tmp}/amproc.XXXXXX")
WS=$(cd "$WS" && pwd -P)
SID=""
TARGET_PID=""
status=0

cleanup() {
    [ -n "$TARGET_PID" ] && kill "$TARGET_PID" 2>/dev/null || true
    [ -n "$SID" ] && "$A" session destroy "$SID" >/dev/null 2>&1 || true
    rm -rf "$WS"
}
trap 'cleanup' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

cat > "$WS/access.py" <<'PY'
import ctypes, os, subprocess, sys
libc = ctypes.CDLL(None, use_errno=True)
me = ctypes.c_uint32.in_dll(libc, "mach_task_self_")

def task_port(fn, pid):
    port = ctypes.c_uint32()
    return "allowed" if fn(me, pid, ctypes.byref(port)) == 0 else "denied"

def suspend(pid):
    if libc.pid_suspend(pid) != 0:
        return "denied"
    libc.pid_resume(pid)
    return "allowed"

def check(pid):
    return " ".join([task_port(libc.task_for_pid, pid),
                     task_port(libc.task_read_for_pid, pid),
                     suspend(pid)])

if sys.argv[1] == "child":
    # A child of this process is in the same session.
    c = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    print(check(c.pid))
    c.kill()
else:
    print(check(int(sys.argv[1])))
PY

# The target runs outside the session. It must be a Homebrew Python, not
# /bin/sleep, because root cannot get the task port of a platform binary.
"$PY" -c "import time; time.sleep(300)" &
TARGET_PID=$!

SID=$("$A" session create --workspace "$WS" --policy agent-default | awk '/^Session/{print $2}')
[ -n "$SID" ] || { echo "could not create a session" >&2; exit 2; }

echo "sudo runs the root half of the test."
outside=$(sudo "$PY" "$WS/access.py" "$TARGET_PID" 2>&1 || true)
if [ "$outside" = "allowed allowed allowed" ]; then
    ok "root outside the session: task_for_pid, task_read_for_pid and pid_suspend succeed"
else
    fail "root outside the session: got '$outside', want 'allowed allowed allowed'"
fi

# wrap joins the root process to the session. It reads the API key from the
# environment, because root has a different home directory.
run_wrapped() {
    (cd "$WS" && sudo AGENTMON_API_KEY="$API_KEY" "$A" wrap --session "$SID" --report=false -- \
        "$PY" "$WS/access.py" "$@" 2>/dev/null) || true
}
got=$(run_wrapped "$TARGET_PID" | tail -n 1)
if [ "$got" = "denied denied denied" ]; then
    ok "root in the session: all three calls to a process outside the session are denied"
else
    fail "root in the session to an outside process: got '$got', want 'denied denied denied'"
fi
if kill -0 "$TARGET_PID" 2>/dev/null; then
    ok "the outside process still runs"
else
    fail "the outside process died"
fi

got=$(run_wrapped child | tail -n 1)
if [ "$got" = "allowed allowed allowed" ]; then
    ok "root in the session: all three calls to its own child succeed"
else
    fail "root in the session to its child: got '$got', want 'allowed allowed allowed'"
fi

n=$("$A" events query --session "$SID" --type process_access_blocked 2>/dev/null \
    | grep -c '"type": "process_access_blocked"' || true)
if [ "$n" -ge 3 ]; then ok "$n process_access_blocked events"; else fail "$n process_access_blocked events, want 3 or more"; fi

trap - EXIT
cleanup
exit $status
