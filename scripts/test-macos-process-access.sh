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

# Ask for the password before anything starts. sudo needs a terminal for it.
echo "sudo runs the root half of the test."
sudo -v || { echo "sudo failed; run this script in a terminal" >&2; exit 2; }

KEY_FILE="$HOME/Library/Application Support/agentmon/local-api.key"
API_KEY=${AGENTMON_API_KEY:-}
if [ -z "$API_KEY" ] && [ -r "$KEY_FILE" ]; then API_KEY=$(cat "$KEY_FILE"); fi

WS=$(mktemp -d "${TMPDIR:-/tmp}/amproc.XXXXXX")
WS=$(cd "$WS" && pwd -P)
TARGET_PID=""
status=0

cleanup() {
    [ -n "$TARGET_PID" ] && kill "$TARGET_PID" 2>/dev/null || true
    rm -rf "$WS"
}
trap 'cleanup' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

cat > "$WS/access.py" <<'PY'
import ctypes, os, signal, socket, sys, time
libc = ctypes.CDLL(None, use_errno=True)
me = ctypes.c_uint32.in_dll(libc, "mach_task_self_")

def step(name, result):
    # stderr shows how far the probe got if it dies part way.
    print("%s: %s" % (name, result), file=sys.stderr, flush=True)
    return result

def session_marker():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect("/var/run/usbmuxd")
        return step("usbmuxd", "outside")
    except PermissionError:
        return step("usbmuxd", "insession")
    finally:
        s.close()

def task_port(name, fn, pid):
    port = ctypes.c_uint32()
    return step(name, "allowed" if fn(me, pid, ctypes.byref(port)) == 0 else "denied")

def suspend(pid):
    if libc.pid_suspend(pid) != 0:
        return step("pid_suspend", "denied")
    libc.pid_resume(pid)
    return step("pid_suspend", "allowed")

def check(pid):
    return " ".join([session_marker(),
                     task_port("task_for_pid", libc.task_for_pid, pid),
                     task_port("task_read_for_pid", libc.task_read_for_pid, pid),
                     suspend(pid)])

if sys.argv[1] == "child":
    # A forked child is in the same session. It is a fork and not an exec,
    # because agent-default refuses a second exec of python3 in a session.
    child = os.fork()
    if child == 0:
        time.sleep(30)
        os._exit(0)
    print(check(child))
    os.kill(child, signal.SIGKILL)
    os.waitpid(child, 0)
else:
    print(check(int(sys.argv[1])))
PY

# The target runs outside the session. It must be a Homebrew Python, not
# /bin/sleep, because root cannot get the task port of a platform binary.
"$PY" -c "import time; time.sleep(300)" &
TARGET_PID=$!

outside=$(sudo "$PY" "$WS/access.py" "$TARGET_PID" 2>/dev/null || true)
if [ "$outside" = "outside allowed allowed allowed" ]; then
    ok "root outside the session: task_for_pid, task_read_for_pid and pid_suspend succeed"
else
    fail "root outside the session: got '$outside', want 'outside allowed allowed allowed'"
fi

# Homebrew's python3 is a launcher that execs Python.app. Under wrap, that
# second exec dies with no event, so wrap runs the Python.app binary itself.
PYAPP=$("$PY" -c 'import os, sys; print(os.path.join(sys.base_prefix, "Resources/Python.app/Contents/MacOS/Python"))')
[ -x "$PYAPP" ] || { echo "$PYAPP is missing" >&2; exit 2; }

# wrap creates a new agent-default session, with the wrap process as its
# root. A second wrap into the same session is not used, because the daemon
# keeps the first root PID. wrap reads the API key from the environment,
# because root has a different home directory.
#
# run_wrapped prints the probe's last line of output. On a failure the caller
# prints the exit code and stderr, which run_wrapped keeps in $WS/err.
run_wrapped() {
    local rc=0
    (cd "$WS" && sudo AGENTMON_API_KEY="$API_KEY" "$A" wrap --policy agent-default --report=false -- \
        "$PYAPP" "$WS/access.py" "$@" 2>"$WS/err") > "$WS/out" || rc=$?
    echo "exit $rc" >> "$WS/err"
    tail -n 1 "$WS/out"
}
details() { sed 's/^/      /' "$WS/err"; }

# The probe first connects to /var/run/usbmuxd, which agent-default denies to
# a session process. "insession" proves that wrap joined the probe to the
# session, so an "allowed" result is not from a process outside it.
got=$(run_wrapped "$TARGET_PID")
if [ "$got" = "insession denied denied denied" ]; then
    ok "root in the session: all three calls to a process outside the session are denied"
else
    fail "root in the session to an outside process: got '$got', want 'insession denied denied denied'"
    details
fi
if kill -0 "$TARGET_PID" 2>/dev/null; then
    ok "the outside process still runs"
else
    fail "the outside process died"
fi

got=$(run_wrapped child)
if [ "$got" = "insession allowed allowed allowed" ]; then
    ok "root in the session: all three calls to its own child succeed"
else
    fail "root in the session to its child: got '$got', want 'insession allowed allowed allowed'"
    details
fi

# The events search runs on compact JSON, with no space after a colon.
n=$("$A" events query --since 10m --type process_access_blocked --text-like "%\"target_pid\":$TARGET_PID%" 2>/dev/null \
    | grep -c '"type": "process_access_blocked"' || true)
if [ "$n" -ge 3 ]; then ok "$n process_access_blocked events"; else fail "$n process_access_blocked events, want 3 or more"; fi

trap - EXIT
cleanup
exit $status
