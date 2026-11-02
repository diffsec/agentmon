#!/usr/bin/env bash
# Hardware test: unix_socket_rules and signal_rules apply to a macOS session.
#
# Before extension build 1675, the extension checked a unix socket connect
# or bind only against the daemon's own directory, and a signal only when it
# went to the daemon. A session ignored both rule types. This script runs an
# agent-default session and expects the policy's decision for each case. The
# same calls from outside the session must succeed.
#
# Run it on a Mac where AgentMon.app is installed, its extension is enabled,
# and the daemon is running. Run it before each release.
set -euo pipefail

A=${AGENTMON:-/Applications/AgentMon.app/Contents/MacOS/agentmon}
# /usr/bin/python3 is a shim that runs xcodebuild, which a session refuses.
PY=${PYTHON:-}
if [ -z "$PY" ]; then
    for p in /opt/homebrew/bin/python3 /usr/local/bin/python3 \
             /Library/Developer/CommandLineTools/usr/bin/python3; do
        if [ -x "$p" ]; then PY=$p; break; fi
    done
fi
[ -n "$PY" ] || { echo "no python3 found; set PYTHON" >&2; exit 2; }

# agent-default denies a connect to any socket under /var/run, except the
# ones that its allow rules name. usbmuxd is on every Mac.
SYS_SOCK=/var/run/usbmuxd
[ -S "$SYS_SOCK" ] || { echo "$SYS_SOCK is missing" >&2; exit 2; }

WS=$(mktemp -d "${TMPDIR:-/tmp}/amsig.XXXXXX")
WS=$(cd "$WS" && pwd -P)
SID=""
OUTSIDE_PID=""
status=0

cleanup() {
    [ -n "$OUTSIDE_PID" ] && kill "$OUTSIDE_PID" 2>/dev/null || true
    [ -n "$SID" ] && "$A" session destroy "$SID" >/dev/null 2>&1 || true
    rm -rf "$WS"
}
trap 'cleanup' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

cat > "$WS/sock.py" <<'PY'
import socket, sys
op, path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    if op == "connect":
        s.connect(path)
    elif op == "bind":
        s.bind(path)
    elif op == "resolve":
        socket.getaddrinfo(path, 443)
    print("allowed")
except PermissionError:
    print("denied")
except OSError as e:
    print("error %s" % e)
PY

# run_in WHERE CMD... prints the command's output. WHERE is "in" for the
# session and "out" for this shell.
run_in() {
    local where=$1; shift
    if [ "$where" = in ]; then
        "$A" exec "$SID" -- "$@" 2>/dev/null || true
    else
        "$@" 2>/dev/null || true
    fi
}

expect() {
    local want=$1 got=$2 what=$3
    if [ "$got" = "$want" ]; then ok "$what: $got"; else fail "$what: got '$got', want '$want'"; fi
}

SID=$("$A" session create --workspace "$WS" --policy agent-default | awk '/^Session/{print $2}')
[ -n "$SID" ] || { echo "could not create a session" >&2; exit 2; }

# --- Unix sockets ------------------------------------------------------------

# The resolver socket is /var/run/mDNSResponder, and ES names it
# /private/var/run/mDNSResponder. allow-macos-system-services must match.
expect allowed "$(run_in in "$PY" "$WS/sock.py" resolve example.com)" "session resolves a host name"
expect denied  "$(run_in in "$PY" "$WS/sock.py" connect "$SYS_SOCK")" "session connect to $SYS_SOCK"
expect allowed "$(run_in out "$PY" "$WS/sock.py" connect "$SYS_SOCK")" "outside connect to $SYS_SOCK"
# No rule names the workspace, so the default denies the bind.
expect denied  "$(run_in in "$PY" "$WS/sock.py" bind "$WS/a.sock")" "session bind in the workspace"
expect allowed "$(run_in out "$PY" "$WS/sock.py" bind "$WS/b.sock")" "outside bind in the workspace"

# --- Signals -----------------------------------------------------------------

# agent-default denies "sh -c" with a script (shellc-opaque-script), so the
# signals come from Python.
cat > "$WS/sig.py" <<'PY'
import os, signal, subprocess, sys
case = sys.argv[1]
def send(pid, sig):
    try:
        os.kill(pid, sig)
        print("sent")
    except PermissionError:
        print("refused")
if case == "child":
    p = subprocess.Popen(["/bin/sleep", "30"])
    send(p.pid, signal.SIGKILL)
    p.wait()
elif case == "grandchild":
    # The middle process is a fork, not an exec: agent-default refuses a
    # second exec of python3 in the session.
    r, w = os.pipe()
    middle = os.fork()
    if middle == 0:
        c = subprocess.Popen(["/bin/sleep", "30"])
        os.write(w, b"%d\n" % c.pid)
        c.wait()
        os._exit(0)
    send(int(os.read(r, 32)), signal.SIGKILL)
    os.waitpid(middle, 0)
else:
    send(int(sys.argv[2]), getattr(signal, case))
PY

# allow-children and allow-descendants.
expect sent "$(run_in in "$PY" "$WS/sig.py" child)" "session SIGKILL to its child"
expect sent "$(run_in in "$PY" "$WS/sig.py" grandchild)" "session SIGKILL to its grandchild"

# deny-external-fatal: a process outside the session survives SIGTERM. It
# ignores SIGHUP, so the last case does not stop it.
/bin/sh -c 'trap "" HUP; exec sleep 300' &
OUTSIDE_PID=$!
expect refused "$(run_in in "$PY" "$WS/sig.py" SIGTERM "$OUTSIDE_PID")" "session SIGTERM to a process outside the session"
if kill -0 "$OUTSIDE_PID" 2>/dev/null; then
    ok "the outside process still runs"
else
    fail "the outside process died"
fi
# No rule allows SIGHUP to a process outside the session, so the default
# denies it.
expect refused "$(run_in in "$PY" "$WS/sig.py" SIGHUP "$OUTSIDE_PID")" "session SIGHUP to a process outside the session"
expect sent "$(run_in out "$PY" "$WS/sig.py" SIGHUP "$OUTSIDE_PID")" "outside SIGHUP to the same process"

# --- Events ------------------------------------------------------------------

count() {
    "$A" events query --session "$SID" --type "$1" 2>/dev/null | grep -c '"type": "'"$1"'"' || true
}
n=$(count unix_socket_op)
if [ "$n" -ge 2 ]; then ok "$n unix_socket_op events"; else fail "$n unix_socket_op events, want 2 or more"; fi
n=$(count signal_blocked)
if [ "$n" -ge 2 ]; then ok "$n signal_blocked events"; else fail "$n signal_blocked events, want 2 or more"; fi

trap - EXIT
cleanup
exit $status
