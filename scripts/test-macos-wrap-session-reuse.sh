#!/usr/bin/env bash
# Hardware test: every `agentmon wrap --session` into one session runs inside
# that session.
#
# Before build 1677 the daemon sent the extension only the session's first
# root PID. A wrap into a session that the extension already held returned at
# once, and its agent ran outside the session with no policy (SECENG-312).
# This script starts two wraps into one session, the first still running
# while the second starts, and expects agent-default to deny a connect to
# /var/run/usbmuxd in both.
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
# Homebrew's python3 is a launcher that execs Python.app. Under wrap, that
# second exec dies with no event (SECENG-311), so wrap runs Python.app itself.
PYAPP=$("$PY" -c 'import os, sys; print(os.path.join(sys.base_prefix, "Resources/Python.app/Contents/MacOS/Python"))')
[ -x "$PYAPP" ] || { echo "$PYAPP is missing" >&2; exit 2; }

SYS_SOCK=/var/run/usbmuxd
[ -S "$SYS_SOCK" ] || { echo "$SYS_SOCK is missing" >&2; exit 2; }

WS=$(mktemp -d "${TMPDIR:-/tmp}/amreuse.XXXXXX")
WS=$(cd "$WS" && pwd -P)
SID=""
FIRST_PID=""
status=0

cleanup() {
    [ -n "$FIRST_PID" ] && kill "$FIRST_PID" 2>/dev/null || true
    [ -n "$SID" ] && "$A" session destroy "$SID" >/dev/null 2>&1 || true
    rm -rf "$WS"
}
trap 'cleanup' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

# probe.py prints "insession" when the connect is denied, which agent-default
# does only to a session process. With a file name, it checks once, then waits
# for that file and checks again.
cat > "$WS/probe.py" <<'PY'
import os, socket, sys, time

def check():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect("/var/run/usbmuxd")
        return "outside"
    except PermissionError:
        return "insession"
    finally:
        s.close()

print(check(), flush=True)
if len(sys.argv) > 1:
    for _ in range(600):
        if os.path.exists(sys.argv[1]):
            break
        time.sleep(0.1)
    print(check(), flush=True)
PY

SID=$("$A" session create --workspace "$WS" --policy agent-default | awk '/^Session/{print $2}')
[ -n "$SID" ] || { echo "could not create a session" >&2; exit 2; }

wrap() {
    (cd "$WS" && "$A" wrap --session "$SID" --report=false -- "$PYAPP" "$WS/probe.py" "$@" 2>>"$WS/err")
}

# The first wrap checks, then waits until the second wrap finished.
wrap "$WS/go" > "$WS/first.out" &
FIRST_PID=$!
for _ in $(seq 1 100); do
    [ -s "$WS/first.out" ] && break
    sleep 0.1
done
got=$(head -n 1 "$WS/first.out")
if [ "$got" = insession ]; then ok "first wrap: in the session"; else fail "first wrap: got '$got', want insession"; fi

got=$(wrap | tail -n 1)
if [ "$got" = insession ]; then ok "second wrap: in the session"; else fail "second wrap: got '$got', want insession"; fi

touch "$WS/go"
wait "$FIRST_PID" || true
FIRST_PID=""
got=$(sed -n 2p "$WS/first.out")
if [ "$got" = insession ]; then
    ok "first wrap after the second started: still in the session"
else
    fail "first wrap after the second started: got '$got', want insession"
fi

got=$(wrap | tail -n 1)
if [ "$got" = insession ]; then ok "third wrap: in the session"; else fail "third wrap: got '$got', want insession"; fi

if [ $status -ne 0 ] && [ -s "$WS/err" ]; then
    echo "wrap stderr:"
    sed 's/^/      /' "$WS/err"
fi

trap - EXIT
cleanup
exit $status
