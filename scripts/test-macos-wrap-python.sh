#!/usr/bin/env bash
# Hardware test: Homebrew's python3 runs under `agentmon wrap`, and an exec
# that the policy denies leaves an execve event.
#
# Before build 1678, python3 exited 255 under wrap, and no event said why
# (SECENG-311). /opt/homebrew/bin/python3 resolves to .../bin/python3.15, and
# ES reports that resolved path. agent-default names python3, not
# python3.15, so the exec fell through to default-deny-commands.
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

WS=$(mktemp -d "${TMPDIR:-/tmp}/ampy.XXXXXX")
WS=$(cd "$WS" && pwd -P)
status=0
trap 'rm -rf "$WS"' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

wrap() {
    (cd "$WS" && "$A" wrap --policy agent-default --report=false -- "$@" 2>>"$WS/err")
}

# --- python3 runs ------------------------------------------------------------

rc=0
got=$(wrap "$PY" -c 'print("ran")') || rc=$?
if [ "$got" = ran ] && [ $rc -eq 0 ]; then
    ok "$PY runs under wrap"
else
    fail "$PY under wrap: got '$got', exit $rc, want 'ran', exit 0"
fi

# --- a denied exec leaves an event --------------------------------------------

# No agent-default rule names /usr/bin/banner, so default-deny-commands
# denies it. python3 starts it, so the extension, not wrap, makes the check.
# A denied exec after a fork ends the child with SIGKILL, so the probe reads
# the exit status. Outside a session, banner exits 0.
cat > "$WS/deny.py" <<'PY'
import subprocess
try:
    r = subprocess.run(["/usr/bin/banner", "x"], capture_output=True)
    print("ran" if r.returncode == 0 else "denied")
except PermissionError:
    print("denied")
PY
got=$(wrap "$PY" "$WS/deny.py" | tail -n 1) || true
if [ "$got" = denied ]; then ok "an exec of /usr/bin/banner is denied"; else fail "/usr/bin/banner: got '$got', want denied"; fi

# The events search runs on compact JSON, with no space after a colon.
n=$("$A" events query --since 5m --type execve --text-like '%/usr/bin/banner%' 2>/dev/null \
    | grep -c '"type": "execve"' || true)
if [ "$n" -ge 1 ]; then ok "$n execve event for /usr/bin/banner"; else fail "no execve event for /usr/bin/banner"; fi

if [ $status -ne 0 ] && [ -s "$WS/err" ]; then
    echo "wrap stderr:"
    sed 's/^/      /' "$WS/err"
fi
exit $status
