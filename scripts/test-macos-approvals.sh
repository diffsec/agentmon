#!/usr/bin/env bash
# Hardware test: approve rules on macOS open one dialog, and an approval lets
# the agent's retry succeed.
#
# The system extension cannot hold a file event while a person reads a
# dialog. It denies the operation and asks the daemon for an approval. If
# the person approves, the access is granted for 60 seconds. Identical
# requests share one dialog.
#
# A person must answer two dialogs: Approve for a file, then either answer
# for a host. Run it on a Mac where AgentMon.app is installed, its extension,
# content filter and transparent proxy are enabled, and the daemon runs with
# approvals.mode "gui". It needs internet access. Run it before each release.
set -euo pipefail

A=${AGENTMON:-/Applications/AgentMon.app/Contents/MacOS/agentmon}
PY=${PYTHON:-}
if [ -z "$PY" ]; then
    for p in /opt/homebrew/bin/python3 /usr/local/bin/python3 \
             /Library/Developer/CommandLineTools/usr/bin/python3; do
        if [ -x "$p" ]; then PY=$p; break; fi
    done
fi
[ -n "$PY" ] || { echo "no python3 found; set PYTHON" >&2; exit 2; }

WS=$(mktemp -d "${TMPDIR:-/tmp}/amappr.XXXXXX")
WS=$(cd "$WS" && pwd -P)
SID=""
status=0

cleanup() {
    [ -n "$SID" ] && "$A" session destroy "$SID" >/dev/null 2>&1 || true
    rm -rf "$WS"
}
trap 'cleanup' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

# count_events TYPE TEXT prints how many events of TYPE in the session have
# TEXT in their JSON. The search runs on compact JSON, with no space after a
# colon.
count_events() {
    "$A" events query --session "$SID" --type "$1" --text-like "%$2%" 2>/dev/null \
        | grep -c '"type": "'"$1"'"' || true
}

# wait_for TYPE TEXT SECONDS waits until an event of TYPE with TEXT exists.
wait_for() {
    local end=$((SECONDS + $3))
    while [ $SECONDS -lt $end ]; do
        [ "$(count_events "$1" "$2")" -gt 0 ] && return 0
        sleep 1
    done
    return 1
}

echo "SECRET=1" > "$WS/.env"
SID=$("$A" session create --workspace "$WS" --policy agent-default | awk '/^Session/{print $2}')
[ -n "$SID" ] || { echo "could not create a session" >&2; exit 2; }

# --- File: deny, one dialog, approve, retry succeeds -------------------------

for _ in 1 2 3; do
    if "$A" exec "$SID" -- /bin/cat "$WS/.env" >/dev/null 2>&1; then
        fail "the read of .env succeeded before any approval"
    fi
done
ok "the read of .env is denied while nobody approved it"

echo
echo ">>> Click Approve in the AgentMon dialog for $WS/.env (60 seconds)."
if wait_for approval_resolved '"approved":true' 60; then
    ok "a person approved the read"
else
    fail "nobody approved the read in 60 seconds"
fi
n=$(count_events approval_requested "/.env")
if [ "$n" -eq 1 ]; then
    ok "three reads opened one dialog"
else
    fail "three reads opened $n dialogs, want 1"
fi

# The daemon sends a new snapshot when the grant starts. Allow a moment for
# the extension to fetch it.
granted=no
for _ in 1 2 3 4 5; do
    if out=$("$A" exec "$SID" -- /bin/cat "$WS/.env" 2>/dev/null) && [ "$out" = "SECRET=1" ]; then
        granted=yes; break
    fi
    sleep 1
done
if [ $granted = yes ]; then
    ok "the retry after the approval reads .env"
else
    fail "the retry after the approval did not read .env"
fi
if "$A" exec "$SID" -- /bin/sh -c "echo X >> '$WS/.env'" >/dev/null 2>&1; then
    fail "the read grant allowed a write"
else
    ok "the read grant does not allow a write"
fi

# --- Network: four flows to one host share one dialog -------------------------

cat > "$WS/net.py" <<'PY'
import socket, sys, threading
results = []
def connect():
    try:
        socket.create_connection(("example.com", 443), timeout=90).close()
        results.append(True)
    except Exception:
        results.append(False)
threads = [threading.Thread(target=connect) for _ in range(4)]
for t in threads: t.start()
for t in threads: t.join()
print("connected=%d" % results.count(True))
PY

echo
echo ">>> Answer the AgentMon dialog for example.com:443 (90 seconds)."
out=$("$A" exec "$SID" -- "$PY" "$WS/net.py" 2>&1 || true)
n=$(count_events approval_requested "example.com:443")
if [ "$n" -eq 1 ]; then
    ok "four flows to example.com:443 opened one dialog"
else
    fail "four flows to example.com:443 opened $n dialogs, want 1"
fi
# Every flow waits for the same answer, so all four connect or none do.
if [ "$(count_events approval_resolved '"approved":true%example.com:443')" -gt 0 ] ||
   [ "$(count_events approval_resolved 'example.com:443%"approved":true')" -gt 0 ]; then
    want=4; word=approval
else
    want=0; word=denial
fi
if printf '%s' "$out" | grep -q "connected=$want"; then
    ok "after the $word, $want of 4 flows connected"
else
    fail "after the $word, want connected=$want, got: $out"
fi

trap - EXIT
cleanup
exit $status
