#!/usr/bin/env bash
# Hardware test: direct TCP connections from a session go through the
# daemon's network policy.
#
# The transparent proxy in the system extension sends each outbound TCP flow
# from a session process to the daemon, which applies the session's network
# rules in policy order. A client that ignores HTTPS_PROXY must reach a domain
# that the policy allows, and must not reach one that it does not.
#
# Run it on a Mac where AgentMon.app is installed, its extension, content
# filter and transparent proxy are enabled, and the daemon is running. It
# needs internet access. Run it before each release.
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

if ! "$A" network-filter status | grep -q "Transparent proxy: running"; then
    echo "the transparent proxy is not running; run: $A network-filter enable" >&2
    exit 2
fi

WS=$(mktemp -d "${TMPDIR:-/tmp}/amnet.XXXXXX")
WS=$(cd "$WS" && pwd -P)
SID=""

cleanup() {
    [ -n "$SID" ] && "$A" session destroy "$SID" >/dev/null 2>&1 || true
    rm -rf "$WS"
}
trap 'cleanup' EXIT

cat > "$WS/net.py" <<'PY'
import socket, ssl, sys

failures = 0

def https_get(host):
    """A direct TLS connection by name, with no proxy."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            return s.recv(12)

def http_get(host):
    """A direct plain HTTP request by name. The flow must fail before a reply."""
    with socket.create_connection((host, 80), timeout=15) as s:
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
        reply = s.recv(12)
        if not reply:
            raise ConnectionError("closed with no reply")
        return reply

def expect(name, allowed, fn):
    global failures
    try:
        fn()
        ok = allowed
        detail = "connected"
    except Exception as e:
        ok = not allowed
        detail = "%s: %s" % (type(e).__name__, e)
    word = "allowed" if allowed else "refused"
    if ok:
        print("ok    %s: %s" % (word, name))
    else:
        print("FAIL  want %s: %s (%s)" % (word, name, detail))
        failures += 1

expect("https to github.com, which allow-github allows", True, lambda: https_get("github.com"))
expect("https to pypi.org, which allow-pypi allows", True, lambda: https_get("pypi.org"))
# Port 443 to an unknown host matches approve-unknown-https, which waits for
# a person. Port 80 reaches default-deny-network.
expect("http to example.com, which default-deny-network denies", False, lambda: http_get("example.com"))
expect("tcp to 169.254.169.254:80, which deny-metadata-services denies", False,
       lambda: socket.create_connection(("169.254.169.254", 80), timeout=5).close())

sys.exit(1 if failures else 0)
PY

SID=$("$A" session create --workspace "$WS" --policy agent-default | awk '/^Session/{print $2}')
[ -n "$SID" ] || { echo "could not create a session" >&2; exit 2; }

status=0
# Python's socket module ignores HTTPS_PROXY, so each connection is direct.
# agentmon exec exits non-zero when the command met any deny, which this test
# causes on purpose, so the result comes from the script's own lines.
out=$("$A" exec "$SID" -- "$PY" "$WS/net.py" 2>&1 || true)
printf '%s\n' "$out" | grep -E '^(ok|FAIL) '
if ! printf '%s\n' "$out" | grep -q '^ok ' || printf '%s\n' "$out" | grep -q '^FAIL '; then
    status=1
fi

# The daemon must record each decision. File events fill the default
# limit, so the query asks for net_connect events only.
events=$("$A" events query --session "$SID" --type net_connect 2>/dev/null || true)
for host in github.com example.com; do
    if printf '%s' "$events" | grep -q "\"domain\": \"$host\""; then
        echo "ok    the daemon recorded a net_connect event for $host"
    else
        echo "FAIL  no net_connect event for $host"
        status=1
    fi
done

trap - EXIT
cleanup
exit $status
