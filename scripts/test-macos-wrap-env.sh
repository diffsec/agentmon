#!/usr/bin/env bash
# Hardware test: `agentmon wrap` applies sandbox.env_inject and env_policy to
# the agent's environment on macOS, as it does on Linux.
#
# Before build 1684, the macOS wrap-init reply carried neither, so the agent
# got the caller's environment unchanged.
#
# The daemon configuration needs an env_inject entry. The shipped
# configuration injects BASH_ENV. The env_policy check runs only when
# sandbox.wrap_env_policy.enabled is true. It then expects agent-default to
# remove AWS_SECRET_ACCESS_KEY.
#
# Run it on a Mac where AgentMon.app is installed, its extension is enabled,
# and the daemon is running. Run it before each release.
set -euo pipefail

A=${AGENTMON:-/Applications/AgentMon.app/Contents/MacOS/agentmon}
CONFIG=${AGENTMON_CONFIG:-"$HOME/Library/Application Support/agentmon/config.yml"}
PY=${PYTHON:-}
if [ -z "$PY" ]; then
    for p in /opt/homebrew/bin/python3 /usr/local/bin/python3; do
        if [ -x "$p" ]; then PY=$p; break; fi
    done
fi
[ -n "$PY" ] || { echo "no python3 found; set PYTHON" >&2; exit 2; }

WS=$(mktemp -d "${TMPDIR:-/tmp}/amenv.XXXXXX")
WS=$(cd "$WS" && pwd -P)
status=0
trap 'rm -rf "$WS"' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

# The first env_inject key in the daemon configuration, and its value.
read -r KEY VAL < <(awk '
    /^[^ #]/ { insb = ($0 ~ /^sandbox:/) }
    insb && /^  env_inject:/ { ine = 1; next }
    ine && /^    [A-Za-z_][A-Za-z0-9_]*:/ {
        k = $1; sub(":", "", k); v = $2; gsub("\"", "", v); print k, v; exit }
    ine && /^  [^ ]/ { ine = 0 }
' "$CONFIG") || true
[ -n "${KEY:-}" ] || { echo "no sandbox.env_inject entry in $CONFIG" >&2; exit 2; }

got=$(cd "$WS" && env "$KEY=caller-value" AWS_SECRET_ACCESS_KEY=caller-secret \
    "$A" wrap --policy agent-default --report=false -- \
    "$PY" -c "import os; print(os.environ.get('$KEY', '-'), os.environ.get('AWS_SECRET_ACCESS_KEY', '-'))" \
    2>>"$WS/err" | tail -n 1) || true
read -r injected secret <<<"$got"

if [ "${injected:-}" = "$VAL" ]; then
    ok "env_inject sets $KEY=$VAL under wrap"
else
    fail "$KEY under wrap: got '${injected:-}', want '$VAL'"
fi

if awk '/^  wrap_env_policy:/ { w = 1; next } w && /enabled: *true/ { f = 1 } w && /^  [^ ]/ { w = 0 } END { exit !f }' "$CONFIG"; then
    if [ "${secret:-}" = "-" ]; then
        ok "env_policy removes AWS_SECRET_ACCESS_KEY under wrap"
    else
        fail "AWS_SECRET_ACCESS_KEY under wrap: got '${secret:-}', want it removed"
    fi
else
    echo "skip  env_policy: sandbox.wrap_env_policy.enabled is not true"
fi

if [ $status -ne 0 ] && [ -s "$WS/err" ]; then
    echo "wrap stderr:"
    sed 's/^/      /' "$WS/err"
fi
exit $status
