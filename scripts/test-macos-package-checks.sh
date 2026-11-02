#!/usr/bin/env bash
# Hardware test: a package install inside a macOS session is checked, also
# when the agent starts it and not `agentmon exec`.
#
# Before build 1679, only the command that `agentmon exec` started was
# package-checked. An install that an agent ran under `agentmon wrap` was
# not. agent-default blocks a package with a critical vulnerability, and
# django 2.2 has CVE-2022-34265 (CVSS 9.8).
#
# Run it on a Mac where AgentMon.app is installed, its extension is enabled,
# and the daemon runs with `package_checks.enabled: true`. It needs internet
# access to pypi.org and api.osv.dev. Run it before each release.
set -euo pipefail

A=${AGENTMON:-/Applications/AgentMon.app/Contents/MacOS/agentmon}
PY=${PYTHON:-}
if [ -z "$PY" ]; then
    for p in /opt/homebrew/bin/python3 /usr/local/bin/python3; do
        if [ -x "$p" ]; then PY=$p; break; fi
    done
fi
[ -n "$PY" ] || { echo "no python3 found; set PYTHON" >&2; exit 2; }

WS=$(mktemp -d "${TMPDIR:-/tmp}/ampkg.XXXXXX")
WS=$(cd "$WS" && pwd -P)
status=0
trap 'rm -rf "$WS"' EXIT

ok()   { echo "ok    $*"; }
fail() { echo "FAIL  $*"; status=1; }

# A pip configuration on this Mac can name another index, which
# agent-default does not allow. --isolated ignores it, and every install
# names pypi.org.
INDEX=https://pypi.org/simple

# The venv is made outside the session. Homebrew's python refuses a plain
# pip install (PEP 668), so every install goes into the venv.
"$PY" -m venv "$WS/.venv"

# install.py runs one install and prints "installed" or "refused". A denied
# exec ends the child with SIGKILL.
cat > "$WS/install.py" <<'PY'
import subprocess, sys
r = subprocess.run(sys.argv[1:], capture_output=True)
print("installed" if r.returncode == 0 else "refused rc=%d" % r.returncode)
PY

wrap() {
    (cd "$WS" && "$A" wrap --policy agent-default --report=false -- "$@" 2>>"$WS/err")
}

expect() {
    local want=$1 got=$2 what=$3
    case "$got" in
        "$want"*) ok "$what: $got" ;;
        *) fail "$what: got '$got', want '$want'" ;;
    esac
}

# pip3 is a script. ES reports the python3.15 interpreter as the executable,
# and the daemon must find pip in argv[1].
got=$(wrap "$PY" "$WS/install.py" "$WS/.venv/bin/pip" --isolated install --no-cache-dir --index-url "$INDEX" "django==2.2" | tail -n 1) || true
expect refused "$got" "pip install django==2.2 (critical CVE) under wrap"

got=$(wrap "$PY" "$WS/install.py" "$WS/.venv/bin/python" -m pip --isolated install --no-cache-dir --index-url "$INDEX" "django==2.2" | tail -n 1) || true
expect refused "$got" "python -m pip install django==2.2 under wrap"

got=$(wrap "$PY" "$WS/install.py" "$WS/.venv/bin/pip" --isolated install --no-cache-dir --index-url "$INDEX" "six==1.16.0" | tail -n 1) || true
expect installed "$got" "pip install six==1.16.0 (no findings) under wrap"

# The events search runs on compact JSON, with no space after a colon.
n=$("$A" events query --since 10m --type execve --text-like '%django%' 2>/dev/null \
    | grep -c '"rule": "package-check"' || true)
if [ "$n" -ge 2 ]; then ok "$n execve events from the package check"; else fail "$n execve events from the package check, want 2 or more"; fi

if [ $status -ne 0 ] && [ -s "$WS/err" ]; then
    echo "wrap stderr:"
    sed 's/^/      /' "$WS/err"
fi
exit $status
