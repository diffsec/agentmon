#!/usr/bin/env bash
# Hardware test: file calls that change or copy a file without opening it
# must follow the session policy.
#
# On extension build 1669, an agent-default session could clonefile() a file
# in ~/.ssh into its workspace and read the copy, and could truncate() and
# chmod() a file outside the workspace. A write to the same file was refused.
# This script runs those calls, and the related ones, inside a session and
# expects each one to fail. The same calls on a workspace file must succeed.
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

WS=$(mktemp -d "${TMPDIR:-/tmp}/amws.XXXXXX")
WS=$(cd "$WS" && pwd -P)
OUTSIDE="$HOME/agentmon-bypass-test-$$.txt"
SECRET_DIR="$HOME/.ssh"
SECRET="$SECRET_DIR/agentmon-bypass-test-$$"
SID=""
made_ssh_dir=0

cleanup() {
    [ -n "$SID" ] && "$A" session destroy "$SID" >/dev/null 2>&1 || true
    chflags nouchg,nohidden "$OUTSIDE" 2>/dev/null || true
    rm -f "$OUTSIDE" "$SECRET"
    rmdir "$OUTSIDE.d" 2>/dev/null || true
    [ "$made_ssh_dir" = 1 ] && rmdir "$SECRET_DIR" 2>/dev/null || true
    rm -rf "$WS"
}
trap 'cleanup' EXIT

printf 'keep\n' > "$OUTSIDE"
chmod 644 "$OUTSIDE"
if [ ! -d "$SECRET_DIR" ]; then mkdir -m 700 "$SECRET_DIR"; made_ssh_dir=1; fi
printf 'secret\n' > "$SECRET"
printf 'inside\n' > "$WS/inside.txt"

cat > "$WS/bypass.py" <<'PY'
import ctypes, os, sys

libc = ctypes.CDLL(None, use_errno=True)
outside, secret, ws = sys.argv[1], sys.argv[2], sys.argv[3]
inside = os.path.join(ws, "inside.txt")
failures = 0

def call(name, fn):
    ctypes.set_errno(0)
    try:
        rc = fn()
        err = ctypes.get_errno() if rc != 0 else 0
    except OSError as e:
        err = e.errno or 1
    return err

def refused(name, fn):
    global failures
    err = call(name, fn)
    if err in (1, 13):  # EPERM, EACCES
        print("ok    refused: %s" % name)
    else:
        print("FAIL  not refused: %s (errno %d)" % (name, err))
        failures += 1

def allowed(name, fn):
    global failures
    err = call(name, fn)
    if err == 0:
        print("ok    allowed: %s" % name)
    else:
        print("FAIL  refused in the workspace: %s (%s)" % (name, os.strerror(err)))
        failures += 1

b = lambda p: p.encode()
# Python on macOS has no os.setxattr.
setxattr = lambda p: libc.setxattr(b(p), b"user.agentmon", b"x", 1, 0, 0)

# Copies of a protected file, made without an open.
refused("clonefile of a file in ~/.ssh", lambda: libc.clonefile(b(secret), b(ws + "/clone"), 0))
refused("link to a file in ~/.ssh", lambda: libc.link(b(secret), b(ws + "/hardlink")))

# Changes to a file outside the workspace, made without an open for writing.
refused("truncate outside", lambda: libc.truncate(b(outside), ctypes.c_longlong(0)))
refused("chmod outside", lambda: libc.chmod(b(outside), 0o600))
refused("chown outside", lambda: libc.chown(b(outside), os.getuid(), os.getgid()))
refused("chflags outside", lambda: libc.chflags(b(outside), 0x8000))  # UF_HIDDEN
refused("utimes outside", lambda: libc.utimes(b(outside), None))
refused("setxattr outside", lambda: setxattr(outside))
refused("mkdir outside", lambda: libc.mkdir(b(outside + ".d"), 0o755))

# The same calls in the workspace still work.
allowed("clonefile in the workspace", lambda: libc.clonefile(b(inside), b(ws + "/clone2"), 0))
allowed("link in the workspace", lambda: libc.link(b(inside), b(ws + "/link2")))
allowed("truncate in the workspace", lambda: libc.truncate(b(inside), ctypes.c_longlong(3)))
allowed("chmod in the workspace", lambda: libc.chmod(b(inside), 0o600))
allowed("utimes in the workspace", lambda: libc.utimes(b(inside), None))
allowed("setxattr in the workspace", lambda: setxattr(inside))
allowed("mkdir in the workspace", lambda: libc.mkdir(b(ws + "/d"), 0o755))
allowed("rmdir in the workspace", lambda: libc.rmdir(b(ws + "/d")))

sys.exit(1 if failures else 0)
PY

SID=$("$A" session create --workspace "$WS" --policy agent-default | awk '/^Session/{print $2}')
[ -n "$SID" ] || { echo "could not create a session" >&2; exit 2; }

status=0
"$A" exec "$SID" -- "$PY" "$WS/bypass.py" "$OUTSIDE" "$SECRET" "$WS" || status=1

# The file outside the workspace must be unchanged.
if [ "$(cat "$OUTSIDE")" != "keep" ] || [ "$(stat -f %Lp "$OUTSIDE")" != "644" ]; then
    echo "FAIL  the file outside the workspace changed"
    status=1
else
    echo "ok    the file outside the workspace is unchanged"
fi
trap - EXIT
cleanup
exit $status
