#!/usr/bin/env bash
# Smoke test for assemble-macos-bundle.sh. Runs anywhere (no Xcode, no
# signing identity): fakes the Xcode products and Go binaries, assembles,
# and asserts the bundle tree. Running on a case-sensitive filesystem
# (Linux CI) also catches macos/agentmon-vs-macos/AgentMon path drift.
set -euo pipefail
cd "$(dirname "$0")/.."

SYSEXT="dev.diffsec.agentmon.SysExt.systemextension"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Fake Xcode build products
mkdir -p "$TMP/products/$SYSEXT/Contents/MacOS"
touch "$TMP/products/$SYSEXT/Contents/MacOS/sysext"
mkdir -p "$TMP/products/approval-dialog.app/Contents"

# Fake Go binaries
mkdir -p "$TMP/go-bin"
touch "$TMP/go-bin/agentmon" "$TMP/go-bin/agentmon-shell-shim" \
      "$TMP/go-bin/agentmon-stub" "$TMP/go-bin/agentmon-macwrap"

APP="$TMP/AgentMon.app"
GO_BIN_DIR="$TMP/go-bin" PRODUCTS_DIR="$TMP/products" \
  scripts/assemble-macos-bundle.sh "$APP"

fail=0
require() {
  if [ ! -e "$1" ]; then
    echo "MISSING: $1" >&2
    fail=1
  fi
}

require "$APP/Contents/MacOS/agentmon"
require "$APP/Contents/MacOS/agentmon-shell-shim"
require "$APP/Contents/MacOS/agentmon-stub"
# agentmon-macwrap applies the seatbelt profile for every exec. It went
# unshipped for the whole life of the macOS port, and the only symptom was a
# log line nobody read.
require "$APP/Contents/MacOS/agentmon-macwrap"
require "$APP/Contents/Info.plist"
require "$APP/Contents/Library/SystemExtensions/$SYSEXT"
require "$APP/Contents/Library/SystemExtensions/$SYSEXT/Contents/embedded.provisionprofile"
# The XPC service was removed: nothing used it, and it still went through
# signing and notarization on every release.
if [ -e "$APP/Contents/XPCServices" ]; then
  echo "UNEXPECTED: $APP/Contents/XPCServices" >&2
  fail=1
fi
require "$APP/Contents/Resources/approval-dialog.app"
require "$APP/Contents/embedded.provisionprofile"
require "$APP/Contents/Resources/config.yml"
# The bundle ships the macOS config, not the repository's development config.
# The development config uses auth.type none and paths relative to the working
# directory, which is / under launchd.
if ! cmp -s macos/AgentMon-files/config.yml "$APP/Contents/Resources/config.yml"; then
  echo "WRONG: Resources/config.yml is not macos/AgentMon-files/config.yml" >&2
  fail=1
fi
require "$APP/Contents/Resources/default-policy.yml"
[ -n "$(ls "$APP/Contents/Resources/configs/policies/"*.yaml 2>/dev/null)" ] \
  || { echo "MISSING: Resources/configs/policies/*.yaml" >&2; fail=1; }

# GO_BIN_DIR must be required, not silently skipped
if PRODUCTS_DIR="$TMP/products" scripts/assemble-macos-bundle.sh "$TMP/Other.app" 2>/dev/null; then
  echo "FAIL: assemble succeeded without GO_BIN_DIR" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: assemble smoke test"
exit "$fail"
