#!/usr/bin/env bash
# Sign the macOS app bundle inside-out (nested code first, outer app last).
# Single source of truth for local (Makefile) and release (release.yml)
# signing — fix signing here, not in the callers (issue #442).
#
# Usage: SIGNING_IDENTITY="Developer ID Application: ..." \
#          sign-macos-bundle.sh <app-bundle-path>
#
# Must run from the repository root (entitlements paths are repo-relative).
set -euo pipefail

APP="${1:?usage: SIGNING_IDENTITY=... sign-macos-bundle.sh <app-bundle-path>}"
SYSEXT="dev.diffsec.agentmon.SysExt.systemextension"

if [ -z "${SIGNING_IDENTITY:-}" ]; then
  echo "error: SIGNING_IDENTITY must be set (see 'security find-identity -v -p codesigning')" >&2
  exit 1
fi

# 1. Go binaries, with entitlements scoped to the binary that needs them.
#
# com.apple.developer.system-extension.install is a restricted entitlement, and
# only the host app calls OSSystemExtensionRequest. It used to be granted to
# every binary in Contents/MacOS except the shell shim, so agentmon-stub -- the
# exec-redirect helper an agent's own commands run through -- carried the right
# to install a system extension it never uses. agentmon-macwrap needs no
# entitlement at all: sandbox_init_with_parameters is a private API, not a
# gated one.
APP_ENTITLEMENTS="macos/AgentMon/agentmon/agentmon.entitlements"
if [ ! -f "$APP_ENTITLEMENTS" ]; then
  echo "error: entitlements file not found: $APP_ENTITLEMENTS" >&2
  exit 1
fi

for bin in "${APP}/Contents/MacOS"/*; do
  name="$(basename "$bin")"
  case "$name" in
    agentmon)
      echo "Signing $name (app entitlements)"
      codesign --force --sign "$SIGNING_IDENTITY" \
        --entitlements "$APP_ENTITLEMENTS" \
        --options runtime --timestamp \
        "$bin"
      ;;
    *)
      echo "Signing $name (no entitlements)"
      codesign --force --sign "$SIGNING_IDENTITY" \
        --options runtime --timestamp \
        "$bin"
      ;;
  esac
  codesign --verify --strict "$bin"
done

# 2. System Extension
echo "Signing System Extension"
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/AgentMon/SysExt.entitlements \
  --options runtime --timestamp \
  "${APP}/Contents/Library/SystemExtensions/${SYSEXT}"

# 3. XPC Service
echo "Signing XPC Service"
codesign --force --sign "$SIGNING_IDENTITY" \
  --options runtime --timestamp \
  "${APP}/Contents/XPCServices/xpc.xpc"

# 4. Approval Dialog
echo "Signing Approval Dialog"
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/AgentMon/approval-dialog/approval-dialog.entitlements \
  --options runtime --timestamp \
  "${APP}/Contents/Resources/approval-dialog.app"

# 5. Main app bundle
echo "Signing app bundle"
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements "$APP_ENTITLEMENTS" \
  --options runtime --timestamp \
  "${APP}"

# 6. Verify
codesign --verify --deep --strict --verbose=2 "${APP}"
