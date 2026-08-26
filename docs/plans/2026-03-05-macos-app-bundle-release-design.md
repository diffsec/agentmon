# macOS App Bundle Release Design

## Goal

Replace standalone macOS CLI binary signing with a full `.app` bundle release. macOS users get a signed, notarized DMG containing the app bundle with system extension, XPC service, and approval dialog embedded.

## Pipeline Structure

```
goreleaser ──→ build-macos-app ──→ update-checksums
           ──→ alpine-build     ──↗
           ──→ docker-test
```

The `sign-macos` job in `release.yml` is replaced by `build-macos-app`. No matrix — single job produces one universal DMG.

The disabled `macos-enterprise.yml` workflow is deleted (functionality merged here).

## Universal Binary Assembly

**Go binaries:** GoReleaser produces separate arm64 and amd64 darwin archives. Download both, extract, and `lipo` them:

```bash
lipo -create -output agentmon-universal \
  unsigned-arm64/agentmon \
  unsigned-amd64/agentmon
```

Same for `agentmon-shell-shim` and any other Mach-O binaries in the archives.

**Swift targets:** Build the Xcode project as universal in one shot:

```bash
xcodebuild \
  -project macos/diffsec/agentmon.xcodeproj \
  -scheme agentmon \
  -configuration Release \
  -derivedDataPath build/DerivedData \
  ARCHS="arm64 x86_64" \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO
```

Built unsigned — signing happens in a dedicated step.

## App Bundle Structure

```
AgentMon.app/
  Contents/
    Info.plist                          ← from macos/AgentMon-files/Info.plist
    MacOS/
      agentmon                           ← universal Go binary (lipo'd)
      agentmon-shell-shim                ← universal Go binary (lipo'd)
    Library/SystemExtensions/
      SysExt.systemextension/           ← from DerivedData
    XPCServices/
      xpc.xpc/                          ← from DerivedData
    Resources/
      approval-dialog.app/              ← from DerivedData
```

## Code Signing (Inside-Out)

Each component signed explicitly with its own entitlements. No `--deep` on individual components.

```bash
# 1. System Extension
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/agentmon/SysExt.entitlements \
  --options runtime --timestamp \
  "build/AgentMon.app/Contents/Library/SystemExtensions/SysExt.systemextension"

# 2. XPC Service
codesign --force --sign "$SIGNING_IDENTITY" \
  --options runtime --timestamp \
  "build/AgentMon.app/Contents/XPCServices/xpc.xpc"

# 3. Approval Dialog
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/agentmon/approval-dialog/approval-dialog.entitlements \
  --options runtime --timestamp \
  "build/AgentMon.app/Contents/Resources/approval-dialog.app"

# 4. Main app bundle
codesign --force --sign "$SIGNING_IDENTITY" \
  --entitlements macos/diffsec/agentmon/agentmon.entitlements \
  --options runtime --timestamp \
  "build/AgentMon.app"

# 5. Verify
codesign --verify --deep --strict --verbose=2 "build/AgentMon.app"
```

## Entitlements Reference

| Component | Entitlements file | Key entitlements |
|---|---|---|
| agentmon (host app) | `macos/diffsec/agentmon/agentmon.entitlements` | system-extension.install, app-sandbox, network.client |
| SysExt | `macos/agentmon/SysExt.entitlements` | networkextension (content-filter, dns-proxy) |
| xpc | none (sandbox from build settings) | app-sandbox, hardened-runtime |
| approval-dialog | `macos/agentmon/approval-dialog/approval-dialog.entitlements` | app-sandbox, network.client |

## Notarization & DMG

```bash
ditto -c -k --keepParent build/AgentMon.app build/AgentMon.zip
xcrun notarytool submit build/AgentMon.zip \
  --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" \
  --team-id "$TEAM_ID" --wait --timeout 20m
xcrun stapler staple build/AgentMon.app

hdiutil create -volname "AgentMon" \
  -srcfolder build/AgentMon.app \
  -ov -format UDZO "build/AgentMon-${VERSION}.dmg"
```

Upload DMG, delete old darwin tarballs from release.

## File Changes

**Modify:**
- `.github/workflows/release.yml` — Replace `sign-macos` with `build-macos-app`
- `Makefile` — Update macOS enterprise targets to new paths

**Delete:**
- `.github/workflows/macos-enterprise.yml` — Merged into release.yml
- `macos/AgentMon-files/AgentMon.entitlements` — Replaced by new entitlements

**Keep:**
- `macos/AgentMon-files/Info.plist` — Host app bundle Info.plist
- `.goreleaser.yml` — Unchanged, darwin builds remain as intermediate artifacts
