#!/usr/bin/env bash
# Ad-hoc signs a copy of /usr/bin/true with each .entitlements file in the
# tree. codesign parses entitlements with AMFI's XML parser, which is stricter
# than plutil: it rejects an XML comment that `plutil -lint` accepts. CI builds
# the Swift targets with signing off, so without this check a bad file is first
# found by whoever signs a release.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
count=0
while IFS= read -r file; do
  count=$((count + 1))
  cp /usr/bin/true "$TMP/bin"
  if out="$(codesign --force --sign - --entitlements "$file" "$TMP/bin" 2>&1)"; then
    echo "ok    $file"
  else
    echo "FAIL  $file: $out" >&2
    fail=1
  fi
done < <(find macos -name '*.entitlements' | sort)

if [ "$count" -eq 0 ]; then
  echo "FAIL  no .entitlements files found under macos/" >&2
  exit 1
fi
exit "$fail"
