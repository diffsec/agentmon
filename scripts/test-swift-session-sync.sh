#!/usr/bin/env bash
# Exercise SessionPolicyCache.activeSessions(inSnapshotReply:), which decides
# which cached sessions the system extension drops. While the extension holds
# any session, it checks every file open on the machine, so a session it fails
# to drop slows the whole machine down.
#
# Like test-swift-cidr.sh, this extracts the real function from the source and
# fails loudly if the extraction finds nothing. The reply shapes match
# TestNoSessionSnapshotShape and TestActiveSessionsInSnapshot in
# internal/platform/darwin/policysock.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=macos/AgentMon/SessionPolicyCache.swift
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

python3 - "$SRC" "$WORK/sync.swift" <<'PY'
import sys

src = open(sys.argv[1]).read()
decl = "    static func activeSessions(inSnapshotReply reply: [String: Any]) -> Set<String>? {"
if decl not in src:
    sys.exit("activeSessions declaration not found in %s -- update this script" % sys.argv[1])
i = src.index(decl)
j = src.index("\n    }\n", i) + len("\n    }\n")
fn = src[i:j].replace("    static func", "func", 1)
fn = "\n".join(l[4:] if l.startswith("    ") else l for l in fn.split("\n"))
if "active_sessions" not in fn:
    sys.exit("extracted body does not look like activeSessions -- update this script")

open(sys.argv[2], "w").write("import Foundation\n\n" + fn + r'''

var failures = 0
func check(_ reply: [String: Any], _ want: Set<String>?, _ why: String) {
    let got = activeSessions(inSnapshotReply: reply)
    if got == want {
        print("ok    \(why)")
    } else {
        print("FAIL  \(why): got \(String(describing: got)), want \(String(describing: want))")
        failures += 1
    }
}

check(["session_id": "b", "active_sessions": ["a", "b"]], ["a", "b"], "the listed sessions are active")
check(["allow": false, "rule": "no-policy-fail-closed"], [], "no session registered means none are active")
check(["session_id": "a", "allow": false, "rule": "no-policy-fail-closed"], nil,
      "a fail-closed snapshot for a real session says nothing about the others")
check(["error": "socket closed"], nil, "a reply without the list says nothing")

exit(failures == 0 ? 0 : 1)
''')
PY

swiftc -O -o "$WORK/sync" "$WORK/sync.swift"
"$WORK/sync"
