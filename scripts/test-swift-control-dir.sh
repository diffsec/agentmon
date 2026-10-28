#!/usr/bin/env bash
# Exercise SessionPolicyCache.touchesControlDirectory, the check that keeps a
# session process out of the daemon's directory. The directory holds the
# policy socket, and a process that replaces the socket answers every policy
# question the system extension asks. It also holds the key that opens the
# daemon's API.
#
# Like test-swift-cidr.sh, this extracts the real function from the source and
# fails loudly if the extraction finds nothing.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=macos/AgentMon/SessionPolicyCache.swift
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

python3 - "$SRC" "$WORK/guard.swift" <<'PY'
import sys

src = open(sys.argv[1]).read()
decl = "    static func touchesControlDirectory(path: String, operation: String, controlDir: String) -> Bool {"
if decl not in src:
    sys.exit("touchesControlDirectory declaration not found in %s -- update this script" % sys.argv[1])
i = src.index(decl)
j = src.index("\n    }\n", i) + len("\n    }\n")
fn = src[i:j].replace("    static func", "func", 1)
fn = "\n".join(l[4:] if l.startswith("    ") else l for l in fn.split("\n"))
if "hasPrefix" not in fn:
    sys.exit("extracted body does not look like touchesControlDirectory -- update this script")


open(sys.argv[2], "w").write("import Foundation\n\n" + fn + r'''

let dir = "/Users/u/Library/Application Support/agentmon"
var failures = 0
func check(_ path: String, _ op: String, _ want: Bool, _ why: String) {
    let got = touchesControlDirectory(path: path, operation: op, controlDir: dir)
    if got == want {
        print("ok    \(why)")
    } else {
        print("FAIL  \(why): \(op) \(path) got \(got), want \(want)")
        failures += 1
    }
}

check(dir + "/policy.sock", "delete", true, "removing the policy socket is refused")
check(dir + "/policy.sock", "create", true, "binding a new policy socket is refused")
check(dir + "/config.yml", "write", true, "rewriting the daemon's configuration is refused")
check(dir, "rename", true, "moving the directory itself is refused")
check("/Users/u/Library/Application Support", "rename", true, "moving an ancestor is refused")
check("/Users/u/Library", "delete", true, "deleting an ancestor is refused")
check(dir + "/local-api.key", "read", true, "reading the local API key is refused")
check(dir + "/data/audit.jsonl", "read", true, "reading the daemon's audit data is refused")
check(dir + "-other/x", "write", false, "a sibling that shares the prefix is not the directory")
check("/Users/u/Library/Application Support/other", "write", false, "writing next to the directory is not refused")
check("/Users/u/Library", "create", false, "creating in an ancestor is not refused")
if touchesControlDirectory(path: "/x", operation: "write", controlDir: "") {
    print("FAIL  an unknown directory must not refuse everything")
    failures += 1
} else {
    print("ok    an unknown directory refuses nothing")
}

exit(failures == 0 ? 0 : 1)
''')
PY

swiftc -O -o "$WORK/guard" "$WORK/guard.swift"
"$WORK/guard"
