#!/usr/bin/env bash
# Exercise SessionPolicyCache's file rule order against cases from
# configs/policies/default.yaml.
#
# The extension must decide file access the way Engine.CheckFile does in
# internal/policy/engine.go: the first rule that matches, in policy order. It
# used to check every deny rule first, so the catch-all default-deny-files rule
# denied every write in a session, /dev/null included.
#
# Like test-swift-cidr.sh, this extracts the real functions from the source
# rather than keeping a second copy, and fails loudly if the extraction finds
# nothing.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=macos/AgentMon/SessionPolicyCache.swift
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

python3 - "$SRC" "$WORK/rules.swift" <<'PY'
import sys

src = open(sys.argv[1]).read()

def extract(decl, end):
    if decl not in src:
        sys.exit("declaration not found in %s -- update this script: %s" % (sys.argv[1], decl))
    i = src.index(decl)
    j = src.index(end, i) + len(end)
    return src[i:j]

def dedent(fn):
    return "\n".join(l[4:] if l.startswith("    ") else l for l in fn.split("\n"))

rule = extract("struct FileRule {", "\n}\n")
first = dedent(extract("    static func firstMatchingFileRule(", "\n    }\n").replace("    static func", "    func", 1))
glob = dedent(extract("    private func globMatch(pattern: String, path: String) -> Bool {", "\n    }\n").replace("    private func", "    func", 1))

if ".first {" not in first or "fnmatch" not in glob:
    sys.exit("extracted bodies do not look like the rule matcher -- update this script")

open(sys.argv[2], "w").write("import Foundation\n\n" + rule + "\n" + first + "\n" + glob + r'''

// Rules in the order default.yaml lists them, cut down to what the cases use.
let rules: [FileRule] = [
    FileRule(pattern: "/Users/*/.ssh/**", operations: ["read", "write"], action: "deny"),
    FileRule(pattern: "/work/**", operations: ["write", "create"], action: "allow"),
    FileRule(pattern: "/work/**", operations: ["delete"], action: "approve"),
    FileRule(pattern: "/dev/null", operations: ["write", "create", "open"], action: "allow"),
    FileRule(pattern: "/tmp/**", operations: ["*"], action: "audit"),
    FileRule(pattern: "**", operations: ["write", "create", "delete"], action: "deny"),
]

var failures = 0
func check(_ path: String, _ op: String, _ want: String?, _ why: String) {
    let got = firstMatchingFileRule(rules, path: path, operation: op, match: globMatch)?.action
    if got == want {
        print("ok    \(why)")
    } else {
        print("FAIL  \(why): \(op) \(path) got \(got ?? "no rule"), want \(want ?? "no rule")")
        failures += 1
    }
}

check("/dev/null", "write", "allow", "an allow before the catch-all deny wins for /dev/null")
check("/work/a/b.txt", "write", "allow", "an allow before the catch-all deny wins for the workspace")
check("/work/a/b.txt", "delete", "approve", "the first matching rule decides, not the most severe")
check("/etc/passwd", "write", "deny", "the catch-all deny still applies when nothing earlier matches")
check("/Users/x/.ssh/id_ed25519", "read", "deny", "a deny before an allow still wins")
check("/tmp/x", "chmod", "audit", "the * operation matches any operation")
check("/etc/hosts", "read", nil, "no rule matches, so the caller applies the default")

exit(failures == 0 ? 0 : 1)
''')
PY

swiftc -O -o "$WORK/rules" "$WORK/rules.swift"
"$WORK/rules"
