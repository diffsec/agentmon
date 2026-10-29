#!/usr/bin/env bash
# Exercise SessionPolicyCache's file rule order against cases from
# configs/policies/default.yaml.
#
# The extension must decide file access the way Engine.CheckFile does in
# internal/policy/engine.go: the first rule that matches, in policy order. It
# used to check every deny rule first, so the catch-all default-deny-files rule
# denied every write in a session, /dev/null included.
#
# It also checks FileOperation in ESFClient.swift, which names the operation
# for each ES file event with the names that the Go engine uses.
#
# Like test-swift-cidr.sh, this extracts the real functions from the source
# rather than keeping a second copy, and fails loudly if the extraction finds
# nothing.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=macos/AgentMon/SessionPolicyCache.swift
ESF=macos/AgentMon/ESFClient.swift
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

python3 - "$SRC" "$WORK/rules.swift" "$ESF" <<'PY'
import sys

src = open(sys.argv[1]).read()
esf = open(sys.argv[3]).read()

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
# globMatch is an instance method that uses the static globRegex cache, so
# both are extracted as they ship and wrapped in a class of the same name.
cache_start = "    /// Compiled regular expressions for ** patterns, by pattern."
glob_decl = "    private func globMatch(pattern: String, path: String) -> Bool {"
if cache_start not in src or glob_decl not in src:
    sys.exit("glob cache or globMatch not found in %s -- update this script" % sys.argv[1])
gi = src.index(cache_start)
gj = src.index("\n    }\n", src.index(glob_decl)) + len("\n    }\n")
glob = ("final class SessionPolicyCache {\n" + src[gi:gj] + "}\n"
        + "let globMatch = SessionPolicyCache().globMatch\n")
glob = glob.replace("    private func globMatch", "    func globMatch", 1)

enum_decl = "enum FileOperation {"
if enum_decl not in esf:
    sys.exit("FileOperation not found in %s -- update this script" % sys.argv[3])
ei = esf.index(enum_decl)
fileop = esf[ei:esf.index("\n}\n", ei) + 3]

if ".first {" not in first or "fnmatch" not in glob:
    sys.exit("extracted bodies do not look like the rule matcher -- update this script")

open(sys.argv[2], "w").write("import Foundation\n\n" + rule + "\n" + first + "\n" + glob + "\n" + fileop + r'''

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

// A rule with no operations matches every operation, as matchOp does in Go.
let anyOp = [FileRule(pattern: "/secret/**", operations: [], action: "deny")]
for op in ["read", "write", "chmod", "rmdir"] {
    let got = firstMatchingFileRule(anyOp, path: "/secret/a", operation: op, match: globMatch)?.action
    if got == "deny" {
        print("ok    a rule with no operations matches \(op)")
    } else {
        print("FAIL  a rule with no operations does not match \(op)")
        failures += 1
    }
}

func expect(_ got: [String], _ want: [String], _ why: String) {
    if got == want {
        print("ok    \(why)")
    } else {
        print("FAIL  \(why): got \(got), want \(want)")
        failures += 1
    }
}

expect([FileOperation.forCreate(mode: S_IFDIR | 0o755)], ["mkdir"], "a new directory is mkdir")
expect([FileOperation.forCreate(mode: S_IFLNK | 0o755)], ["symlink"], "a new symbolic link is symlink")
expect([FileOperation.forCreate(mode: S_IFREG | 0o644)], ["create"], "a new file is create")
expect([FileOperation.forCreate(mode: 0o644)], ["create"], "a mode with no type bits is create")
expect([FileOperation.forUnlink(mode: S_IFDIR | 0o755)], ["rmdir"], "removing a directory is rmdir")
expect([FileOperation.forUnlink(mode: S_IFREG | 0o644)], ["delete"], "removing a file is delete")

func attrs(common: Int32 = 0, file: Int32 = 0) -> attrlist {
    var a = attrlist()
    a.commonattr = attrgroup_t(common)
    a.fileattr = attrgroup_t(file)
    return a
}
expect(FileOperation.forSetattrlist(attrs(common: ATTR_CMN_OWNERID)), ["chown"], "setattrlist of the owner is chown")
expect(FileOperation.forSetattrlist(attrs(common: ATTR_CMN_ACCESSMASK)), ["chmod"], "setattrlist of the mode is chmod")
expect(FileOperation.forSetattrlist(attrs(common: ATTR_CMN_FLAGS)), ["chmod"], "setattrlist of the flags is chmod")
expect(FileOperation.forSetattrlist(attrs(common: ATTR_CMN_MODTIME)), ["write"], "setattrlist of the times is write")
expect(FileOperation.forSetattrlist(attrs(common: ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_MODTIME)),
       ["chown", "chmod", "write"], "setattrlist of several attributes checks each operation")
expect(FileOperation.forSetattrlist(attrs(file: ATTR_FILE_DATALENGTH)), ["write"], "setattrlist of a file attribute is write")
expect(FileOperation.forSetattrlist(attrs()), ["write"], "an empty setattrlist is write")
expect([FileOperation.eventType(for: "mkdir"), FileOperation.eventType(for: "rmdir"),
        FileOperation.eventType(for: "chmod"), FileOperation.eventType(for: "truncate")],
       ["dir_create", "dir_delete", "file_chmod", "file_write"], "each operation has a daemon event type")

// The compiled pattern is reused, not rebuilt on every match.
let a = SessionPolicyCache.globRegex(for: "/work/**")
let b = SessionPolicyCache.globRegex(for: "/work/**")
if a == nil || a !== b {
    print("FAIL  a ** pattern is compiled again on each call")
    failures += 1
} else {
    print("ok    a ** pattern is compiled once and reused")
}

exit(failures == 0 ? 0 : 1)
''')
PY

swiftc -O -o "$WORK/rules" "$WORK/rules.swift"
"$WORK/rules"
