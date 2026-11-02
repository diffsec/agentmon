#!/usr/bin/env bash
# Run the shared policy parity table through the extension's matchers.
#
# internal/platform/darwin/policysock/testdata/policy_parity.json lists file,
# network, unix socket and signal cases with the decision that the Go engine
# gives. The Go half, the TestPolicyParity_Go* tests, checks the engine
# against it. This half checks
# SessionPolicyCache's matchers, extracted from the real source as
# test-swift-file-rules.sh does, so a decision that differs between Linux and
# macOS fails one of the two.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=macos/AgentMon/SessionPolicyCache.swift
TABLE=internal/platform/darwin/policysock/testdata/policy_parity.json
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

python3 - "$SRC" "$WORK/parity.swift" "$TABLE" <<'PY'
import sys

src = open(sys.argv[1]).read()

def between(start, end):
    if start not in src:
        sys.exit("not found in %s -- update this script: %s" % (sys.argv[1], start))
    i = src.index(start)
    return src[i:src.index(end, i) + len(end)]

file_rule = between("struct FileRule {", "\n}\n")
net_rule = between("struct NetworkRule {", "\n}\n")
unix_rule = between("struct UnixSocketRule {", "\n}\n")
sig_rule = between("struct SignalRule {", "\n}\n")
sig_target = between("struct SignalTarget {", "\n}\n")
socket_paths = between("    static func socketPathCandidates(", "\n    }\n")
first_unix = between("    static func firstMatchingUnixSocketRule(", "\n    }\n")
first_sig = between("    static func firstMatchingSignalRule(", "\n    }\n")
sig_match = between("    static func signalTargetMatches(", "\n    }\n")
first_file = between("    static func firstMatchingFileRule(", "\n    }\n")
network = between("    /// Whether a connection matches a network rule, as CheckNetworkIP decides",
                  "    static func firstMatchingNetworkRule(")
network += between("    static func firstMatchingNetworkRule(", "\n    }\n")[len("    static func firstMatchingNetworkRule("):]
cidr = between("    private func cidrMatch(pattern: String, ip: String) -> Bool {", "\n    }\n")
cidr = cidr.replace("    private func cidrMatch", "    func cidrMatch", 1)
glob = between("    /// Compiled regular expressions for ** patterns, by pattern.", "    private func globMatch(pattern: String, path: String) -> Bool {")
glob += between("    private func globMatch(pattern: String, path: String) -> Bool {", "\n    }\n")[len("    private func globMatch(pattern: String, path: String) -> Bool {"):]
glob = glob.replace("    private func globMatch(pattern: String, path: String) -> Bool {", "    func globMatch(pattern: String, path: String) -> Bool {", 1)

for needle, body in [("domainGlobRegex", network), ("inet_pton", cidr), ("fnmatch", glob), (".first", first_file),
                     (".first", first_unix), ("/private", socket_paths), ("signals.contains", first_sig),
                     ("pid_range", sig_match)]:
    if needle not in body:
        sys.exit("extracted code does not look right (%s) -- update this script" % needle)

cls = ("final class SessionPolicyCache {\n" + first_file + "\n" + network + "\n" + cidr + "\n" + glob + "\n"
       + socket_paths + "\n" + first_unix + "\n" + first_sig + "\n" + sig_match + "\n}\n")

open(sys.argv[2], "w").write("import Foundation\nimport os\n\n" + file_rule + "\n" + net_rule + "\n" + unix_rule + "\n" + sig_rule + "\n" + sig_target + "\n" + cls + r'''
let table = try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "''' + sys.argv[3] + r'''"))) as! [String: Any]
let cache = SessionPolicyCache()
var failures = 0

func fileRules(_ raw: [[String: Any]]) -> [FileRule] {
    raw.flatMap { r in
        (r["paths"] as! [String]).map {
            FileRule(pattern: $0, operations: Set(r["operations"] as? [String] ?? []), action: r["decision"] as! String)
        }
    }
}

func checkFiles(_ name: String, _ rules: [FileRule], _ cases: [[String: Any]]) {
    for c in cases {
        let path = c["path"] as! String, op = c["operation"] as! String, want = c["want"] as! String
        let got = SessionPolicyCache.firstMatchingFileRule(rules, path: path, operation: op, match: cache.globMatch)?.action
            ?? (SessionPolicyCache.isReadOperation(op) ? "allow" : "deny")
        if got == want {
            print("ok    \(name): \(op) \(path) = \(got)")
        } else {
            print("FAIL  \(name): \(op) \(path) = \(got), Go says \(want)")
            failures += 1
        }
    }
}

let allFileRules = table["file_rules"] as! [[String: Any]]
checkFiles("file", fileRules(allFileRules), table["file_cases"] as! [[String: Any]])
checkFiles("file, no catch-all", fileRules(Array(allFileRules.dropLast())), table["file_cases_no_catch_all"] as! [[String: Any]])

let netRules = (table["network_rules"] as! [[String: Any]]).map { r in
    NetworkRule(name: r["name"] as! String, domains: r["domains"] as? [String] ?? [],
                cidrs: r["cidrs"] as? [String] ?? [], ports: Set(r["ports"] as? [Int] ?? []),
                proto: nil, action: r["decision"] as! String)
}
for c in table["network_cases"] as! [[String: Any]] {
    let host = c["host"] as! String, ip = c["ip"] as! String, port = c["port"] as! Int, want = c["want"] as! String
    let got = SessionPolicyCache.firstMatchingNetworkRule(netRules) {
        SessionPolicyCache.networkRuleMatches($0, host: host.isEmpty ? nil : host, ip: ip, port: port,
                                              domainMatch: SessionPolicyCache.domainGlobMatch,
                                              cidrMatch: cache.cidrMatch)
    }?.action ?? "deny"
    if got == want {
        print("ok    network: \(host.isEmpty ? ip : host):\(port) = \(got)")
    } else {
        print("FAIL  network: \(host.isEmpty ? ip : host):\(port) = \(got), Go says \(want)")
        failures += 1
    }
}

let unixRules = (table["unix_socket_rules"] as! [[String: Any]]).flatMap { r in
    (r["paths"] as! [String]).map {
        UnixSocketRule(name: r["name"] as! String, pattern: $0,
                       operations: Set(r["operations"] as? [String] ?? []), action: r["decision"] as! String)
    }
}
func checkUnix(_ path: String, _ op: String, _ want: String, _ label: String) {
    let got = SessionPolicyCache.firstMatchingUnixSocketRule(
        unixRules, paths: SessionPolicyCache.socketPathCandidates(path), operation: op,
        match: cache.globMatch)?.action ?? "deny"
    if got == want {
        print("ok    \(label): \(op) \(path) = \(got)")
    } else {
        print("FAIL  \(label): \(op) \(path) = \(got), Go says \(want)")
        failures += 1
    }
}
for c in table["unix_socket_cases"] as! [[String: Any]] {
    let path = c["path"] as! String, op = c["operation"] as! String, want = c["want"] as! String
    checkUnix(path, op, want, "unix")
    // ES names the real path. A rule for /var/run or /tmp must match the
    // same socket under /private.
    if path.hasPrefix("/var/") || path.hasPrefix("/tmp/") {
        checkUnix("/private" + path, op, want, "unix, real path")
    }
}

let signalRules = (table["signal_rules"] as! [[String: Any]]).map { r -> SignalRule in
    let target = r["target"] as! [String: Any]
    return SignalRule(name: r["name"] as! String,
                      signals: Set((r["signals"] as! [String]).map { Int32($0)! }),
                      target: target["type"] as! String, pattern: target["pattern"] as? String ?? "",
                      min: target["min"] as? Int ?? 0, max: target["max"] as? Int ?? 0,
                      action: r["decision"] as! String)
}
for c in table["signal_cases"] as! [[String: Any]] {
    let flag = { (k: String) in c[k] as? Bool ?? false }
    let t = SignalTarget(sourcePID: pid_t(c["source_pid"] as! Int), targetPID: pid_t(c["target_pid"] as! Int),
                         targetCmd: c["target_cmd"] as? String ?? "", inSession: flag("in_session"),
                         sameUser: flag("same_user"), isChild: flag("is_child"),
                         isDescendant: flag("is_descendant"), isSibling: flag("is_sibling"),
                         isParent: flag("is_parent"))
    let sig = Int32(c["signal"] as! Int), want = c["want"] as! String
    let got = SessionPolicyCache.firstMatchingSignalRule(signalRules, signal: sig, target: t)?.action ?? "deny"
    let label = "signal \(sig) from \(t.sourcePID) to \(t.targetPID)"
    if got == want {
        print("ok    \(label) = \(got)")
    } else {
        print("FAIL  \(label) = \(got), Go says \(want)")
        failures += 1
    }
}

exit(failures == 0 ? 0 : 1)
''')
PY

swiftc -O -o "$WORK/parity" "$WORK/parity.swift"
"$WORK/parity"
