#!/usr/bin/env bash
# Exercise SessionPolicyCache.cidrMatch against known-good CIDR cases.
#
# The Xcode project has no test target, and adding one to run a single pure
# function is more machinery than the function is worth. Instead this extracts
# cidrMatch from the real source and runs assertions against it, so there is no
# second copy that can drift from the one that ships.
#
# The extraction is textual and therefore brittle: it looks for the exact
# declaration line and the first closing brace at method indentation. If
# cidrMatch is renamed, reindented, or gains a nested type declared at the same
# level, this fails loudly rather than silently testing nothing -- the sanity
# check below is there to guarantee that.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=macos/AgentMon/SessionPolicyCache.swift
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

python3 - "$SRC" "$WORK/cidr.swift" <<'PY'
import sys

src = open(sys.argv[1]).read()
decl = "    private func cidrMatch(pattern: String, ip: String) -> Bool {"
if decl not in src:
    sys.exit("cidrMatch declaration not found in %s -- update this script" % sys.argv[1])
i = src.index(decl)
j = src.index("\n    }\n", i) + len("\n    }\n")
fn = src[i:j].replace("    private func", "func", 1)
fn = "\n".join(l[4:] if l.startswith("    ") else l for l in fn.split("\n"))

if "inet_pton" not in fn:
    sys.exit("extracted body does not look like cidrMatch -- update this script")

open(sys.argv[2], "w").write("import Foundation\n\n" + fn + r'''

var failures = 0
func check(_ pattern: String, _ ip: String, _ want: Bool, _ why: String) {
    let got = cidrMatch(pattern: pattern, ip: ip)
    if got != want {
        print("FAIL  \(pattern) vs \(ip): got \(got), want \(want)  -- \(why)")
        failures += 1
    } else {
        print("ok    \(pattern) vs \(ip) = \(got)  (\(why))")
    }
}

check("10.0.0.0/8", "10.1.2.3", true, "inside a v4 block")
check("10.0.0.0/8", "11.1.2.3", false, "outside a v4 block")
check("192.168.1.0/24", "192.168.1.255", true, "last address in a /24")
check("192.168.1.0/24", "192.168.2.1", false, "the next /24 over")
check("192.168.1.42/32", "192.168.1.42", true, "/32 exact host")
check("192.168.1.42/32", "192.168.1.43", false, "/32 neighbour")
check("0.0.0.0/0", "8.8.8.8", true, "/0 matches everything")
check("10.0.0.0/9", "10.127.255.255", true, "non-byte-aligned prefix, inside")
check("10.0.0.0/9", "10.128.0.0", false, "non-byte-aligned prefix, just outside")
check("2001:db8::/32", "2001:db8:1234::1", true, "inside a v6 block")
check("2001:db8::/32", "2001:db9::1", false, "outside a v6 block")
check("fe80::/10", "fe80::1", true, "v6 non-byte-aligned prefix")
check("fe80::/10", "fec0::1", false, "v6 non-byte-aligned, outside")
check("10.0.0.0/8", "2001:db8::1", false, "v6 address against a v4 rule")
check("2001:db8::/32", "10.1.2.3", false, "v4 address against a v6 rule")
check("10.0.0.0/33", "10.1.2.3", false, "prefix too long for v4 matches nothing")
check("10.0.0.0/-1", "10.1.2.3", false, "negative prefix matches nothing")
check("not-an-ip/8", "10.1.2.3", false, "unparseable address matches nothing")
check("10.0.0.0/abc", "10.1.2.3", false, "unparseable prefix matches nothing")
check("10.0.0.0", "10.0.0.0", false, "no slash is not a CIDR")

print(failures == 0 ? "\nALL PASS" : "\n\(failures) FAILURES")
exit(failures == 0 ? 0 : 1)
''')
PY

swift "$WORK/cidr.swift"
