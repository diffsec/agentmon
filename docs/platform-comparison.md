# Platform Comparison

agentmon supports **Linux** and **macOS**. Windows support was removed in full; if
you are looking for it, it is gone rather than unfinished.

Every score in this document comes from `agentmon detect`, which probes the
machine it runs on and scores five protection domains. It is the same code path
the product uses at runtime, so a number here can be reproduced by running the
command. Where a claim has not been measured, this document says so rather than
filling the cell in.

```
25  File Protection
25  Command Control
20  Network
15  Resource Limits
15  Isolation
```

Weights live in `internal/capabilities/detect_result.go`. A domain scores its
full weight if any backend in it is available, and zero otherwise — there is no
partial credit, because a mechanism that runs half the time is not half a
control.

## What actually enforces

| Domain | Linux | macOS (ESF + Network Extension) |
|---|---|---|
| File read/write/create/delete | FUSE3, Landlock, seccomp-notify | **Block** — ESF `AUTH_OPEN` / `AUTH_CREATE` / `AUTH_UNLINK` / `AUTH_RENAME` |
| Command execution | seccomp `execve`, ptrace | **Block** — ESF `AUTH_EXEC`, decided by the daemon |
| Network TCP/UDP | eBPF, Landlock network | **Block** — `NEFilterDataProvider`, per-flow |
| DNS | iptables redirect to the DNS proxy | **Not enforced** — see below |
| Resource limits | cgroups v2 | **Not enforced** — no implementation exists |
| Isolation | PID/mount/network namespaces, capability drop | Seatbelt (SBPL) via `agentmon-macwrap` |

macOS scores **85/100** with the system extension running and the content filter
installed: 25 file + 25 command + 20 network + 15 isolation. Resource limits are
0/15 and genuinely absent.

Linux's score is runtime-dependent — it reflects which kernel features the host
actually offers, and a restricted container scores lower than a root-privileged
host. Run `agentmon detect` rather than assuming a number. The backends it
probes are listed in `internal/capabilities/detect_linux.go`.

## macOS enforcement, measured

Verified on Apple Silicon hardware on 2026-08-27 with the system extension
activated, Full Disk Access granted, and the content filter enabled. Every line
is an observed result, under `agentmon wrap` with a session-scoped policy.

| Case | Result |
|---|---|
| allowed command | ran normally |
| denied command | `Killed: 9` — ESF `AUTH_EXEC` |
| allowed file read | contents returned |
| denied file read | `Operation not permitted` — ESF `AUTH_OPEN` |
| **same file read outside the session** | **succeeds** |
| allowed connection (`:443`) | `status=200` |
| denied connection (`:80`) | `Recv failure: Socket is not connected` |
| denied CIDR (`1.1.1.0/24`) | connection dropped |
| address just outside that CIDR | allowed |
| **same denied connection outside the session** | **succeeds** |

The two bolded rows are the point: enforcement is scoped to processes inside a
tracked agentmon session, not to the machine. That is also what makes the
fail-closed behaviour safe — when the daemon cannot answer, the sandboxed agent
is blocked, not the user's Mac.

## macOS: how each domain is decided

These differ, and the difference matters when debugging.

- **File** — ESF `AUTH_OPEN` → `SessionPolicyCache.evaluateFile`, decided
  **locally** from a policy snapshot the extension holds.
- **Network** — `NEFilterDataProvider.handleNewFlow` → `evaluateNetwork`, also
  decided **locally** from the snapshot.
- **Command** — ESF `AUTH_EXEC` → the extension asks the **daemon** over the
  policy socket (`exec_check` → `PolicyAdapter.CheckExec`).

Exec is the odd one out deliberately. Projecting `command_rules` into the
snapshot would mean re-implementing the policy engine in Swift, and it would be
lossy — no argument filtering, no `command_overrides`, no process contexts, no
ancestry, no `sh -c` collapsing. A local matcher that answers "allow" where the
engine says "deny" is a silent fail-open.

The verdict is delivered out of order, so the ES handler never blocks. A
synchronous wait would stall message delivery for the whole ES client, and one
slow answer would cascade into deadline kills — losing all enforcement rather
than one exec. A watchdog denies if no verdict arrives.

## Writing a macOS command policy

Two behaviours surprise people. Both are correct; neither is a bug.

**`/bin/sh` re-execs `/bin/bash`.** ESF reports a second `AUTH_EXEC` with
`path=/bin/bash` and the same argv. A policy that allows `sh` but not `bash`
therefore kills the shell. Allow both.

**`sh -c '<compound command>'` is denied** with rule `shellc-wrapper-bypass`.
The engine fails closed when it cannot collapse a shell-c form to a single
binary, because falling through to an allow-shell rule would leak the deny. This
is shared with Linux; it was simply unreachable on macOS until command
enforcement worked. Agents run `sh -c` constantly, so a policy for a wrapped
agent has to account for it.

## Known gaps

**DNS is not enforced on macOS, and the DNS proxy provider refuses to start.**
This is deliberate. Installing an `NEDNSProxyManager` configuration as the code
stands would break name resolution for the entire machine: the provider has no
upstream resolver, so an allowed query is answered with a copy of itself; the
policy snapshot carries no DNS rules, so every query takes that path; and a DNS
proxy is machine-wide, unlike the content filter, which is scoped to session
PIDs. Closing the gap needs an upstream resolver, DNS rules in the snapshot, and
PID scoping, in that order.

**No resource limits on macOS.** There is no cgroups equivalent and no launchd
limits implementation in the tree. `agentmon detect` reports 0/15 for this
domain rather than claiming Mach-based monitoring as enforcement — observing a
process's memory is not capping it.

**No process isolation on macOS beyond seatbelt.** There is no namespace
equivalent. The seatbelt profile compiled by `agentmon-macwrap` restricts
filesystem and exec reach; it is not a namespace.

**No signal blocking on macOS.** Endpoint Security can audit signals but not
block or redirect them.

**No runtime environment-variable interception on macOS.** `shim/darwin/envshim.c`
exists but is never built. Spawn-time filtering works.

**Xcode's `/usr/bin` shims do not work under seatbelt.** `git`, `python3`,
`clang` and `xcrun` resolve `/var/select/developer_dir`, then `dlopen` libraries
from `Xcode.app` and talk to system services. No reasonable profile permits
this. Homebrew equivalents work.

## Requirements

| | Linux | macOS |
|---|---|---|
| Privileges | root or `CAP_SYS_ADMIN` for namespaces | user approval of the system extension |
| Kernel/OS | 5.x+ for full eBPF | macOS 14.0+ |
| Extra | — | Full Disk Access for the extension; a content filter configuration |
| Architecture | amd64, arm64 | **arm64 only** — Apple Silicon |

Two macOS steps are easy to miss and both fail silently:

- **Full Disk Access** must be granted to the system extension, or `es_new_client`
  fails and the extension crash-loops. It is reset whenever the extension is
  reinstalled.
- **The content filter configuration** must exist and be enabled, or macOS never
  calls `startFilter` and network rules are unenforced. `agentmon activate-extension`
  installs it; `agentmon network-filter status` reports it.

## Installation

**There is no published release yet.** Build from source:

```bash
make build                       # Linux and macOS Go binaries
make build-macos-enterprise      # macOS app bundle, signed (needs SIGNING_IDENTITY)
```

macOS additionally requires notarization before the system extension will load,
because System Integrity Protection blocks the developer-mode alternative. See
the [macOS Build Guide](macos-build.md).

## macOS + Lima

Running agentmon inside a Lima VM gives Linux-native enforcement, because it *is*
Linux — the macOS platform code is not involved at all. This is a deployment
choice rather than a separate backend, and it costs VM overhead on file I/O
through virtiofs plus a few hundred MB of RAM.

`internal/platform/lima/` also supports an orchestrated mode, where agentmon runs
on macOS and uses Lima as an execution sandbox via `limactl shell`. It is **not**
selected automatically: `detectPlatformMode()` used to return the Lima backend
whenever any Lima VM was running, so a developer with Colima up for Docker
silently got a different enforcement backend. It must now be requested
explicitly in configuration.

Neither Lima mode has been measured against the enforcement suite above. Treat
the "identical to Linux" claim as a statement about architecture, not a test
result.

## Performance

No benchmarks in this repository measure interception overhead, so this document
no longer quotes any. Earlier revisions carried per-mechanism latency and
throughput tables that no test produced.

What can be said from the design: ESF and the Network Extension make their
decisions in kernel-adjacent code with no FUSE-style userspace round trip for
file reads, and the file and network paths on macOS answer from a cached policy
snapshot rather than consulting the daemon. Command execution does consult the
daemon, one unix-socket round trip per exec.

If overhead matters for your workload, measure it on your workload.

## See also

- [macOS Build Guide](macos-build.md)
- [macOS ESF+NE Architecture](macos-esf-ne-architecture.md)
