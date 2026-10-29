# macOS enforcement gaps: phased plan

Date: 2026-10-29. Baseline: `main` after diffsec/agentmon#70, extension build 1669.

This plan closes the gaps that the macOS coverage review found. Each phase ships as one or more PRs, each with a Linear issue in SECENG, project AgentMon.

## Evidence

The review used three sources: the code, live tests on build 1669 in an `agent-default` session, and the Endpoint Security headers in the macOS 27 SDK.

Confirmed live:

- `clonefile()` on `~/.ssh/known_hosts` succeeded, and the clone in the workspace was readable. `cat` and `cp -c` on the same file were refused, because they open it first.
- `truncate()` and `chmod()` on a file outside the workspace succeeded. A direct write to the same directory was refused.

Confirmed in code:

- The snapshot version is always 1 (`internal/platform/darwin/policysock/handler.go:350`). `updateSession` drops a snapshot whose version is not newer (`macos/AgentMon/SessionPolicyCache.swift:560`), so a policy reload never reaches the extension.
- `evaluateNetwork` checks every deny rule before any allow rule (`SessionPolicyCache.swift:430`). Go uses the first matching rule.
- The snapshot sets the file, network and DNS defaults to allow (`handler.go:314`). The Go engine denies an unmatched network connection and an unmatched write.
- Nothing calls `SetPNACLHandler`, so each `pnacl_check` returns allow.
- The snapshot carries network rules for domains and CIDRs only. A rule with ports and no domain or CIDR is dropped.
- The extension handles `approve` and `redirect` file and network decisions as deny.

## Decisions

The decisions below were agreed on 2026-10-29.

1. Network clients. Every client must keep working, including clients that ignore `HTTPS_PROXY`, such as `ssh`, UDP and QUIC clients, and some CFNetwork apps. A rule that refuses direct flows is therefore not acceptable. Instead, the system extension adds a `NETransparentProxyProvider`. It captures each TCP and UDP flow from a session process and sends it to a gateway in the daemon. The gateway runs the same policy check, events and redirect logic as the Linux transparent gateway (`internal/netmonitor/transparent_tcp.go:99`). The extension sends the original destination and the audit token in a short header, because macOS has no `SO_ORIGINAL_DST`. The Linux gateway splices bytes without content inspection, so DLP on macOS stays limited to clients that use the HTTP proxy, which is the same as on Linux.
2. `approve` on file and network operations. An ES AUTH event has a deadline of a few seconds, which is too short for a person. The extension denies the operation, the daemon opens the approval dialog, and on approval the daemon adds a time-limited allow to the session cache. The allow lasts 60 seconds and covers only the exact path or host. The agent retries and succeeds. `approve` on exec works the same way. If approvals are not configured, `approve` acts as deny, as it does in Go.
3. Docker in `agent-default`. The container runtime runs outside the session, so a container escapes every rule. `docker` and the Docker socket move out of `agent-default` into a separate opt-in policy, `agent-docker`.
4. macOS 27 features. `AUTH_XPC_CONNECT` and `AUTH_BOOTSTRAP_LOOK_UP` exist only from macOS 27.0, and the app supports 15.6. The extension uses them on 27. Older systems use the exec-deny fallback in phase 4.

## Phase 1: close the file-access bypasses

Goal: no file call changes or reads a file that the policy protects.

- Subscribe to `AUTH_TRUNCATE`, `AUTH_SETMODE`, `AUTH_SETOWNER`, `AUTH_SETFLAGS`, `AUTH_SETACL`, `AUTH_SETEXTATTR`, `AUTH_DELETEEXTATTR`, `AUTH_SETATTRLIST`, `AUTH_UTIMES` and `AUTH_EXCHANGEDATA`. Map them to the policy operations `write`, `chmod` and `chown`.
- Check `AUTH_CLONE`, `AUTH_COPYFILE` and `AUTH_LINK` against the session policy: `read` on the source, `create` on the target. Today they check only the daemon's directory.
- Pass `mkdir` and `rmdir` to the cache as their own operations. Today they arrive as `create` and `delete`, so a rule that names only `mkdir` or `rmdir` never matches.
- Make a rule with no `operations` match every operation, as Go does (`internal/policy/engine.go:1258`).
- Add the live repro (`clonefile`, `truncate`, `chmod`) to a hardware test script that runs before each release.
- Measure the cost with the 1000-process benchmark. The new events fire only for session processes, because the extension subscribes only while a session exists (diffsec/agentmon#64).

Size: one PR. Swift tests in `scripts/test-swift-file-rules.sh`.

## Phase 2: match the Go policy engine

Goal: a policy gives the same decision on macOS and Linux.

- Add the transparent proxy from decision 1. The provider captures flows from session processes only, and returns `false` from `handleNewFlow` for every other flow. The daemon's own flows stay exempt by audit token (diffsec/agentmon#59). The daemon gateway reuses the handler in `transparent_tcp.go` with the destination from the header in place of `originalDst`. UDP needs a datagram path in the gateway, because the Linux gateway handles TCP only.
- Make `evaluateNetwork` use the first matching rule, as diffsec/agentmon#61 did for files. With the transparent proxy in place, the content filter decides only flows that the proxy does not capture.
- Send the policy's real defaults in the snapshot.
- Send rules that have ports but no domain or CIDR. Match a rule that has both domains and CIDRs only when both match.
- Replace the fixed snapshot version with a counter for each session, and push a new snapshot when a policy reloads.
- Install the PNACL handler, or remove `pnacl_check` and decide unknown flows in the cache.
- Implement decision 2 for `approve`. Report `redirect` on file and network as unsupported in `agentmon policy validate` on macOS.
- Add a shared test table that runs the same cases through the Go engine and the Swift cache.

Size: three PRs. The transparent proxy and first-match rules come first, then the defaults, versions and PNACL, then approvals. Each PR needs a live test on hardware, because the provider needs a new `NETransparentProxyManager` configuration and the `app-proxy-provider-systemextension` entitlement value.

## Phase 3: enforce the missing rule types

- `unix_socket_rules`: check `AUTH_UIPC_CONNECT` and `AUTH_UIPC_BIND` against the session policy. Today they guard only the daemon's directory.
- `signal_rules`: check `AUTH_SIGNAL` against the session policy. Today it guards only the daemon. Fix `docs/platform-comparison.md`, which says that ES cannot block signals.
- Process access: deny `AUTH_GET_TASK`, `AUTH_GET_TASK_READ` and `AUTH_PROC_SUSPEND_RESUME` from a session process to a process outside the session.
- `package_rules`: run the package check in the ESF exec path, so that `agentmon wrap` checks package installs too.
- `resource_limits`: set `RLIMIT_NOFILE`, `RLIMIT_CPU` and `RLIMIT_FSIZE` on the session root in `agentmon-macwrap`. These limits apply to each process, not to the session as a whole. `RLIMIT_NPROC` is not used, because macOS counts every process of the user against it. A process-count limit for the session comes from the extension instead: deny `AUTH_EXEC` when the session holds more than `max_pids` processes. This stops new programs but not a plain `fork()`, because ES has no AUTH event for fork. Memory, disk and network limits stay unsupported. `agentmon policy validate` must say so.
- `env_policy`: apply `max_*` and `block_iteration` at the start of the session under `wrap`.
- DNS rules: a research spike. `NEDNSProxyProvider` flows carry `sourceAppAuditToken`, so DNS queries can be matched to a session. Ship only if the spike shows that the token names the session process, not `mDNSResponder`.

Size: one PR each for sockets and signals, process access, package checks, and limits. The DNS spike is separate.

## Phase 4: close the escape routes

Goal: a session process cannot start work outside the session.

- Track the responsible process. A process whose `responsible_audit_token` (ES message version 4 or later) belongs to a session joins that session. This covers apps that LaunchServices starts on behalf of a session process.
- On macOS 27: deny `AUTH_XPC_CONNECT` and `AUTH_BOOTSTRAP_LOOK_UP` from session processes to the launchd job-submission, LaunchServices and Apple Events services. The allowlist of service names comes from a test of `open`, `osascript`, `launchctl submit` and `SMJobSubmit` called from Python.
- Before macOS 27: deny the exec of `open`, `osascript`, `launchctl` and `at` in the shipped agent policies, and treat any process that launchd starts as outside the session. Document that an in-process API call can still reach launchd on these versions.
- Implement decision 3 (Docker).
- Write a regression script that tries every route above from a session and expects each one to fail.

Size: two PRs, the responsible-process tracking first.

## Phase 5: documentation and release gates

- Rewrite the macOS column of `docs/platform-comparison.md` from the results of phases 1 to 4.
- Add a "macOS limits" section to the README that lists what stays unenforced, with the reason.
- Run the hardware regression scripts from phases 1 and 4 in the release checklist.

## Order and dependencies

Phase 1 has no dependencies and closes the confirmed bypasses, so it goes first. Phase 2 does not depend on phase 1, but it shares the extension build and the hardware tests, so it follows phase 1. Phases 3 and 4 can run in parallel after phase 1. Phase 5 runs last.
