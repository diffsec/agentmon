# agentmon Cross-Platform Notes

**Last updated:** April 2026

agentmon supports **Linux** and **macOS** natively. Linux provides the most complete feature set. macOS uses **ESF+NE** (90% security score, **Alpha**) for file, process, and network enforcement. The ESF+NE tier is functional end-to-end but should not be considered production-ready — expect rough edges and breaking changes.

**macOS ESF+NE entitlements:** agentmon ships with the required ESF and Network Extension entitlements. No separate Apple approval is needed to use the pre-built binary.

Windows is not supported; support was removed in full. Unix socket enforcement (seccomp user-notify) is Linux-only.

## Linux Security Levels

Linux security features vary significantly depending on kernel version, runtime environment, and available privileges. agentmon automatically detects available features and selects the best security mode.

### Environment Compatibility Matrix

| Environment | seccomp | eBPF | Landlock | FUSE | ptrace | Capabilities |
|-------------|---------|------|----------|------|--------|--------------|
| Native Linux (kernel 6.7+) | ✅ | ✅ | ✅ (ABI v4) | ✅ | ✅ | ✅ |
| Native Linux (kernel 5.13-6.6) | ✅ | ✅ | ✅ (ABI v1-3) | ✅ | ✅ | ✅ |
| Native Linux (kernel < 5.13) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Docker (privileged) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Docker (unprivileged) | ❌* | ❌ | ✅ | ❌† | ❌‡ | ✅ |
| Docker (--cap-add SYS_PTRACE) | ❌* | ❌ | ✅ | ❌† | ✅ | ✅ |
| Kubernetes (standard) | ❌* | ❌ | ✅ | ❌† | ❌‡ | ✅ |
| AWS Fargate | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Nested containers | ❌ | ❌ | ✅ | ❌ | ❌‡ | ✅ |
| gVisor/Firecracker | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

\* Requires seccomp user-notify support in container runtime
† Requires `/dev/fuse` device and `SYS_ADMIN` capability
‡ Requires `SYS_PTRACE` capability (add via `--cap-add SYS_PTRACE` or securityContext)

### Security Mode by Environment

Based on available features, agentmon selects one of four security modes:

| Mode | Score | Typical Environment | Key Protections |
|------|-------|---------------------|-----------------|
| `full` | 100% | Native Linux, privileged containers | seccomp syscall filtering, eBPF network, FUSE filesystem |
| `ptrace` | ~90% | AWS Fargate, containers with SYS_PTRACE | ptrace execve interception, shim policy enforcement |
| `landlock` | ~85% | Unprivileged containers with FUSE | Landlock kernel sandbox + FUSE fine-grained control |
| `landlock-only` | ~80% | Unprivileged containers, restricted runtimes | Landlock kernel sandbox, shim policy enforcement |
| `minimal` | ~50% | gVisor, Firecracker, highly restricted | Capability dropping, shim policy only |

### Feature Availability by Kernel Version

| Kernel | Landlock ABI | Network Control | Filesystem Control |
|--------|--------------|-----------------|-------------------|
| 6.10+ | v5 | TCP bind/connect | Full + IOCTL |
| 6.7+ | v4 | TCP bind/connect | Full |
| 6.2+ | v3 | None | Full + truncate |
| 5.19+ | v2 | None | Full + REFER |
| 5.13+ | v1 | None | Basic |
| < 5.13 | N/A | None (use eBPF) | None (use seccomp) |

### What You Lose Without seccomp

When seccomp is unavailable (nested containers, restricted runtimes):

| Feature | With seccomp | Without seccomp | Mitigation |
|---------|--------------|-----------------|------------|
| Signal interception | Kernel-level | ❌ | PID namespace + dropped CAP_KILL |
| Abstract Unix sockets | Blocked | ❌ | Path-based sockets blocked via Landlock |
| Syscall filtering | 400+ syscalls | ❌ | Landlock + capabilities cover most cases |
| Fine-grained execution | Per-syscall | ❌ | Landlock execute paths + shim |

### What You Lose Without eBPF

When eBPF is unavailable:

| Feature | With eBPF | Without eBPF | Mitigation |
|---------|-----------|--------------|------------|
| Network visibility | All traffic | ❌ | Proxy-based monitoring |
| Connection tracking | Kernel-level | ❌ | Landlock TCP (kernel 6.7+) |
| DNS inspection | Deep | Proxy-level | DNS proxy |

### What You Gain With ptrace

When seccomp user-notify is unavailable but `SYS_PTRACE` capability is present (e.g. AWS Fargate), ptrace mode provides kernel-level execve interception:

| Feature | Without ptrace | With ptrace | Notes |
|---------|----------------|-------------|-------|
| Execution control | Shim only | Kernel-level | Intercepts execve/execveat syscalls |
| Deny enforcement | Shim check | Syscall invalidation | Returns -EACCES before exec runs |
| Fork/clone tracking | No | Yes | Auto-attaches to child processes |
| Process tree depth | No | Yes | Tracks nesting for policy decisions |
| execveat support | No | Yes | Handles fd-based exec (AT_EMPTY_PATH) |

**Typical use case:** AWS Fargate tasks where seccomp user-notify and eBPF are unavailable, but `SYS_PTRACE` is granted via `linuxParameters.capabilities.add`.

### Detection and Fallback

agentmon performs capability detection at startup:

```
INFO  security capabilities detected
        seccomp_user_notify=false    # Not available in this container
        ebpf=false                   # No CAP_BPF
        landlock=true
        landlock_abi=4               # Kernel 6.7+
        landlock_network=true        # Can restrict TCP
        fuse=false                   # No /dev/fuse
        ptrace=true                  # SYS_PTRACE available
        capabilities=true            # Can drop caps

INFO  selected security mode
        mode=ptrace
        protection_score=90%
```

### Forcing Specific Modes

Override auto-detection in configuration:

```yaml
security:
  # Force a specific mode (fails if requirements not met when strict=true)
  mode: landlock-only
  strict: true

  # Or set a minimum acceptable mode
  mode: auto
  minimum_mode: landlock-only  # Fail if only minimal is available
```

See [Security Modes](security-modes.md) for detailed mode configuration.

## What works today

- **Linux (native):** primary supported platform with tiered security (full → landlock → landlock-only → minimal depending on environment). See [Linux Security Levels](#linux-security-levels) above.
- **macOS ESF+NE (Alpha):** Endpoint Security Framework + Network Extension. File, command and network policy enforce; DNS and resource limits do not. Apple Silicon only. Build and notarize from source -- there is no published release or Homebrew tap.
- **Windows:** not supported. Support was removed in full.
- **gRPC (optional):** if enabled, clients connect to `server.grpc.addr` (default `127.0.0.1:9090`). The CLI can prefer gRPC via `AGENTMON_TRANSPORT=grpc`.

## Feature availability (current implementation)

- **FUSE workspace view:** Linux (FUSE3). In containers requires `/dev/fuse` + `SYS_ADMIN`. macOS uses ESF for file monitoring; FUSE is hardcoded off there.
- **FUSE event emission:** File operation events (open, read, write, create, delete, rename) are emitted to the configured EventChannel for audit logging and monitoring.
- **Process sandboxing:** Linux (namespaces via unshare), macOS (seatbelt SBPL profiles compiled by `agentmon-macwrap`).
- **Network visibility + policy enforcement:** works via the per-session proxy (DNS/connect/HTTP events).
- **Transparent netns interception:** optional, Linux/root-only (requires privileges; proxy mode works without it).
- **cgroups v2 limits:** optional, Linux-only; disabled by default (requires a writable cgroup base path).
- **macOS resource monitoring:** native Mach API monitoring for memory, CPU, and thread count (monitoring only, no enforcement).
- **Process execution stats:** CPU user/system time and peak memory returned in exec results on Linux and macOS.
- **seccomp syscall filtering:** Linux-only via seccomp user-notify for unix socket enforcement.
- **ptrace execve interception:** Linux-only via PTRACE_SEIZE for execve/execveat enforcement in restricted containers (e.g. AWS Fargate with SYS_PTRACE).
- **XPC/Mach IPC control:** macOS-only via sandbox profiles with mach-lookup restrictions. See [macOS XPC Sandbox](macos-xpc-sandbox.md).
- **Full namespace isolation:** Linux and Lima VM via `unshare` (user, mount, PID, network namespaces).
- **eBPF network enforcement:** Linux-only, requires cgroups v2 and root/CAP_BPF.

## Quick start

### Linux

```bash
agentmon server
```

### macOS (ESF+NE — Alpha)

```bash
brew tap canyonroad/tap
brew install --cask agentmon
```

After installation, approve the system extension in **System Settings > General > Login Items & Extensions**.

**From source** (requires Xcode 15+):

```bash
make build-macos-enterprise
```

See [macOS Build Guide](macos-build.md) for detailed build instructions.

### macOS (Lima VM - Full Isolation)

For full Linux isolation on macOS, Lima VM provides two deployment modes:

#### Inside-VM Mode (Recommended - 100% Security Score)

Run agentmon and your AI agent harness **entirely inside** the Lima VM. This is identical to native Linux:

```bash
# Install Lima
brew install lima

# Create and start a VM
limactl start default

# Shell into the VM
limactl shell default

# Inside the VM - install and run agentmon as normal Linux
curl -fsSL https://get.agentmon.dev | bash
agentmon server
```

This gives you **full Linux-equivalent protection**:
- Full FUSE3 filesystem interception
- Full iptables network interception
- Full Linux namespace isolation (mount, network, PID, user)
- Full seccomp-bpf syscall filtering
- Full cgroups v2 resource limits

**This is the simplest approach** - no special Lima platform code needed. Just treat the VM as a Linux server.

**Trade-offs:**
- File I/O to macOS filesystem via virtiofs (15-30% overhead)
- VM uses ~200-500MB RAM
- Interact via SSH/shell into VM

#### Orchestrated Mode (85% Security Score)

Run agentmon on macOS, using Lima as a remote execution sandbox:

```bash
# Install Lima
brew install lima

# Create and start a VM
limactl start default

# agentmon on macOS automatically detects Lima and uses it
agentmon server  # Will use darwin-lima mode
```

**Automatic Detection:** When `limactl` is installed and at least one VM is running, agentmon automatically uses Lima mode which provides:
- Full Linux namespace isolation (mount, network, PID, user)
- seccomp-bpf syscall filtering
- cgroups v2 resource limits
- FUSE3 filesystem interception
- iptables network interception

**Trade-offs:**
- Additional latency from `limactl shell` IPC
- Path translation between macOS and Lima paths
- More complex architecture

**Manual Mode Selection:** You can force Lima mode in your config:

```yaml
platform:
  mode: darwin-lima  # or just "lima"
```

#### Lima Implementation Details (Both Modes)

Inside the VM, both modes use standard Linux primitives:

**Resource Limits (cgroups v2):**
- Cgroup path: `/sys/fs/cgroup/agentmon/<session-name>`
- Supported limits: CPU (quota/period), memory, process count, disk I/O (read/write bandwidth)
- Stats available: memory usage, CPU time, process count, disk I/O bytes

**Network Interception (iptables):**
- Custom chain: `AGENTMON` in the nat table
- TCP traffic redirected to proxy port (localhost excluded)
- DNS (UDP port 53) redirected to DNS proxy port

**Filesystem Mounting (bindfs):**
- Source directory mounted to mount point using bindfs (passthrough mount)
- Automatic bindfs installation if not present (`sudo apt install bindfs`)
- Unmount via `fusermount -u` with `sudo umount` fallback
- Mount tracking prevents duplicate mounts to same location

**Process Isolation (namespaces):**
- Full isolation: user, mount, UTS, IPC, network, and PID namespaces
- Partial isolation: mount, UTS, IPC, PID namespaces (when user namespace unavailable)
- Automatic detection of available isolation level
- Working directory support for sandboxed commands

### macOS (sandbox-exec - Process Sandboxing)

For all macOS deployments (ESF+NE or Lima), agentmon uses `sandbox-exec` with SBPL (Sandbox Profile Language) profiles to provide process-level file and network restrictions:

```bash
# sandbox-exec is used automatically when executing commands
# No additional installation required - it's a built-in macOS tool
```

**How It Works:**

When agentmon executes a command in a session, it wraps the command with `sandbox-exec -p '<SBPL profile>' <command>`. The SBPL profile is dynamically generated based on the session's workspace and configuration.

**Default Profile Behavior:**

| Component | Policy |
|-----------|--------|
| Default | Deny-all (`(deny default)`) |
| Process ops | Allow fork, exec, self-signal |
| System paths | Read-only access to `/usr/lib`, `/System/Library`, `/bin`, `/usr/bin`, etc. |
| Homebrew | Read-only access to `/opt/homebrew/bin`, `/opt/homebrew/Cellar` |
| Temp files | Full access to `/tmp`, `/private/tmp`, `/var/folders` |
| TTY/PTY | Full access for interactive terminal |
| Workspace | Full access (from session config) |
| Network | Denied by default, requires `network` capability |
| IPC | Mach messaging and POSIX IPC allowed |

**Enabling Network Access:**

```yaml
sandbox:
  capabilities:
    - network    # Adds (allow network*) to SBPL profile
```

**Adding Extra Paths:**

```yaml
sandbox:
  workspace: /path/to/workspace
  allowed_paths:
    - /home/user/.config/myapp    # Additional full access
    - /usr/local/share/data
```

**Limitations:**
- `sandbox-exec` is deprecated by Apple but functional on all macOS versions
- No resource limits (CPU, memory) - use Lima for that
- No syscall filtering (unlike Linux seccomp)
- Child processes inherit the sandbox (escape not possible via fork)
- No PID namespace isolation (sandboxed processes can see all system processes)

**Security Score:** Contributes to the "Minimal" process isolation tier on macOS.

**Implementation:** See `internal/platform/darwin/sandbox.go` for the SBPL profile generation logic.

### Docker (any host)

FUSE requires extra privileges inside containers:

```bash
docker run --rm -it \
  --cap-add SYS_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor=unconfined \
  -p 18080:18080 \
  -v "$(pwd)":/workspace \
  ghcr.io/diffsec/agentmon:latest
```

## Detecting Available Capabilities

Use `agentmon detect` to probe your environment and see what security features are available:

```bash
# Show capabilities in table format (default)
agentmon detect

# Output as JSON for scripting
agentmon detect --output json

# Output as YAML
agentmon detect --output yaml
```

### Generating Optimized Configuration

Use `agentmon detect config` to generate a configuration snippet optimized for your environment:

```bash
# Print to stdout
agentmon detect config

# Write to file
agentmon detect config --output security.yaml

# Redirect to file
agentmon detect config > my-config.yaml
```

The generated config includes only security-related sections (`security:`, `landlock:`, `capabilities:`) that you can merge into your main configuration file.

## Troubleshooting

- **FUSE mount fails (Linux):** ensure FUSE3 is installed (host/VM) and, in Docker, `/dev/fuse` is present and `SYS_ADMIN` is allowed.
- **No file events on macOS:** ensure the system extension is approved in System Settings > General > Login Items & Extensions.
- **bindfs mount fails (Lima):** ensure bindfs is installed in the VM (`sudo apt install bindfs`) and `/dev/fuse` is available.
- **System Extension not loading (macOS ESF+NE):** check System Settings > General > Login Items & Extensions. User must approve the System Extension.
- **XPC connection fails (macOS ESF+NE):** verify the System Extension is approved and running. Check Console.app for XPC errors.
- **ESF client initialization fails:** ensure the app is signed with valid ESF entitlement from Apple (requires approval).
- **Transparent network mode fails:** run as root / with NET_ADMIN capabilities; otherwise rely on proxy mode.
- **cgroups errors:** keep `sandbox.cgroups.enabled: false` unless you have a writable cgroup v2 base path configured.
- **gRPC connection fails:** confirm `server.grpc.enabled: true`, the address/port are reachable, and (if auth is enabled) send the API key via gRPC metadata `x-api-key`.
