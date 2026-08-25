# Linux Package Managers Design

**Status:** Implemented

## Overview

Add Linux packaging for deb (Debian/Ubuntu), rpm (Fedora/RHEL), and Arch Linux using nFPM for simplified cross-format builds. CI builds packages on release tags.

## Package Contents

**Binaries:**
- `/usr/bin/agentmon` - Main CLI
- `/usr/bin/agentmon-shell-shim` - Shell shim

**Configuration:**
- `/etc/agentmon/config.yaml` - Default config (noreplace on upgrade)

**Shell Completions:**
- `/usr/share/bash-completion/completions/agentmon`
- `/usr/share/zsh/site-functions/_agentmon`
- `/usr/share/fish/vendor_completions.d/agentmon.fish`

**Documentation:**
- `/usr/share/doc/agentmon/README.md`
- `/usr/share/doc/agentmon/LICENSE`

## Directory Structure

```
packaging/
├── nfpm.yaml              # Single config for all formats
├── config.yaml            # Default config file
└── completions/
    ├── agentmon.bash
    ├── agentmon.zsh
    └── agentmon.fish
```

## nFPM Configuration

Single `packaging/nfpm.yaml` generates deb, rpm, and archlinux packages.

Key features:
- Version from environment variable (set by CI)
- Config file marked as `config|noreplace`
- Supports amd64 and arm64 architectures

## Build Process

**Local:**
```bash
make package-deb
make package-rpm
make package-arch
make package-all
```

**CI (GitHub Actions):**
- Triggers on `v*` tags
- Matrix: amd64, arm64
- Builds all three formats
- Uploads to GitHub Releases with SHA256SUMS

## Files to Create

1. `packaging/nfpm.yaml` - nFPM config
2. `packaging/config.yaml` - Default configuration
3. `packaging/completions/agentmon.bash` - Bash completion
4. `packaging/completions/agentmon.zsh` - Zsh completion
5. `packaging/completions/agentmon.fish` - Fish completion
6. `.github/workflows/release.yml` - Release workflow
7. Update `Makefile` - Add package targets

## Decisions

- Use nFPM instead of native tools (simpler, single config)
- Config at `/etc/agentmon/` (matches existing code)
- No systemd service (shell shim auto-starts server)
- Build both via CI and locally
