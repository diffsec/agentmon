# Claude Code Guidelines

Read and follow [AGENTS.md](./AGENTS.md) for cross-platform development rules.

## Project Structure

- `cmd/` - CLI entry points
- `internal/` - Private packages
- `pkg/` - Public packages
- `internal/platform/` - OS-specific implementations (darwin, linux)

## Build & Test

```bash
go build ./...                    # Build all
go test ./...                     # Test all
```

## Before Committing

1. Run tests: `go test ./...`
2. Check for hardcoded paths or OS-specific assumptions
