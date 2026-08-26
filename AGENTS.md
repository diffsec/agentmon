# Agent Guidelines

This project targets Linux and macOS. Windows support was removed; do not reintroduce
`//go:build windows` files, `GOOS=windows` build steps, or Windows-only abstractions.

## Paths

- Use `filepath.Join()` for all path construction
- Use `os.TempDir()` instead of hardcoded `/tmp`
- Use `filepath.Separator` if you need the separator character
- Never hardcode `/` or `\` as path separators

## OS-Specific Code

- Use build tags for platform-specific files: `//go:build linux`, `//go:build darwin`
- Check `runtime.GOOS` for runtime platform detection
- Skip platform-specific tests with `t.Skip()` when features aren't available

## Common Platform Differences

| Feature | Linux | macOS |
|---------|-------|-------|
| Unix sockets | Yes | Yes |
| PTY | /dev/ptmx | /dev/ptmx |
| Resource limits | cgroups | RLIMIT_* |
| Signals | Full POSIX | Full POSIX |
| $0 / argv[0] | Works | Works |

## Testing

- Use `t.TempDir()` for test directories (auto-cleaned)

## Environment Variables

- Use `os.Getenv()` / `os.Setenv()`
- Use `os.Environ()` to get the full environment as `KEY=value` slice
