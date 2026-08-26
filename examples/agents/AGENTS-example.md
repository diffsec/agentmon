# Command Execution via agentmon

**All shell commands in this project MUST be executed through agentmon.**

When using the Bash tool, wrap every command with `agentmon exec`:

## Required Syntax

```bash
agentmon exec SESSION_ID -- COMMAND [ARGS...]
```

The `--` separator is **required** between the session ID and the command.

## Examples

Instead of:
```bash
ls -la
npm install
go build ./...
```

Use:
```bash
agentmon exec my-session -- ls -la
agentmon exec my-session -- npm install
agentmon exec my-session -- go build ./...
```

## Using Environment Variables (Recommended)

When `AGENTMON_SESSION_ID` is set, pass all command arguments after `exec`:

```bash
export AGENTMON_SESSION_ID=my-session
agentmon exec -- ls -la
agentmon exec -- npm install
```

## Auto-Creating Sessions

Use `--root` to auto-create a session if it doesn't exist:

```bash
agentmon exec my-session --root /path/to/workspace -- ls -la
```

Or set the environment variable:

```bash
export AGENTMON_SESSION_ROOT=/path/to/workspace
agentmon exec my-session -- ls -la
```

## Common Flags

| Flag            | Description                          |
|-----------------|--------------------------------------|
| `--timeout 30s` | Command timeout (e.g., 30s, 5m)      |
| `--output json` | JSON structured output               |
| `--stream`      | Stream output as produced            |
| `--pty`         | Interactive PTY mode                 |

## Environment Variables

| Variable               | Description                                      |
|------------------------|--------------------------------------------------|
| `AGENTMON_SESSION_ID`   | Default session ID (avoids passing as argument)  |
| `AGENTMON_SESSION_ROOT` | Root directory for auto-creating sessions        |
| `AGENTMON_SERVER`       | Server URL (default: `http://127.0.0.1:18080`)    |
