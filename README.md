# Agent SSH MCP

> MCP server for persistent SSH sessions with **tmux integration**, **port forwarding**, and **SFTP file writes** — built for AI agent workflows.

Based on [ssh-mcp-sessions](https://github.com/fryjustinc/ssh-mcp-sessions) by Justin Fry (MIT), with significant enhancements for agent reliability.

---

## What's improved over the original

The original [fryjustinc/ssh-mcp-sessions](https://github.com/fryjustinc/ssh-mcp-sessions) provides 8 basic tools that execute commands directly in a hidden ssh2 shell buffer. This repo is a significant rework:

### Architecture changes

| Original | This repo |
|----------|-----------|
| Commands run in a hidden ssh2 shell; output captured via in-memory buffer | Commands run inside a **tmux session** (`ai`); user can attach and watch live with `tmux attach -t ai` |
| Single end marker: `printf '__MCP_DONE__%s%d\n' $?` — no start marker, no polling | Dual start+end markers polled via `capture-pane`; output extracted between them |
| No reconnect logic — connection loss kills the session | Auto-reconnects on next command; keepalive every 30 s |
| No file transfer | **SFTP**: `upload-file`, `download-file`, `write-remote-file` |
| No port forwarding | `forward-port` / `stop-forward` via ssh2 `forwardOut` |

### New tools added

| Tool | Purpose |
|------|---------|
| `setup-tmux` | (Re)initialize tmux on an existing session |
| `upload-file` | Upload local file to remote via SFTP |
| `download-file` | Download remote file to local via SFTP |
| `write-remote-file` | Write text content directly via SFTP — no shell, no quoting issues, no heredoc |
| `forward-port` | Forward a local TCP port to a remote host:port |
| `stop-forward` | Stop a port forward tunnel |

### Reliability fixes

| Issue | Root cause | Fix |
|-------|-----------|-----|
| Captured output contained entire pane history | End marker regex required a preceding `\n`; commands without trailing newline caused marker detection to fail → 30 s timeout → full pane returned as fallback | Regex changed to `endMarker(\d+)(?:\n|$)` |
| Long sessions accumulated large scrollback, slowing polling | `capture-pane -S -1000` scanned 1000 lines on every poll | `tmux clear-history` before each command + window reduced to `-S -200` |
| heredoc (`<< EOF`) hung the session | tmux waits for EOF input that never arrives | Detected and rejected with a helpful error |
| exit code `-1` was indistinguishable from a real command failure | Timeout and true failure both returned the same code | Timeout now returns `[tmux capture timed out — command may still be running]` |

---

## Installation

```bash
npm install -g agent-ssh-mcp
```

Or run without installing:

```bash
npx agent-ssh-mcp
```

---

## MCP Client Configuration

Add to your MCP client config (Claude Desktop, Claude Code, Cursor, etc.):

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["agent-ssh-mcp"]
    }
  }
}
```

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

**Claude Code / VS Code** — `.vscode/settings.json`:
```json
{
  "claude.mcpServers": {
    "ssh": { "command": "npx", "args": ["agent-ssh-mcp"] }
  }
}
```

**Cursor** — `~/Library/Application Support/Cursor/mcp.json` (macOS)

---

## Host Configuration

Hosts are stored in `~/.ssh-mcp/hosts.json`, created automatically on first use.

### Add a host

```json
{
  "tool": "add-host",
  "host_id": "my-server",
  "host": "1.2.3.4",
  "port": 22,
  "username": "root",
  "password": "optional",
  "keyPath": "~/.ssh/id_rsa"
}
```

Authentication priority: password → private key → SSH agent (`SSH_AUTH_SOCK`).

---

## Tools Reference

### Session lifecycle

| Tool | Parameters | Description |
|------|-----------|-------------|
| `add-host` | `host_id`, `host`, `port`, `username`, `password?`, `keyPath?` | Save SSH host config |
| `list-hosts` | — | List all saved hosts |
| `edit-host` | `host_id` + any field to change | Update host config |
| `remove-host` | `host_id` | Delete host config |
| `start-session` | `host_id`, `sessionId?` | Connect and auto-initialize tmux |
| `list-sessions` | — | Show active sessions with uptime |
| `close-session` | `sessionId` | Disconnect and clean up |
| `setup-tmux` | `session_id` | (Re)initialize tmux on an existing session |

### Command execution

| Tool | Parameters | Description |
|------|-----------|-------------|
| `exec` | `session_id`, `command` | Run a command; auto-routes through tmux when available |

**Note:** Do not use `tmux send-keys` manually — `exec` handles tmux routing automatically.

**Avoid heredoc syntax** (`<< EOF`). Use `write-remote-file` instead.

### File transfer

| Tool | Parameters | Description |
|------|-----------|-------------|
| `upload-file` | `session_id`, `local_path`, `remote_path` | Upload local file via SFTP (**preferred for large/binary files**) |
| `download-file` | `session_id`, `remote_path`, `local_path` | Download remote file via SFTP |
| `write-remote-file` | `session_id`, `remote_path`, `content` | Write text content directly via SFTP — handles special characters, no shell quoting issues |

### Port forwarding

| Tool | Parameters | Description |
|------|-----------|-------------|
| `forward-port` | `session_id`, `local_port`, `remote_host`, `remote_port`, `tunnel_id?` | Forward `127.0.0.1:<local_port>` → `<remote_host>:<remote_port>` |
| `stop-forward` | `tunnel_id` | Stop a port forward tunnel |

Example — access a remote PostgreSQL locally:
```json
{
  "tool": "forward-port",
  "session_id": "my-session",
  "local_port": 15432,
  "remote_host": "127.0.0.1",
  "remote_port": 5432
}
```
Then connect to `postgresql://user:pass@127.0.0.1:15432/db`.

---

## Typical Agent Workflow

```
1. add-host       → save target server
2. start-session  → SSH connect + tmux init (returns session_id)
3. exec           → run commands (output is clean, no scrollback pollution)
4. write-remote-file / upload-file → write files reliably
5. forward-port   → expose remote services locally if needed
6. close-session  → clean up
```

Sessions auto-close after 2 hours of inactivity.

---

## tmux Observability

Every command is executed inside a tmux session named `ai`. You (or the user) can attach to watch in real time:

```bash
ssh root@<host>
tmux attach -t ai
```

---

## Building from Source

```bash
git clone https://github.com/xcdd/Agent-SSH-MCP
cd Agent-SSH-MCP
npm install
npm run build
```

Run tests:
```bash
npm test
```

---

## Security Notes

- `~/.ssh-mcp/hosts.json` may contain passwords — treat it as sensitive (`chmod 600`).
- Prefer key-based or SSH agent authentication.
- Sessions inherit all privileges of the SSH user.

---

## License

MIT — see [LICENSE](./LICENSE).

Original work © 2025 Justin Fry. Modifications © 2026 xcdd.
