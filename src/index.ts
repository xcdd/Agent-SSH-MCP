#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import type { ClientChannel, ConnectConfig, SFTPWrapper } from 'ssh2';
import SSH2Module from 'ssh2';
const { Client: SSHClient, utils: sshUtils } = SSH2Module as typeof import('ssh2');
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { readFile, writeFile, mkdir, stat } from 'fs/promises';
import { createReadStream, createWriteStream, mkdirSync } from 'fs';
import { resolve as resolvePath, dirname } from 'path';
import os from 'os';
import net from 'net';
import { randomUUID } from 'crypto';

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function expandPath(input: string | undefined): string | undefined {
  if (!input) return input;
  if (input === '~') return os.homedir();
  if (input.startsWith('~/')) return resolvePath(os.homedir(), input.slice(2));
  if (input.startsWith('~')) return resolvePath(os.homedir(), input.slice(1));
  return resolvePath(input);
}

const DEFAULT_TIMEOUT = 2 * 60 * 60 * 1000; // 2 hours default timeout
const CONNECT_TIMEOUT = 30 * 1000; // 30 seconds connection timeout

const HOSTS_DIR = resolvePath(os.homedir(), '.ssh-mcp');
const HOSTS_FILE = resolvePath(HOSTS_DIR, 'hosts.json');

type StoredHost = {
  id: string;
  host: string;
  port: number;
  username: string;
  password?: string;
  keyPath?: string;
};

const HostsSchema = z.object({
  hosts: z.array(z.object({
    id: z.string(),
    host: z.string(),
    port: z.number().int().positive().default(22),
    username: z.string(),
    password: z.string().optional(),
    keyPath: z.string().optional(),
  })).default([]),
});

async function ensureHostsFile(): Promise<void> {
  await mkdir(HOSTS_DIR, { recursive: true });
  try {
    const stats = await stat(HOSTS_FILE);
    if (!stats.isFile()) {
      throw new McpError(ErrorCode.InternalError, `${HOSTS_FILE} exists but is not a file`);
    }
  } catch (err: any) {
    if (err?.code === 'ENOENT') {
      await writeFile(HOSTS_FILE, JSON.stringify({ hosts: [] }, null, 2), 'utf8');
    } else if (err?.code !== 'EISDIR') {
      throw err;
    } else {
      throw new McpError(ErrorCode.InternalError, `${HOSTS_FILE} is a directory`);
    }
  }
}

async function readHosts(): Promise<StoredHost[]> {
  await ensureHostsFile();
  const raw = await readFile(HOSTS_FILE, 'utf8');
  const parsed = HostsSchema.safeParse(JSON.parse(raw || '{}'));
  if (!parsed.success) {
    throw new McpError(ErrorCode.InternalError, `Failed to parse hosts.json: ${parsed.error.message}`);
  }
  return parsed.data.hosts;
}

async function writeHosts(hosts: StoredHost[]): Promise<void> {
  await ensureHostsFile();
  await writeFile(HOSTS_FILE, JSON.stringify({ hosts }, null, 2), 'utf8');
}

async function getHostConfig(hostId: string): Promise<ConnectConfig> {
  const hosts = await readHosts();
  const host = hosts.find((h) => h.id === hostId);
  if (!host) {
    throw new McpError(ErrorCode.InvalidParams, `Host '${hostId}' not found`);
  }

  const config: ConnectConfig = {
    host: host.host,
    port: host.port ?? 22,
    username: host.username,
  };

  if (host.password) {
    config.password = host.password;
  } else if (host.keyPath) {
    const expanded = expandPath(host.keyPath);
    if (!expanded) {
      throw new McpError(ErrorCode.InvalidParams, `Invalid key path for host '${hostId}'`);
    }
    const keyContent = await readFile(expanded, 'utf8');
    config.privateKey = keyContent;
  } else {
    // Fallback to SSH agent if available
    if (process.env.SSH_AUTH_SOCK) {
      config.agent = process.env.SSH_AUTH_SOCK;
      config.agentForward = true;
    }
  }

  return config;
}

// Command sanitization and validation
export function sanitizeCommand(command: string): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }
  
  const trimmedCommand = command.trim();
  if (!trimmedCommand) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }
  
  // Length check
  if (trimmedCommand.length > 15000) {
    throw new McpError(ErrorCode.InvalidParams, 'Command is too long (max 1000 characters)');
  }
  
  return trimmedCommand;
}

// Escape command for use in shell contexts (like pkill)
export function escapeCommandForShell(command: string): string {
  // Replace single quotes with escaped single quotes
  return command.replace(/'/g, "'\"'\"'");
}

const activeSessions = new Map<string, PersistentSession>();
const activeTunnels = new Map<string, { server: net.Server; localPort: number; remoteHost: string; remotePort: number; sessionId: string }>();
const DEFAULT_SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '1.0.9',
  capabilities: {
    resources: {},
    tools: {},
  },
});

server.tool(
  "add-host",
  "Persist a new SSH host configuration.",
  {
    host_id: z.string().describe("Unique identifier for the host. we recommend user@hostname"),
    host: z.string().describe("Hostname or IP address"),
    port: z.number().int().positive().default(22).describe("SSH port (default 22)"),
    username: z.string().describe("SSH username"),
    password: z.string().optional().describe("Password for authentication"),
    keyPath: z.string().optional().describe("Path to private key (defaults to SSH agent if omitted)"),
  },
  async ({ host_id, host, port, username, password, keyPath }) => {
    const hosts = await readHosts();
    if (hosts.some((h) => h.id === host_id)) {
      throw new McpError(ErrorCode.InvalidParams, `Host '${host_id}' already exists`);
    }
    hosts.push({
      id: host_id,
      host,
      port,
      username,
      password,
      keyPath,
    });
    await writeHosts(hosts);
    return { content: [{ type: 'text', text: `Host '${host_id}' added` }] };
  }
);

server.tool(
  "list-hosts",
  "List all stored SSH host configurations.",
  {},
  async () => {
    const hosts = await readHosts();
    if (hosts.length === 0) {
      return { content: [{ type: 'text', text: 'No hosts configured' }] };
    }
    const lines = hosts.map((host) =>
      `id=${host.id} host=${host.host}:${host.port} user=${host.username} auth=${host.password ? 'password' : host.keyPath ? 'key' : 'agent'}`
    );
    return { content: [{ type: 'text', text: lines.join('\n') }] };
  }
);

server.tool(
  "remove-host",
  "Remove a stored SSH host configuration.",
  {
    host_id: z.string().describe("Identifier of the host to remove"),
  },
  async ({ host_id }) => {
    const hosts = await readHosts();
    const next = hosts.filter((host) => host.id !== host_id);
    if (next.length === hosts.length) {
      throw new McpError(ErrorCode.InvalidParams, `Host '${host_id}' does not exist`);
    }
    await writeHosts(next);
    return { content: [{ type: 'text', text: `Host '${host_id}' removed` }] };
  }
);

server.tool(
  "edit-host",
  "Edit fields of an existing host configuration.",
  {
    host_id: z.string().describe("Identifier of the host to edit"),
    host: z.string().optional(),
    port: z.number().int().positive().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    keyPath: z.string().optional(),
  },
  async ({ host_id, host, port, username, password, keyPath }) => {
    const hosts = await readHosts();
    const target = hosts.find((h) => h.id === host_id);
    if (!target) {
      throw new McpError(ErrorCode.InvalidParams, `Host '${host_id}' does not exist`);
    }
    if (host) target.host = host;
    if (port) target.port = port;
    if (username) target.username = username;
    if (password !== undefined) target.password = password;
    if (keyPath !== undefined) target.keyPath = keyPath;
    await writeHosts(hosts);
    return { content: [{ type: 'text', text: `Host '${host_id}' updated` }] };
  }
);

server.tool(
  "start-session",
  "Start a new SSH session for a stored host. Automatically initializes tmux if available (user can attach with 'tmux attach -t ai'). Falls back to direct shell if tmux is not installed. IMPORTANT: Commands that install tmux itself should be executed BEFORE calling start-session, or use setup-tmux after installation. When tmux is active, the exec tool automatically routes commands through tmux — just pass the actual command, do NOT manually write 'tmux send-keys'.",
  {
    host_id: z.string().describe("Identifier of the host to connect"),
    sessionId: z.string().optional().describe("Optional session identifier; generated if omitted"),
  },
  async ({ host_id, sessionId }) => {
    const hostConfig = await getHostConfig(host_id);
    const id = sessionId && sessionId.trim() ? sessionId.trim() : randomUUID();
    if (activeSessions.has(id)) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${id}' already exists`);
    }
    let session: PersistentSession;
    try {
      session = await getOrCreateSession(id, hostConfig, true);
    } catch (err: any) {
      // Connection failed — remove the zombie session from activeSessions
      const zombie = activeSessions.get(id);
      if (zombie) {
        zombie.dispose();
        activeSessions.delete(id);
      }
      throw new McpError(ErrorCode.InternalError, `Failed to connect to '${host_id}': ${err?.message ?? err}`);
    }
    // Initialize tmux after connection is established (separate from ensureConnected for reliability)
    try {
      await session.initTmux();
    } catch (err) {
      console.error(`start-session: tmux init failed for ${id}:`, err);
    }
    const info = session.getInfo();
    const tmuxStatus = info.tmuxReady ? 'tmux ready (attach: tmux attach -t ai)' : 'tmux not available (direct shell mode)';
    return { content: [{ type: 'text', text: `${id}\n${tmuxStatus}` }] };
  }
);

server.tool(
  "exec",
  "Execute a shell command on an existing SSH session. When tmux is active, commands are automatically sent via tmux (non-blocking, user can observe with 'tmux attach -t ai'). IMPORTANT: Just pass the actual command to execute — do NOT manually write 'tmux send-keys' or 'tmux capture-pane', the plugin handles tmux routing automatically. If tmux session is lost, automatically falls back to direct shell mode.",
  {
    session_id: z.string().describe("Identifier of the session to use"),
    command: z.string().describe("Command to execute"),
  },
  async ({ session_id, command }) => {
    const sanitizedCommand = sanitizeCommand(command);
    const session = activeSessions.get(session_id);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${session_id}' does not exist`);
    }
    const { output, exitCode } = await session.execute(sanitizedCommand);
    let resultText: string;
    if (exitCode === -1) {
      resultText = `[tmux capture timed out — command may still be running. Partial output:]\n${output}`;
    } else if (exitCode !== 0) {
      resultText = `Exit code: ${exitCode}\n${output}`;
    } else {
      resultText = output;
    }
    return {
      content: [{ type: 'text', text: resultText }],
    };
  }
);

server.tool(
  "close-session",
  "Close an existing persistent SSH session.",
  {
    sessionId: z.string().describe("Identifier of the session to close"),
  },
  async ({ sessionId }) => {
    const session = activeSessions.get(sessionId);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${sessionId}' does not exist`);
    }
    session.dispose();
    activeSessions.delete(sessionId);
    return { content: [{ type: 'text', text: `Session '${sessionId}' closed` }] };
  }
);

server.tool(
  "upload-file",
  "Upload a local file to the remote server via SFTP. PREFERRED method for writing files — more reliable than echo/cat/heredoc commands, handles binary content and special characters correctly.",
  {
    session_id: z.string().describe("Identifier of the session to use"),
    local_path: z.string().describe("Absolute path of the local file to upload"),
    remote_path: z.string().describe("Absolute path on the remote server where the file will be placed"),
  },
  async ({ session_id, local_path, remote_path }) => {
    const session = activeSessions.get(session_id);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${session_id}' does not exist`);
    }
    const expandedLocal = expandPath(local_path);
    if (!expandedLocal) {
      throw new McpError(ErrorCode.InvalidParams, `Invalid local path: ${local_path}`);
    }
    const result = await session.uploadFile(expandedLocal, remote_path);
    return { content: [{ type: 'text', text: result }] };
  }
);

server.tool(
  "download-file",
  "Download a file from the remote server via SFTP.",
  {
    session_id: z.string().describe("Identifier of the session to use"),
    remote_path: z.string().describe("Absolute path of the remote file to download"),
    local_path: z.string().describe("Absolute path on the local machine where the file will be saved"),
  },
  async ({ session_id, remote_path, local_path }) => {
    const session = activeSessions.get(session_id);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${session_id}' does not exist`);
    }
    const expandedLocal = expandPath(local_path);
    if (!expandedLocal) {
      throw new McpError(ErrorCode.InvalidParams, `Invalid local path: ${local_path}`);
    }
    const result = await session.downloadFile(remote_path, expandedLocal);
    return { content: [{ type: 'text', text: result }] };
  }
);

server.tool(
  "write-remote-file",
  "Write text content directly to a file on the remote server via SFTP. Preferred over echo/cat/heredoc for writing files — reliable, handles special characters, no shell quoting issues.",
  {
    session_id: z.string().describe("Identifier of the session to use"),
    remote_path: z.string().describe("Absolute path on the remote server to write"),
    content: z.string().describe("Text content to write to the file"),
  },
  async ({ session_id, remote_path, content }) => {
    const session = activeSessions.get(session_id);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${session_id}' does not exist`);
    }
    const result = await session.writeRemoteFile(remote_path, content);
    return { content: [{ type: 'text', text: result }] };
  }
);

server.tool(
  "setup-tmux",
  "Initialize tmux session on an existing SSH session. Use this after installing tmux on the remote server to switch from direct shell mode to tmux mode. When tmux is active, user can 'tmux attach -t ai' to observe commands in real-time.",
  {
    session_id: z.string().describe("Identifier of the session to initialize tmux on"),
  },
  async ({ session_id }) => {
    const session = activeSessions.get(session_id);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${session_id}' does not exist`);
    }
    const result = await session.setupTmux();
    return { content: [{ type: 'text', text: result }] };
  }
);

server.tool(
  "forward-port",
  "Create a local TCP port forward through the SSH session. Useful for accessing remote services (e.g. databases) locally. After calling this, connect to 127.0.0.1:<local_port> as if it were <remote_host>:<remote_port> on the server.",
  {
    session_id: z.string().describe("Identifier of the SSH session to use"),
    local_port: z.number().int().positive().describe("Local port to listen on (e.g. 15432)"),
    remote_host: z.string().default("127.0.0.1").describe("Remote host to forward to (default: 127.0.0.1)"),
    remote_port: z.number().int().positive().describe("Remote port to forward to (e.g. 5432)"),
    tunnel_id: z.string().optional().describe("Optional identifier for the tunnel; generated if omitted"),
  },
  async ({ session_id, local_port, remote_host, remote_port, tunnel_id }) => {
    const session = activeSessions.get(session_id);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${session_id}' does not exist`);
    }
    const id = tunnel_id?.trim() || randomUUID();
    if (activeTunnels.has(id)) {
      throw new McpError(ErrorCode.InvalidParams, `Tunnel '${id}' already exists`);
    }
    const tcpServer = await session.forwardPort(local_port, remote_host, remote_port);
    activeTunnels.set(id, { server: tcpServer, localPort: local_port, remoteHost: remote_host, remotePort: remote_port, sessionId: session_id });
    return { content: [{ type: 'text', text: `Tunnel '${id}' active: 127.0.0.1:${local_port} -> ${remote_host}:${remote_port}` }] };
  }
);

server.tool(
  "stop-forward",
  "Stop a port forward tunnel created by forward-port.",
  {
    tunnel_id: z.string().describe("Identifier of the tunnel to stop"),
  },
  async ({ tunnel_id }) => {
    const tunnel = activeTunnels.get(tunnel_id);
    if (!tunnel) {
      throw new McpError(ErrorCode.InvalidParams, `Tunnel '${tunnel_id}' does not exist`);
    }
    await new Promise<void>((resolve) => tunnel.server.close(() => resolve()));
    activeTunnels.delete(tunnel_id);
    return { content: [{ type: 'text', text: `Tunnel '${tunnel_id}' stopped` }] };
  }
);

server.tool(
  "list-sessions",
  "List all active SSH sessions with metadata.",
  {},
  async () => {
    if (activeSessions.size === 0) {
      return { content: [{ type: 'text', text: 'No active sessions' }] };
    }

    const lines: string[] = [];
    for (const [id, session] of activeSessions.entries()) {
      const info = session.getInfo();
      const uptimeMs = Date.now() - info.createdAt;
      const minutes = Math.floor(uptimeMs / 60000);
      const seconds = Math.floor((uptimeMs % 60000) / 1000);
      lines.push(
        `session=${id} host=${info.host}:${info.port} user=${info.username} uptime=${minutes}m${seconds}s tmux=${info.tmuxReady} lastCommand=${info.lastCommand ?? 'n/a'}`
      );
    }

    return {
      content: [{ type: 'text', text: lines.join('\n') }],
    };
  }
);

export async function execSshCommand(hostId: string, command: string, sessionId = 'legacy') {
  const config = await getHostConfig(hostId);
  const session = await getOrCreateSession(sessionId, config);
  const { output, exitCode } = await session.execute(command);
  if (exitCode !== 0) {
    throw new McpError(ErrorCode.InternalError, `Error (code ${exitCode}):\n${output}`);
  }
  return {
    content: [{ type: 'text', text: output }],
  };
}

async function getOrCreateSession(id: string, config: ConnectConfig, forceNew = false): Promise<PersistentSession> {
  let session = activeSessions.get(id);
  if (session && forceNew) {
    session.dispose();
    activeSessions.delete(id);
    session = undefined;
  }

  if (!session) {
    session = new PersistentSession(id, config, DEFAULT_SESSION_TTL_MS, (disposedId) => {
      if (activeSessions.get(disposedId) === session) {
        activeSessions.delete(disposedId);
      }
    });
    activeSessions.set(id, session);
  }

  await session.ensureConnected();
  return session;
}

class PersistentSession {
  private conn: InstanceType<typeof SSHClient> | null = null;
  private shell: ClientChannel | null = null;
  private buffer = '';
  private pendingCommand: {
    resolve: (result: { output: string; exitCode: number }) => void;
    reject: (error: Error) => void;
    marker: string;
  } | null = null;
  private inactivityTimer: NodeJS.Timeout | null = null;
  private disposed = false;
  private readonly createdAt = Date.now();
  private lastCommand: string | null = null;
  private connected = false;
  private tmuxReady = false;
  private tmuxSessionName = 'ai';
  private sftp: SFTPWrapper | null = null;

  constructor(
    private readonly id: string,
    private readonly config: ConnectConfig,
    private readonly timeoutMs = DEFAULT_SESSION_TTL_MS,
    private readonly onDispose?: (id: string) => void,
  ) {}

  getInfo() {
    return {
      id: this.id,
      host: this.config.host ?? 'unknown',
      port: this.config.port ?? 22,
      username: this.config.username ?? 'unknown',
      createdAt: this.createdAt,
      lastCommand: this.lastCommand,
      disposed: this.disposed,
      tmuxReady: this.tmuxReady,
    };
  }

  async ensureConnected(): Promise<void> {
    if (this.disposed) {
      throw new McpError(ErrorCode.InternalError, `Session ${this.id} has been disposed`);
    }
    if (this.conn && this.shell && this.connected) {
      return;
    }

    // Auto-reconnect: if connection was lost but session not disposed, reconnect
    this.cleanup();
    this.connected = false;

    await new Promise<void>((resolve, reject) => {
      const conn = new SSHClient();
      this.conn = conn;
      let settled = false;

      const handleResolve = () => {
        if (settled) return;
        settled = true;
        clearTimeout(connectTimer);
        resolve();
      };

      const handleReject = (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(connectTimer);
        this.cleanup(err);
        reject(err);
      };

      // Connection timeout — prevents infinite pending when host is unreachable
      const connectTimer = setTimeout(() => {
        const timeoutErr = new Error(`SSH connection to ${this.config.host}:${this.config.port ?? 22} timed out after ${CONNECT_TIMEOUT / 1000}s`);
        handleReject(timeoutErr);
      }, CONNECT_TIMEOUT);

      conn.on('error', (err) => {
        if (!this.connected) {
          // Error during initial connection
          handleReject(err);
        } else {
          // Error after connection was established — don't crash, just cleanup
          console.error(`SSH session ${this.id} connection error:`, err.message);
          this.cleanup();
        }
      });

      conn.once('ready', () => {
        this.connected = true;
        conn.shell({ term: 'xterm', rows: 40, cols: 120 }, (err, stream) => {
          if (err) {
            handleReject(err);
            return;
          }

          this.shell = stream;
          stream.setEncoding('utf8');
          stream.on('data', (data: string) => {
            this.buffer += data;
            this.processPending();
          });
          stream.on('close', () => {
            this.cleanup();
          });
          stream.stderr?.on('data', (data: string) => {
            this.buffer += data;
            this.processPending();
          });

          // Remove shell prompt noise
          stream.write('export PS1=""\n');
          stream.write('stty -echo 2>/dev/null\n');
          // Wait briefly for shell to process, then clear stale buffer data
          setTimeout(() => {
            this.buffer = '';
            handleResolve();
          }, 300);
        });
      });

      conn.once('end', () => {
        if (this.connected) {
          console.error(`SSH session ${this.id} connection ended`);
        }
        if (!settled) {
          handleReject(new Error(`SSH connection to ${this.config.host}:${this.config.port ?? 22} ended before ready`));
        } else {
          this.cleanup();
        }
      });

      // Add keepalive to prevent idle connection drops
      const keepaliveConfig: ConnectConfig = {
        ...this.config,
        keepaliveInterval: 30000,    // Send keepalive every 30s
        keepaliveCountMax: 5,        // Allow 5 missed keepalives before disconnect
      };
      conn.connect(keepaliveConfig);
    });

    this.resetInactivityTimer();
  }

  async initTmux(): Promise<void> {
    try {
      const { exitCode } = await this.executeDirect('which tmux 2>/dev/null');
      if (exitCode === 0) {
        await this.setupTmuxInternal();
      } else {
        this.tmuxReady = false;
        console.error(`SSH session ${this.id}: tmux not found, using direct shell mode`);
      }
    } catch {
      this.tmuxReady = false;
      console.error(`SSH session ${this.id}: tmux init failed, using direct shell mode`);
    }
  }

  async setupTmux(): Promise<string> {
    await this.ensureConnected();

    // Check if tmux is installed
    const { exitCode: whichCode } = await this.executeDirect('which tmux 2>/dev/null');
    if (whichCode !== 0) {
      throw new McpError(ErrorCode.InternalError, 'tmux is not installed on the remote server. Install it first (e.g. apk add tmux / apt install tmux), then call setup-tmux again.');
    }

    // Check if tmux session already exists (regardless of tmuxReady flag)
    const { exitCode: hasCode } = await this.executeDirect(`tmux has-session -t ${this.tmuxSessionName} 2>/dev/null`);
    if (hasCode === 0 && this.tmuxReady) {
      return `tmux session '${this.tmuxSessionName}' already active. User can attach with: tmux attach -t ${this.tmuxSessionName}`;
    }

    // Session doesn't exist or flag is out of sync — re-initialize
    await this.setupTmuxInternal();
    return `tmux session initialized successfully. User can attach with: tmux attach -t ${this.tmuxSessionName}`;
  }

  private async setupTmuxInternal(): Promise<void> {
    const host = this.config.host ?? 'server';
    // Kill existing tmux ai session if any, then create fresh
    const createResult = await this.executeDirect(`tmux kill-session -t ${this.tmuxSessionName} 2>/dev/null; tmux new-session -d -s ${this.tmuxSessionName}`);

    // Verify the session was actually created
    const verifyResult = await this.executeDirect(`tmux has-session -t ${this.tmuxSessionName} 2>/dev/null`);
    if (verifyResult.exitCode !== 0) {
      throw new Error(`Failed to create tmux session '${this.tmuxSessionName}': ${createResult.output}`);
    }

    await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName} 'stty echo' Enter`);
    await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName} "export PS1='root@${host} # '" Enter`);
    // Clear screen so init commands don't pollute capture-pane output
    await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName} 'clear' Enter`);

    // Small delay to let tmux shell initialize
    await new Promise(r => setTimeout(r, 500));

    this.tmuxReady = true;
  }

  async execute(command: string): Promise<{ output: string; exitCode: number }> {
    await this.ensureConnected();

    if (this.tmuxReady) {
      // Verify tmux session still exists before routing through it
      try {
        const { exitCode: hasCode } = await this.executeDirect(`tmux has-session -t ${this.tmuxSessionName} 2>/dev/null`);
        if (hasCode !== 0) {
          this.tmuxReady = false;
          console.error(`SSH session ${this.id}: tmux session '${this.tmuxSessionName}' lost, falling back to direct shell`);
        }
      } catch {
        this.tmuxReady = false;
        console.error(`SSH session ${this.id}: tmux session check failed, falling back to direct shell`);
      }

      if (this.tmuxReady) {
        try {
          return await this.executeViaTmux(command);
        } catch (err) {
          // tmux execution failed, fall back to direct shell
          this.tmuxReady = false;
          console.error(`SSH session ${this.id}: tmux execution failed, falling back to direct shell:`, err);
          return this.executeDirect(command);
        }
      }
    }
    return this.executeDirect(command);
  }

  private async executeDirect(command: string): Promise<{ output: string; exitCode: number }> {
    if (!this.shell) {
      throw new McpError(ErrorCode.InternalError, 'SSH shell not ready');
    }
    if (this.pendingCommand) {
      throw new McpError(ErrorCode.InternalError, 'Another command is still running in this session');
    }

    this.lastCommand = command;
    this.resetInactivityTimer();

    const token = randomUUID();
    const marker = `__MCP_DONE__${token}__`;

    return new Promise((resolve, reject) => {
      this.pendingCommand = {
        marker,
        resolve,
        reject,
      };

      const commandWithNewline = command.endsWith('\n') ? command : command + '\n';
      // Combine command + marker into a single write to prevent shell treating printf as continuation
      // Use echo for marker output to avoid printf single-quote parsing issues
      const fullCommand = commandWithNewline + `echo ${marker}$?\n`;
      this.shell!.write(fullCommand, (err) => {
        if (err) {
          this.rejectPending(err);
        }
      });
    });
  }

  private async getSftp(): Promise<SFTPWrapper> {
    if (this.sftp) return this.sftp;
    if (!this.conn) throw new McpError(ErrorCode.InternalError, 'SSH connection not ready');
    return new Promise((resolve, reject) => {
      this.conn!.sftp((err, sftp) => {
        if (err) { reject(err); return; }
        this.sftp = sftp;
        resolve(sftp);
      });
    });
  }

  async uploadFile(localPath: string, remotePath: string): Promise<string> {
    await this.ensureConnected();
    const sftp = await this.getSftp();
    // Ensure remote directory exists
    const remoteDir = remotePath.includes('/') ? remotePath.substring(0, remotePath.lastIndexOf('/')) : '';
    if (remoteDir) {
      await new Promise<void>((resolve, reject) => {
        sftp.mkdir(remoteDir, (err: any) => {
          // Ignore error if directory already exists (code 4=FAILURE, 2=ENOENT)
          if (err && err.code !== 4 && err.code !== 2) { reject(err); return; }
          resolve();
        });
      });
    }
    return new Promise((resolve, reject) => {
      const readStream = createReadStream(localPath);
      const writeStream = sftp.createWriteStream(remotePath);
      writeStream.on('error', reject);
      readStream.on('error', reject);
      writeStream.on('close', () => resolve(`Uploaded ${localPath} -> ${remotePath}`));
      readStream.pipe(writeStream);
    });
  }

  async downloadFile(remotePath: string, localPath: string): Promise<string> {
    await this.ensureConnected();
    const sftp = await this.getSftp();
    // Ensure local directory exists
    const localDir = dirname(localPath);
    mkdirSync(localDir, { recursive: true });
    return new Promise((resolve, reject) => {
      const readStream = sftp.createReadStream(remotePath);
      const writeStream = createWriteStream(localPath);
      readStream.on('error', reject);
      writeStream.on('error', reject);
      writeStream.on('close', () => resolve(`Downloaded ${remotePath} -> ${localPath}`));
      readStream.pipe(writeStream);
    });
  }

  async writeRemoteFile(remotePath: string, content: string): Promise<string> {
    await this.ensureConnected();
    const sftp = await this.getSftp();
    const buffer = Buffer.from(content, 'utf8');
    const remoteDir = remotePath.includes('/') ? remotePath.substring(0, remotePath.lastIndexOf('/')) : '';
    if (remoteDir) {
      await new Promise<void>((resolve) => {
        sftp.mkdir(remoteDir, () => resolve()); // ignore error if dir exists
      });
    }
    return new Promise((resolve, reject) => {
      sftp.open(remotePath, 'w', (err, handle) => {
        if (err) { reject(err); return; }
        sftp.write(handle, buffer, 0, buffer.length, 0, (writeErr) => {
          if (writeErr) { sftp.close(handle, () => {}); reject(writeErr); return; }
          sftp.close(handle, (closeErr) => {
            if (closeErr) { reject(closeErr); return; }
            resolve(`Written ${buffer.length} bytes to ${remotePath}`);
          });
        });
      });
    });
  }

  private async executeViaTmux(command: string): Promise<{ output: string; exitCode: number }> {
    // Detect heredoc — it causes tmux to hang waiting for EOF input
    if (/<<\s*'?[A-Za-z_][A-Za-z0-9_]*'?/.test(command)) {
      return {
        output: '[ERROR] heredoc syntax (<<EOF) causes tmux sessions to hang. Use the write-remote-file tool to write file contents instead.',
        exitCode: 1,
      };
    }

    this.lastCommand = command;
    this.resetInactivityTimer();

    // Clear tmux scrollback so capture-pane only sees output from this command
    await this.executeDirect(`tmux clear-history -t ${this.tmuxSessionName} 2>/dev/null`);

    const token = randomUUID();
    const startMarker = `__MCP_START__${token}__`;
    const endMarker = `__MCP_DONE__${token}__`;

    // Send compound command with start and end markers to tmux
    // In tmux shell: echo __MCP_START__; <cmd>; echo __MCP_DONE__$?
    // The $? after the command captures the command's exit code
    // Use single quotes for send-keys to avoid SSH shell expansion
    // Escape single quotes in the command using '\'' pattern
    const escapedCmd = command.replace(/'/g, "'\\''");
    const sendCmd = `echo ${startMarker}; ${escapedCmd}; echo ${endMarker}$?`;
    const sendResult = await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName} '${sendCmd}' Enter`);
    if (sendResult.exitCode !== 0) {
      throw new Error(`tmux send-keys failed: ${sendResult.output}`);
    }

    // Poll tmux capture-pane until end marker appears
    const maxWaitMs = 30000;
    const pollIntervalMs = 300;
    const startTime = Date.now();
    let pollCount = 0;

    while (Date.now() - startTime < maxWaitMs) {
      await new Promise(r => setTimeout(r, pollIntervalMs));
      pollCount++;

      const capResult = await this.executeDirect(`tmux capture-pane -t ${this.tmuxSessionName} -p -S -200 2>&1`);
      if (capResult.exitCode !== 0 && pollCount <= 3) {
        continue;
      }
      if (capResult.exitCode !== 0) {
        throw new Error(`tmux capture-pane failed: ${capResult.output}`);
      }

      const pane = capResult.output;

      // Match end marker output line: "...content__MCP_DONE__uuid__0\n"
      // Don't require a leading \n — command output may not end with a newline.
      // The input line has "echo __MCP_DONE__$?" (ends with $?), never digits, so no false match.
      const endMarkerLineRegex = new RegExp(`${escapeRegex(endMarker)}(\\d+)(?:\\n|$)`, 'm');
      const endMatch = pane.match(endMarkerLineRegex);
      if (endMatch) {
        const exitCode = parseInt(endMatch[1], 10);
        const endMarkerLineStart = endMatch.index!; // marker starts here (no leading \n to skip)

        // Search for start marker on its own output line: "\n__MCP_START__xxx__\n"
        const startMarkerLineRegex = new RegExp(`\\n${escapeRegex(startMarker)}\\n`);
        const startMatch = pane.match(startMarkerLineRegex);
        let cmdOutput: string;
        if (startMatch) {
          const startMarkerLineEnd = startMatch.index! + 1 + startMatch[0].length - 1; // after the trailing \n
          cmdOutput = pane.slice(startMarkerLineEnd, endMarkerLineStart);
        } else {
          // Fallback: output is everything before end marker line
          cmdOutput = pane.slice(0, endMarkerLineStart);
        }

        cmdOutput = cmdOutput
          .replace(/\r/g, '')
          .replace(/\x1b\[\?[0-9]+[hl]/g, '')
          .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
          .replace(/\s+$/, '');

        return { output: cmdOutput, exitCode: Number.isNaN(exitCode) ? 0 : exitCode };
      }
    }

    // Timeout: return whatever we have
    const { output: pane } = await this.executeDirect(`tmux capture-pane -t ${this.tmuxSessionName} -p -S -200 2>&1`);
    return { output: pane.replace(/\r/g, '').replace(/\x1b\[\?[0-9]+[hl]/g, '').replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/\s+$/, ''), exitCode: -1 };
  }

  forwardPort(localPort: number, remoteHost: string, remotePort: number): Promise<net.Server> {
    return new Promise((resolve, reject) => {
      if (!this.conn) {
        reject(new McpError(ErrorCode.InternalError, 'SSH connection not ready'));
        return;
      }
      const conn = this.conn;
      const tcpServer = net.createServer((localSocket) => {
        conn.forwardOut('127.0.0.1', localPort, remoteHost, remotePort, (err, channel) => {
          if (err) {
            localSocket.destroy();
            return;
          }
          localSocket.pipe(channel);
          channel.pipe(localSocket);
          localSocket.on('close', () => channel.end());
          channel.on('close', () => localSocket.destroy());
          channel.on('error', () => localSocket.destroy());
          localSocket.on('error', () => channel.end());
        });
      });
      tcpServer.once('error', (err) => reject(err));
      tcpServer.listen(localPort, '127.0.0.1', () => resolve(tcpServer));
    });
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.cleanup();
  }

  private resetInactivityTimer(): void {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
    }

    this.inactivityTimer = setTimeout(() => {
      this.dispose();
    }, this.timeoutMs);
  }

  private processPending(): void {
    if (!this.pendingCommand) {
      return;
    }

    const { marker, resolve } = this.pendingCommand;
    const markerIndex = this.buffer.indexOf(marker);
    if (markerIndex === -1) {
      return;
    }

    const afterMarker = this.buffer.slice(markerIndex + marker.length);
    const newlineIndex = afterMarker.indexOf('\n');
    if (newlineIndex === -1) {
      return;
    }

    const exitCodeText = afterMarker.slice(0, newlineIndex).trim();
    const remaining = afterMarker.slice(newlineIndex + 1);

    const output = this.buffer.slice(0, markerIndex).replace(/\r/g, '');
    const exitCode = Number.parseInt(exitCodeText, 10);

    this.buffer = remaining;
    this.pendingCommand = null;

    const finalOutput = output
      .replace(/\x1b\[\?[0-9]+[hl]/g, '') // strip bracketed paste mode
      .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '') // strip ANSI escape codes
      .replace(/__MCP_READY__\s*/g, '')
      .replace(/\s+$/, '');

    resolve({ output: finalOutput, exitCode: Number.isNaN(exitCode) ? 0 : exitCode });
    this.resetInactivityTimer();
  }

  private rejectPending(error: Error): void {
    if (!this.pendingCommand) {
      return;
    }
    this.pendingCommand.reject(error);
    this.pendingCommand = null;
  }

  private cleanup(error?: Error): void {
    this.connected = false;

    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }

    if (this.shell) {
      this.shell.removeAllListeners();
      this.shell.end();
      this.shell = null;
    }

    if (this.sftp) {
      this.sftp.end();
      this.sftp = null;
    }

    if (this.conn) {
      this.conn.removeAllListeners();
      this.conn.end();
      this.conn = null;
    }
    this.tmuxReady = false;

    if (this.pendingCommand) {
      this.pendingCommand.reject(error ?? new Error('SSH session closed'));
      this.pendingCommand = null;
    }

    this.buffer = '';

    if (this.disposed) {
      this.onDispose?.(this.id);
    }
  }
}

async function main() {
  // Global safety net — prevent unhandled rejections/exceptions from crashing the MCP process
  process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection (non-fatal):', reason);
  });
  process.on('uncaughtException', (err) => {
    console.error('Uncaught exception (non-fatal):', err);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SSH MCP Server running on stdio");
}

if (process.env.SSH_MCP_DISABLE_MAIN !== '1') {
  main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
  });
}

export {};