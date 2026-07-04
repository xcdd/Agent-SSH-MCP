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
import { execFile as execFileCb } from 'child_process';
import { promisify } from 'util';

const execFile = promisify(execFileCb);

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

// ── Proxy detection ────────────────────────────────────────────────────────

let _cachedSystemProxy: string | null | undefined = undefined; // undefined = not checked yet

async function getSystemProxy(): Promise<string | null> {
  if (_cachedSystemProxy !== undefined) return _cachedSystemProxy;

  // 1. Standard environment variables (all platforms)
  const fromEnv = process.env.ALL_PROXY ?? process.env.all_proxy ??
    process.env.HTTPS_PROXY ?? process.env.https_proxy ??
    process.env.HTTP_PROXY ?? process.env.http_proxy ?? null;
  if (fromEnv) { _cachedSystemProxy = fromEnv; return fromEnv; }

  // 2. Platform-specific
  try {
    if (process.platform === 'win32') {
      _cachedSystemProxy = await getWindowsSystemProxy();
    } else if (process.platform === 'darwin') {
      _cachedSystemProxy = await getMacSystemProxy();
    } else {
      _cachedSystemProxy = null;
    }
  } catch {
    _cachedSystemProxy = null;
  }
  return _cachedSystemProxy;
}

async function getWindowsSystemProxy(): Promise<string | null> {
  try {
    const enableResult = await execFile('reg', [
      'query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
      '/v', 'ProxyEnable',
    ]);
    if (!enableResult.stdout.includes('0x1')) return null;

    const serverResult = await execFile('reg', [
      'query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
      '/v', 'ProxyServer',
    ]);
    const match = serverResult.stdout.match(/ProxyServer\s+REG_SZ\s+(\S+)/);
    if (!match) return null;
    const raw = match[1].trim();
    // "host:port" or "http=h:p;https=h:p;..."
    const part = raw.includes('=') ? (raw.match(/(?:https?=)([^;]+)/)?.[1] ?? raw.split(';')[0]) : raw;
    return part.includes('://') ? part : `http://${part}`;
  } catch {
    return null;
  }
}

async function getMacSystemProxy(): Promise<string | null> {
  try {
    const { stdout } = await execFile('scutil', ['--proxy']);
    const socksEnabled = /SOCKSEnable\s*:\s*1/.test(stdout);
    if (socksEnabled) {
      const h = stdout.match(/SOCKSProxy\s*:\s*(\S+)/)?.[1];
      const p = stdout.match(/SOCKSPort\s*:\s*(\d+)/)?.[1];
      if (h && p) return `socks5://${h}:${p}`;
    }
    const httpEnabled = /HTTPEnable\s*:\s*1/.test(stdout);
    if (httpEnabled) {
      const h = stdout.match(/HTTPProxy\s*:\s*(\S+)/)?.[1];
      const p = stdout.match(/HTTPPort\s*:\s*(\d+)/)?.[1];
      if (h && p) return `http://${h}:${p}`;
    }
    return null;
  } catch {
    return null;
  }
}

// ── Proxy socket creation ──────────────────────────────────────────────────

const PROXY_TIMEOUT = 15 * 1000;

async function createProxySocket(proxyUrl: string, targetHost: string, targetPort: number): Promise<net.Socket> {
  const normalized = proxyUrl.includes('://') ? proxyUrl : `http://${proxyUrl}`;
  const parsed = new URL(normalized);
  const scheme = parsed.protocol.replace(':', '');
  const proxyHost = parsed.hostname;
  const proxyPort = parseInt(parsed.port) || (scheme === 'socks5' || scheme === 'socks4' || scheme === 'socks' ? 1080 : 3128);

  if (scheme === 'socks5' || scheme === 'socks') {
    return connectViaSocks5(proxyHost, proxyPort, targetHost, targetPort);
  }
  if (scheme === 'socks4') {
    return connectViaSocks4(proxyHost, proxyPort, targetHost, targetPort);
  }
  return connectViaHttpConnect(proxyHost, proxyPort, targetHost, targetPort);
}

function connectViaHttpConnect(proxyHost: string, proxyPort: number, targetHost: string, targetPort: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: proxyHost, port: proxyPort });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error(`HTTP proxy ${proxyHost}:${proxyPort} connection timed out`)); }, PROXY_TIMEOUT);

    socket.once('connect', () => {
      socket.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
      let buf = '';
      const onData = (chunk: Buffer) => {
        buf += chunk.toString('binary');
        if (!buf.includes('\r\n\r\n')) return;
        socket.removeListener('data', onData);
        clearTimeout(timer);
        const statusLine = buf.split('\r\n')[0];
        const code = parseInt(statusLine.split(' ')[1] ?? '0');
        if (code === 200) { resolve(socket); }
        else { socket.destroy(); reject(new Error(`HTTP proxy rejected CONNECT to ${targetHost}:${targetPort}: ${statusLine}`)); }
      };
      socket.on('data', onData);
    });
    socket.once('error', (err) => { clearTimeout(timer); reject(new Error(`HTTP proxy ${proxyHost}:${proxyPort} error: ${err.message}`)); });
  });
}

function connectViaSocks5(proxyHost: string, proxyPort: number, targetHost: string, targetPort: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: proxyHost, port: proxyPort });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error(`SOCKS5 proxy ${proxyHost}:${proxyPort} timed out`)); }, PROXY_TIMEOUT);
    let step = 0;
    let partial = Buffer.alloc(0);

    socket.once('connect', () => { socket.write(Buffer.from([0x05, 0x01, 0x00])); });
    socket.on('data', (chunk: Buffer) => {
      partial = Buffer.concat([partial, chunk]);
      if (step === 0 && partial.length >= 2) {
        if (partial[0] !== 0x05 || partial[1] !== 0x00) {
          clearTimeout(timer); socket.destroy();
          reject(new Error(`SOCKS5 auth failed (server chose method 0x${partial[1]?.toString(16) ?? '??'})`));
          return;
        }
        partial = partial.slice(2);
        step = 1;
        const hBuf = Buffer.from(targetHost);
        const req = Buffer.allocUnsafe(7 + hBuf.length);
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
        req[4] = hBuf.length; hBuf.copy(req, 5);
        req.writeUInt16BE(targetPort, 5 + hBuf.length);
        socket.write(req);
      } else if (step === 1 && partial.length >= 4) {
        clearTimeout(timer);
        socket.removeAllListeners('data');
        if (partial[1] !== 0x00) {
          socket.destroy();
          const codes: Record<number, string> = { 1:'general failure', 2:'not allowed', 3:'network unreachable', 4:'host unreachable', 5:'connection refused', 6:'TTL expired' };
          reject(new Error(`SOCKS5 tunnel to ${targetHost}:${targetPort} failed: ${codes[partial[1]] ?? `code 0x${partial[1].toString(16)}`}`));
          return;
        }
        resolve(socket);
      }
    });
    socket.once('error', (err) => { clearTimeout(timer); reject(new Error(`SOCKS5 proxy ${proxyHost}:${proxyPort} error: ${err.message}`)); });
  });
}

function connectViaSocks4(proxyHost: string, proxyPort: number, targetHost: string, targetPort: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: proxyHost, port: proxyPort });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error(`SOCKS4 proxy ${proxyHost}:${proxyPort} timed out`)); }, PROXY_TIMEOUT);
    // SOCKS4a: send 0x04 0x01 + port + 0.0.0.1 + nullbyte + hostname + nullbyte
    socket.once('connect', () => {
      const hBuf = Buffer.from(targetHost);
      const req = Buffer.allocUnsafe(9 + hBuf.length + 1);
      req[0] = 0x04; req[1] = 0x01;
      req.writeUInt16BE(targetPort, 2);
      req.writeUInt32BE(1, 4); // 0.0.0.1 for SOCKS4a
      req[8] = 0x00; // null user id
      hBuf.copy(req, 9);
      req[9 + hBuf.length] = 0x00;
      socket.write(req);
    });
    socket.once('data', (chunk: Buffer) => {
      clearTimeout(timer);
      socket.removeAllListeners('data');
      if (chunk[1] === 0x5a) { resolve(socket); }
      else { socket.destroy(); reject(new Error(`SOCKS4 tunnel to ${targetHost}:${targetPort} failed: code 0x${chunk[1]?.toString(16) ?? '??'}`)); }
    });
    socket.once('error', (err) => { clearTimeout(timer); reject(new Error(`SOCKS4 proxy ${proxyHost}:${proxyPort} error: ${err.message}`)); });
  });
}

type StoredHost = {
  id: string;
  host: string;
  port: number;
  username: string;
  password?: string;
  keyPath?: string;
  proxy?: string;    // e.g. "socks5://127.0.0.1:1080" or "http://proxy:3128"
  noProxy?: boolean; // disable auto system-proxy detection for this host
};

const HostsSchema = z.object({
  hosts: z.array(z.object({
    id: z.string(),
    host: z.string(),
    port: z.number().int().positive().default(22),
    username: z.string(),
    password: z.string().optional(),
    keyPath: z.string().optional(),
    proxy: z.string().optional(),
    noProxy: z.boolean().optional(),
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

async function getHostConfig(hostId: string): Promise<{ config: ConnectConfig; proxy?: string; noProxy?: boolean }> {
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
    if (process.env.SSH_AUTH_SOCK) {
      config.agent = process.env.SSH_AUTH_SOCK;
      config.agentForward = true;
    }
  }

  return { config, proxy: host.proxy, noProxy: host.noProxy };
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
    proxy: z.string().optional().describe("Proxy URL override, e.g. socks5://127.0.0.1:1080 or http://proxy:3128. Omit to use system proxy auto-detection."),
    noProxy: z.boolean().optional().describe("Set true to disable system proxy auto-detection for this host"),
  },
  async ({ host_id, host, port, username, password, keyPath, proxy, noProxy }) => {
    const hosts = await readHosts();
    if (hosts.some((h) => h.id === host_id)) {
      throw new McpError(ErrorCode.InvalidParams, `Host '${host_id}' already exists`);
    }
    hosts.push({ id: host_id, host, port, username, password, keyPath, proxy, noProxy });
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
    proxy: z.string().optional().describe("Proxy URL override, e.g. socks5://127.0.0.1:1080 or http://proxy:3128"),
    noProxy: z.boolean().optional().describe("Set true to disable auto system-proxy for this host"),
  },
  async ({ host_id, host, port, username, password, keyPath, proxy, noProxy }) => {
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
    if (proxy !== undefined) target.proxy = proxy;
    if (noProxy !== undefined) target.noProxy = noProxy;
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
    const { config: hostConfig, proxy, noProxy } = await getHostConfig(host_id);
    const id = sessionId && sessionId.trim() ? sessionId.trim() : randomUUID();
    if (activeSessions.has(id)) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${id}' already exists`);
    }
    let session: PersistentSession;
    try {
      session = await getOrCreateSession(id, hostConfig, true, proxy, noProxy);
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
    if (exitCode === -2) {
      resultText = `[Command is waiting for input — use the exec tool to send the required response (e.g. "y", a password, etc.)]\n${output}`;
    } else if (exitCode === -1) {
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
  const { config, proxy, noProxy } = await getHostConfig(hostId);
  const session = await getOrCreateSession(sessionId, config, false, proxy, noProxy);
  const { output, exitCode } = await session.execute(command);
  if (exitCode !== 0) {
    throw new McpError(ErrorCode.InternalError, `Error (code ${exitCode}):\n${output}`);
  }
  return {
    content: [{ type: 'text', text: output }],
  };
}

async function getOrCreateSession(id: string, config: ConnectConfig, forceNew = false, proxyUrl?: string, noProxy?: boolean): Promise<PersistentSession> {
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
    }, proxyUrl, noProxy);
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
    private readonly proxyUrl?: string,
    private readonly noProxy?: boolean,
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

    // Resolve proxy socket before opening SSH connection
    let proxySocket: net.Socket | undefined;
    const effectiveProxy = this.proxyUrl ?? (this.noProxy ? undefined : await getSystemProxy());
    if (effectiveProxy) {
      const targetHost = this.config.host!;
      const targetPort = this.config.port ?? 22;
      try {
        proxySocket = await createProxySocket(effectiveProxy, targetHost, targetPort);
      } catch (err: any) {
        throw new Error(`Proxy error (${effectiveProxy} → ${targetHost}:${targetPort}): ${err.message}`);
      }
    }

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
        keepaliveInterval: 30000,
        keepaliveCountMax: 5,
      };
      if (proxySocket) keepaliveConfig.sock = proxySocket;
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
          this.tmuxReady = false;
          console.error(`SSH session ${this.id}: tmux execution failed, falling back to direct shell:`, err);
          return this.executeDirect(command);
        }
      }
    }

    // Direct shell mode — only allow tmux installation/diagnostic commands.
    // All other commands must wait until tmux is available (call setup-tmux after installing).
    const isTmuxSetupCmd = /\b(apt(-get)?|yum|dnf|apk|pacman|brew|pkg|zypper|emerge)\b.*\btmux\b|\bwhich\s+tmux\b|\bwhereis\s+tmux\b|\btmux\s+-V\b/i.test(command);
    if (!isTmuxSetupCmd) {
      return {
        output: '[ERROR] tmux is not available on this server. Direct shell mode only accepts tmux installation commands (e.g. "apt install tmux"). After installing, call setup-tmux to enable full command execution.',
        exitCode: 1,
      };
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
    // For interactive-prompt detection
    let lastAfterStart = '';
    let stablePollCount = 0;
    const STABLE_THRESHOLD = 4; // ~1.2s stable → likely waiting for input
    const INTERACTIVE_PROMPT_RE = /\[Y\/n\]|\[y\/N\]|\(yes\/no\)|\[yes\/no\]|\(y\/n\)|\(Y\/N\)|password\s*:|\bpassphrase\s*:|--More--|continue\s*\?\s*\[|are you sure|do you want to|\(y or n\)|\(yes or no\)|enter .{0,30}:/i;
    const startMarkerLineRegex = new RegExp(`\\n${escapeRegex(startMarker)}\\n`);
    const endMarkerLineRegex = new RegExp(`${escapeRegex(endMarker)}(\\d+)(?:\\n|$)`, 'm');

    const cleanOutput = (s: string) => s
      .replace(/\r/g, '')
      .replace(/\x1b\[\?[0-9]+[hl]/g, '')
      .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
      .replace(/\s+$/, '');

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

      // Check for end marker first
      const endMatch = pane.match(endMarkerLineRegex);
      if (endMatch) {
        const exitCode = parseInt(endMatch[1], 10);
        const endMarkerLineStart = endMatch.index!;

        const startMatch = pane.match(startMarkerLineRegex);
        let cmdOutput: string;
        if (startMatch) {
          const startMarkerLineEnd = startMatch.index! + 1 + startMatch[0].length - 1;
          cmdOutput = pane.slice(startMarkerLineEnd, endMarkerLineStart);
        } else {
          cmdOutput = pane.slice(0, endMarkerLineStart);
        }

        return { output: cleanOutput(cmdOutput), exitCode: Number.isNaN(exitCode) ? 0 : exitCode };
      }

      // Interactive-prompt detection: only after start marker has appeared
      const startMatch = pane.match(startMarkerLineRegex);
      if (startMatch) {
        const afterStart = pane.slice(startMatch.index! + 1 + startMatch[0].length - 1);
        const afterStartTrimmed = afterStart.trim();

        if (afterStartTrimmed) {
          // Immediate: known interactive prompt pattern
          if (INTERACTIVE_PROMPT_RE.test(afterStartTrimmed)) {
            return { output: cleanOutput(afterStart), exitCode: -2 };
          }

          // Stability: content unchanged for STABLE_THRESHOLD polls
          if (afterStartTrimmed === lastAfterStart) {
            stablePollCount++;
            if (stablePollCount >= STABLE_THRESHOLD) {
              return { output: cleanOutput(afterStart), exitCode: -2 };
            }
          } else {
            stablePollCount = 0;
            lastAfterStart = afterStartTrimmed;
          }
        }
      }
    }

    // Timeout: return whatever we have
    const { output: pane } = await this.executeDirect(`tmux capture-pane -t ${this.tmuxSessionName} -p -S -200 2>&1`);
    return { output: cleanOutput(pane), exitCode: -1 };
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