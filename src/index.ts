#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import type { ClientChannel, ConnectConfig, SFTPWrapper } from 'ssh2';
import SSH2Module from 'ssh2';
const { Client: SSHClient, utils: sshUtils } = SSH2Module as typeof import('ssh2');
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { readFile, writeFile, mkdir, stat, open as openFileHandle } from 'fs/promises';
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

const INTERACTIVE_PROMPT_RE = /\[Y\/n\]|\[y\/N\]|\(yes\/no\)|\[yes\/no\]|\(y\/n\)|\(Y\/N\)|password\s*:|\bpassphrase\s*:|--More--|continue\s*\?\s*\[|are you sure|do you want to|\(y or n\)|\(yes or no\)|enter .{0,30}:/i;

function cleanPaneOutput(s: string): string {
  return s
    .replace(/\r/g, '')
    .replace(/\x1b\[\?[0-9]+[hl]/g, '')
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\s+$/, '');
}

const HOSTS_DIR = resolvePath(os.homedir(), '.ssh-mcp');
const HOSTS_FILE = resolvePath(HOSTS_DIR, 'hosts.json');

// ── High-speed transfer channel ("fast channel") ───────────────────────────
// SFTP transfers (ssh2) keep at most ~2MB in flight (hard-coded channel window),
// which caps throughput at roughly window/RTT — very slow on high-latency or
// lossy links. When the fastd helper is installed on the remote host, transfers
// go over parallel direct HTTP range requests instead, with SFTP as fallback.

const FAST_MIN_BYTES = 4 * 1024 * 1024; // engage the fast channel for files >= 4MB (helper startup amortizes there)
const FAST_CHUNK = 4 * 1024 * 1024; // 4MB per HTTP request
const FAST_CONCURRENCY = 8; // parallel HTTP streams

type FastdState =
  | { status: 'unchecked' }
  | { status: 'no-helper' }
  | { status: 'ready'; baseUrl: string; mode: 'direct' | 'tunnel'; token: string; localServer?: net.Server; pid: number | null; remoteDir: string }
  | { status: 'unreachable' }
  | { status: 'failed' };

function abortAfter(ms: number): AbortSignal {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  timer.unref?.();
  return controller.signal;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

const FASTD_SCRIPT = `#!/usr/bin/env python3
# agent-ssh-mcp fast transfer helper ("fastd").
# Installed and started on demand by the SSH MCP plugin's high-speed channel.
# Token-gated HTTP file server with parallel ranged GET/PUT support -- much
# faster than SFTP on high-latency or lossy links. Binds 0.0.0.0 on an
# ephemeral port, requires the X-Fastd-Token header for every request, and
# exits by itself after --idle seconds without requests.

import argparse
import json
import os
import re
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

TOKEN = os.environ.get("OGOC_FASTD_TOKEN", "")
PORT_FILE = None
LAST_REQUEST = time.time()


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _authorized(self):
        if not TOKEN or self.headers.get("X-Fastd-Token") != TOKEN:
            self.send_error(403)
            return False
        return True

    def _one(self, key):
        return unquote(parse_qs(urlparse(self.path).query).get(key, [""])[0])

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global LAST_REQUEST
        LAST_REQUEST = time.time()
        try:
            if not self._authorized():
                return
            cmd = urlparse(self.path).path
            if cmd == "/stat":
                p = self._one("path")
                if not p:
                    return self._json({"error": "path required"}, 400)
                if os.path.isdir(p):
                    return self._json({"path": p, "isdir": True, "exists": True, "size": 0})
                try:
                    return self._json({"path": p, "isdir": False, "exists": True, "size": os.path.getsize(p)})
                except OSError:
                    return self._json({"path": p, "isdir": False, "exists": False, "size": 0})
            if cmd == "/read":
                p = self._one("path")
                if not p:
                    return self._json({"error": "path required"}, 400)
                try:
                    size = os.path.getsize(p)
                except OSError as e:
                    return self._json({"error": str(e)}, 404)
                start, end, status = 0, size - 1, 200
                rng = self.headers.get("Range")
                if rng:
                    m = re.match(r"bytes=(\\d*)-(\\d*)$", rng.strip())
                    if not m:
                        return self._json({"error": "bad range"}, 400)
                    if m.group(1):
                        start = int(m.group(1))
                        end = int(m.group(2)) if m.group(2) else size - 1
                    else:
                        n = int(m.group(2))
                        start, end = max(0, size - n), size - 1
                    if start >= size or start > end:
                        return self._json({"error": "range not satisfiable"}, 416)
                    end = min(end, size - 1)
                    status = 206
                length = end - start + 1
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(length))
                if status == 206:
                    self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
                self.end_headers()
                with open(p, "rb") as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
                return
            self._json({"error": "not found"}, 404)
        except (ConnectionError, BrokenPipeError):
            pass
        except Exception as e:
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    def do_POST(self):
        global LAST_REQUEST
        LAST_REQUEST = time.time()
        try:
            if not self._authorized():
                return
            cmd = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            if cmd == "/write":
                p, offset = self._one("path"), int(self._one("offset") or 0)
                if not p:
                    return self._json({"error": "path required"}, 400)
                fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o644)
                try:
                    written, remaining = 0, length
                    while remaining > 0:
                        data = self.rfile.read(min(1024 * 1024, remaining))
                        if not data:
                            break
                        os.pwrite(fd, data, offset + written)
                        written += len(data)
                        remaining -= len(data)
                finally:
                    os.close(fd)
                return self._json({"written": written})
            if cmd == "/truncate":
                p, size = self._one("path"), int(self._one("size") or 0)
                if not p:
                    return self._json({"error": "path required"}, 400)
                fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o644)
                try:
                    os.ftruncate(fd, size)
                finally:
                    os.close(fd)
                return self._json({"ok": True})
            if length > 0:
                self.rfile.read(length)
            self._json({"error": "not found"}, 404)
        except (ConnectionError, BrokenPipeError):
            pass
        except Exception as e:
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass


def main():
    global PORT_FILE
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--port-file", default=None)
    ap.add_argument("--idle", type=int, default=1800)
    args = ap.parse_args()
    PORT_FILE = args.port_file
    if not TOKEN:
        print("FASTD_ERROR: OGOC_FASTD_TOKEN not set", file=sys.stderr)
        sys.exit(2)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    port = httpd.server_address[1]
    if PORT_FILE:
        with open(PORT_FILE, "w") as f:
            f.write(str(port))
    print("FASTD_READY port=%d" % port, flush=True)

    def reaper():
        while True:
            time.sleep(30)
            if time.time() - LAST_REQUEST > args.idle:
                if PORT_FILE:
                    try:
                        os.remove(PORT_FILE)
                    except OSError:
                        pass
                os._exit(0)

    threading.Thread(target=reaper, daemon=True).start()
    httpd.serve_forever()


if __name__ == "__main__":
    main()
`;

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
const activeTunnels = new Map<string, { server: net.Server; sockets: Set<net.Socket>; localPort: number; remoteHost: string; remotePort: number; sessionId: string }>();
const DEFAULT_SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '1.1.0',
  capabilities: {
    resources: {},
    tools: {},
  },
}, {
  instructions:
    'File transfers (upload-file/download-file) automatically use the high-speed channel ' +
    '(parallel HTTP via a small helper daemon) when it is installed on the target host, ' +
    'and fall back to SFTP otherwise. On hosts where transfers feel slow, call ' +
    'install-fast-channel once per host (requires python3; works on mainstream Linux distros) ' +
    'to enable it — subsequent sessions detect it automatically.',
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
  "Start a new SSH session for a stored host. Initializes tmux if available; falls back to direct shell. Install tmux BEFORE calling this, or use setup-tmux after. When tmux is active, exec routes commands automatically — do not write tmux send-keys manually. For fast file transfers on this host, call install-fast-channel once.",
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
    const tmuxStatus = info.tmuxReady
      ? `tmux ready (attach: tmux attach -t ${info.tmuxSessionName})`
      : 'tmux not available (direct shell mode)';
    return { content: [{ type: 'text', text: `${id}\n${tmuxStatus}` }] };
  }
);

server.tool(
  "exec",
  "Execute a shell command on an existing SSH session. When tmux is active, commands are routed automatically — just pass the command, do not write tmux send-keys. Falls back to direct shell if tmux is lost. If output contains '[Command is waiting for input...]', call exec again with just the raw response (e.g. 'y', a password).",
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
  "Upload a local file to the remote server. Preferred over echo/cat/heredoc — handles binary and special characters correctly. Uses the fast channel (fastd) when installed on the host, falls back to SFTP otherwise; for large files or slow links call install-fast-channel once — typically 10-50x faster.",
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
  "Download a file from the remote server. Automatically uses the high-speed channel (parallel HTTP via the fastd helper) when it is installed on the host, and falls back to SFTP otherwise. For large files or slow links, call install-fast-channel once on this host to enable the fast channel — typically 10-50x faster than SFTP on high-latency or lossy links.",
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
  "install-fast-channel",
  "One-time setup of the high-speed file transfer channel on this host: installs a small Python helper (~/.agent-ssh-mcp/fastd.py, requires python3, works on mainstream Linux distros). Once installed, upload-file/download-file detect it automatically on every future session and transfer via parallel HTTP instead of SFTP — typically 10-50x faster on high-latency or lossy links (SFTP remains the automatic fallback). Call this once per host before transferring large files.",
  {
    session_id: z.string().describe("Identifier of the session to install the helper on"),
  },
  async ({ session_id }) => {
    const session = activeSessions.get(session_id);
    if (!session) {
      throw new McpError(ErrorCode.InvalidParams, `Session '${session_id}' does not exist`);
    }
    const result = await session.installFastChannel();
    return { content: [{ type: 'text', text: result }] };
  }
);

server.tool(
  "write-remote-file",
  "Write text content directly to a file on the remote server via SFTP. Preferred over echo/cat/heredoc — reliable, handles special characters.",
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
  "Initialize tmux on an existing SSH session. Use after installing tmux to switch from direct shell mode. When active, user can attach with the session name returned by start-session.",
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
  "Create a local TCP port forward through the SSH session. After calling this, connect to 127.0.0.1:<local_port> to reach <remote_host>:<remote_port> on the server.",
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
    const sockets = new Set<net.Socket>();
    const tcpServer = await session.forwardPort(local_port, remote_host, remote_port, sockets);
    activeTunnels.set(id, { server: tcpServer, sockets, localPort: local_port, remoteHost: remote_host, remotePort: remote_port, sessionId: session_id });
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
    // Destroy all active sockets first so server.close() doesn't wait for them
    for (const sock of tunnel.sockets) sock.destroy();
    tunnel.sockets.clear();
    await Promise.race([
      new Promise<void>((resolve) => tunnel.server.close(() => resolve())),
      new Promise<void>((resolve) => setTimeout(resolve, 5000)),
    ]);
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
  private readonly tmuxSessionName: string;
  private sftp: SFTPWrapper | null = null;
  // When a tmux command returns exitCode -2 (waiting for input), these fields persist
  // across the exec call boundary so the next exec sends raw input instead of a wrapped command.
  private tmuxPendingMarkers: { startMarker: string; endMarker: string; lastSnapshot: string } | null = null;
  private tmuxWaitingForInput = false;
  private fastd: FastdState = { status: 'unchecked' };
  private fastdProbe: Promise<FastdState | null> | null = null;

  constructor(
    private readonly id: string,
    private readonly config: ConnectConfig,
    private readonly timeoutMs = DEFAULT_SESSION_TTL_MS,
    private readonly onDispose?: (id: string) => void,
    private readonly proxyUrl?: string,
    private readonly noProxy?: boolean,
  ) {
    // Derive a tmux-safe session name from the SSH session ID so multiple sessions
    // to the same server don't share and clobber each other's tmux session.
    this.tmuxSessionName = this.id.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 50);
  }

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
      tmuxSessionName: this.tmuxSessionName,
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
        // Prefer SSH compression: during negotiation the server picks the
        // first client-offered algorithm it supports, so listing zlib first
        // enables compression on every server that allows it (OpenSSH default
        // is `Compression delayed`). Servers without support fall back to
        // 'none' automatically. Speeds up SFTP fallback transfers and exec
        // output on bandwidth-limited links.
        algorithms: {
          ...this.config.algorithms,
          compress: ['zlib@openssh.com', 'zlib', 'none'],
        },
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

    await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName}:0.0 'stty echo' Enter`);
    await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName}:0.0 "export PS1='root@${host} # '" Enter`);
    // Clear screen so init commands don't pollute capture-pane output
    await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName}:0.0 'clear' Enter`);

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
          if (this.tmuxWaitingForInput && this.tmuxPendingMarkers) {
            return await this.executeInteractiveInput(command);
          }
          return await this.executeViaTmux(command);
        } catch (err) {
          this.tmuxReady = false;
          this.tmuxWaitingForInput = false;
          this.tmuxPendingMarkers = null;
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
    // Ensure remote directory exists (needed by both the fast channel and SFTP)
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
    // High-speed channel: parallel HTTP via the fastd helper, when installed
    let fileSize = -1;
    try { fileSize = (await stat(localPath)).size; } catch { /* fall through to SFTP errors */ }
    if (fileSize >= FAST_MIN_BYTES) {
      const fastd = await this.ensureFastChannel();
      if (fastd) {
        try {
          const { bytes, ms } = await this.fastUpload(localPath, remotePath);
          const mbps = (bytes / 1048576 / (ms / 1000)).toFixed(2);
          return `Uploaded ${localPath} -> ${remotePath} (fast channel, ${mbps} MB/s)`;
        } catch (err: any) {
          console.error(`fast channel upload failed, falling back to SFTP: ${err?.message ?? err}`);
          this.fastd = { status: 'failed' };
        }
      } else if (this.fastd.status === 'no-helper') {
        // Transfer via SFTP, but nudge the agent towards the fast channel
        const result = await this.sftpFastPut(sftp, localPath, remotePath);
        return `${result} (SFTP fallback — run install-fast-channel on this host to enable much faster transfers)`;
      }
    }
    return this.sftpFastPut(sftp, localPath, remotePath);
  }

  private async sftpFastPut(sftp: SFTPWrapper, localPath: string, remotePath: string): Promise<string> {
    // Pipelined SFTP: keeps ~64x32KB in flight. Still far faster than the old
    // stream pipe (one write per RTT) on high-latency links.
    return new Promise((resolve, reject) => {
      sftp.fastPut(localPath, remotePath, { concurrency: 64, chunkSize: 131072 }, (err) => {
        if (err) { reject(err); return; }
        resolve(`Uploaded ${localPath} -> ${remotePath}`);
      });
    });
  }

  async downloadFile(remotePath: string, localPath: string): Promise<string> {
    await this.ensureConnected();
    const sftp = await this.getSftp();
    // Ensure local directory exists
    const localDir = dirname(localPath);
    mkdirSync(localDir, { recursive: true });
    // High-speed channel: parallel HTTP via the fastd helper, when installed.
    // Probe remote size first so small files skip the helper handshake entirely.
    let remoteSize = -1;
    try {
      const s = await new Promise<any>((resolve, reject) =>
        sftp.stat(remotePath, (err: any, s: any) => err ? reject(err) : resolve(s))
      );
      remoteSize = s?.size ?? -1;
    } catch (err: any) {
      throw new McpError(ErrorCode.InternalError, `Cannot stat ${remotePath}: ${err?.message ?? err}`);
    }
    if (remoteSize >= FAST_MIN_BYTES) {
      const fastd = await this.ensureFastChannel();
      if (fastd) {
        try {
          const { bytes, ms } = await this.fastDownload(remotePath, localPath);
          const mbps = (bytes / 1048576 / (ms / 1000)).toFixed(2);
          return `Downloaded ${remotePath} -> ${localPath} (fast channel, ${mbps} MB/s)`;
        } catch (err: any) {
          console.error(`fast channel download failed, falling back to SFTP: ${err?.message ?? err}`);
          this.fastd = { status: 'failed' };
        }
      } else if (this.fastd.status === 'no-helper') {
        const result = await this.sftpFastGet(sftp, remotePath, localPath);
        return `${result} (SFTP fallback — run install-fast-channel on this host to enable much faster transfers)`;
      }
    }
    return this.sftpFastGet(sftp, remotePath, localPath);
  }

  private async sftpFastGet(sftp: SFTPWrapper, remotePath: string, localPath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      sftp.fastGet(remotePath, localPath, { concurrency: 64, chunkSize: 131072 }, (err) => {
        if (err) { reject(err); return; }
        resolve(`Downloaded ${remotePath} -> ${localPath}`);
      });
    });
  }

  // ── Fast channel: parallel HTTP transfers via the fastd helper ──────────

  private async getRemoteHome(): Promise<string> {
    const { output } = await this.executeDirect('echo $HOME');
    const lines = output.split('\n').map((s) => s.trim()).filter(Boolean);
    return lines[lines.length - 1] || '/root';
  }

  private ensureFastChannel(): Promise<FastdState | null> {
    if (process.env.SSH_MCP_DISABLE_FAST_CHANNEL === '1') {
      return Promise.resolve(null);
    }
    if (this.fastd.status === 'ready') {
      return Promise.resolve(this.fastd);
    }
    if (this.fastd.status !== 'unchecked') {
      return Promise.resolve(null);
    }
    if (!this.fastdProbe) {
      this.fastdProbe = this.probeAndStartFastd().finally(() => {
        this.fastdProbe = null;
      });
    }
    return this.fastdProbe;
  }

  private async probeAndStartFastd(): Promise<FastdState | null> {
    try {
      const { output } = await this.executeDirect(
        // The shell may echo the typed command back, so the success/failure
        // marker is computed at runtime ($((100+1))) — its literal text never
        // appears in the command itself, making the match echo-proof.
        'command -v python3 >/dev/null 2>&1 && test -f "$HOME/.agent-ssh-mcp/fastd.py" && echo "FASTD_$((100+1))YES" || echo "FASTD_$((100+2))NO"'
      );
      if (!output.includes('FASTD_101YES')) {
        this.fastd = { status: 'no-helper' };
        return null;
      }
      this.fastd = await this.startFastd();
      return this.fastd.status === 'ready' ? this.fastd : null;
    } catch (err: any) {
      if (err?.message?.includes('still running')) {
        return null; // shell busy with another command — retry on next transfer
      }
      console.error(`fast channel setup failed for session ${this.id}, using SFTP: ${err?.message ?? err}`);
      this.fastd = { status: 'failed' };
      return null;
    }
  }

  private async startFastd(): Promise<FastdState> {
    const home = await this.getRemoteHome();
    const remoteDir = `${home}/.agent-ssh-mcp`;
    const token = randomUUID().replace(/-/g, '');
    // Start the helper detached; it picks a free port itself and writes it to
    // the port file once listening. pkill clears any stale helper first.
    const { output } = await this.executeDirect(
      `pkill -f 'agent-ssh-mcp/fastd.py' 2>/dev/null; rm -f "${remoteDir}/fastd.port"; ` +
      `OGOC_FASTD_TOKEN=${token} nohup python3 "${remoteDir}/fastd.py" --port 0 --port-file "${remoteDir}/fastd.port" --idle 1800 >/dev/null 2>&1 & echo FASTD_PID=$!`
    );
    const pidMatch = output.match(/FASTD_PID=(\d+)/);
    const pid = pidMatch ? parseInt(pidMatch[1], 10) : null;
    const sftp = await this.getSftp();
    let port = 0;
    for (let i = 0; i < 10 && !port; i++) {
      await sleep(250);
      try {
        const data: Buffer = await new Promise((resolve, reject) => {
          sftp.readFile(`${remoteDir}/fastd.port`, (err: any, buf: Buffer) => (err ? reject(err) : resolve(buf)));
        });
        port = parseInt(data.toString().trim(), 10) || 0;
      } catch { /* port file not written yet */ }
    }
    if (!port) {
      console.error(`fast channel helper did not report a port on session ${this.id}, using SFTP`);
      return { status: 'unreachable' };
    }

    // Opportunistic direct connection (LAN / unfiltered routes): the helper
    // binds an ephemeral token-gated port; try reaching it directly first so
    // transfers can use multiple independent TCP streams. No ports need to be
    // pre-opened by the user — if the direct route is blocked (firewall,
    // filtered transit), fall back to tunneling through the SSH connection.
    const host = this.config.host!;
    try {
      const res = await fetch(`http://${host}:${port}/stat?path=${encodeURIComponent('/etc/hostname')}`, {
        headers: { 'X-Fastd-Token': token },
        signal: abortAfter(4000),
      });
      if (res.ok) {
        console.error(`fast channel ready (direct): ${host}:${port}`);
        return { status: 'ready', mode: 'direct', baseUrl: `http://${host}:${port}`, token, pid, remoteDir };
      }
    } catch { /* direct route blocked — tunnel instead */ }

    // Tunnel fallback: reuse the SSH connection (no extra open ports). Each
    // HTTP connection is forwarded as its own channel, so parallel chunk
    // requests still get independent channel windows.
    const localServer = net.createServer((sock) => {
      this.conn?.forwardOut('127.0.0.1', sock.remotePort ?? 0, '127.0.0.1', port, (err, channel) => {
        if (err) { sock.destroy(); return; }
        sock.pipe(channel).pipe(sock);
        sock.on('error', () => channel.end());
        channel.on('error', () => sock.destroy());
      });
    });
    const localPort = await new Promise<number>((resolve, reject) => {
      localServer.once('error', reject);
      localServer.listen(0, '127.0.0.1', () => {
        const addr = localServer.address();
        resolve(typeof addr === 'object' && addr ? addr.port : 0);
      });
    });
    if (!localPort) {
      localServer.close();
      return { status: 'failed' };
    }
    // Sanity check through the tunnel
    try {
      const res = await fetch(`http://127.0.0.1:${localPort}/stat?path=${encodeURIComponent('/etc/hostname')}`, {
        headers: { 'X-Fastd-Token': token },
        signal: abortAfter(15000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (err: any) {
      localServer.close();
      console.error(`fast channel tunnel check failed on session ${this.id} (${err?.message ?? err}), using SFTP`);
      return { status: 'unreachable' };
    }
    console.error(`fast channel ready (tunnel via SSH): 127.0.0.1:${localPort} -> helper port ${port}`);
    return { status: 'ready', mode: 'tunnel', baseUrl: `http://127.0.0.1:${localPort}`, token, localServer, pid, remoteDir };
  }

  private async fastUpload(localPath: string, remotePath: string): Promise<{ bytes: number; ms: number }> {
    const st = this.fastd;
    if (st.status !== 'ready') throw new Error('fast channel not ready');
    const enc = encodeURIComponent;
    const headers = { 'X-Fastd-Token': st.token };
    const size = (await stat(localPath)).size;
    const t0 = Date.now();
    let res = await fetch(`${st.baseUrl}/truncate?path=${enc(remotePath)}&size=${size}`, {
      method: 'POST', headers, signal: abortAfter(30000),
    });
    if (!res.ok) throw new Error(`fastd truncate failed: HTTP ${res.status}`);
    const chunkCount = size === 0 ? 0 : Math.ceil(size / FAST_CHUNK);
    let nextChunk = 0;
    const fd = await openFileHandle(localPath, 'r');
    try {
      const worker = async (): Promise<void> => {
        for (;;) {
          const i = nextChunk++;
          if (i >= chunkCount) return;
          const start = i * FAST_CHUNK;
          const len = Math.min(FAST_CHUNK, size - start);
          const buf = Buffer.alloc(len);
          const { bytesRead } = await fd.read(buf, 0, len, start);
          if (bytesRead !== len) throw new Error(`short local read at offset ${start}`);
          const r = await fetch(`${st.baseUrl}/write?path=${enc(remotePath)}&offset=${start}`, {
            method: 'POST',
            headers: { ...headers, 'Content-Type': 'application/octet-stream' },
            body: buf,
            signal: abortAfter(300000),
          });
          if (!r.ok) throw new Error(`fastd write failed: HTTP ${r.status}`);
        }
      };
      await Promise.all(Array.from({ length: Math.min(FAST_CONCURRENCY, chunkCount) }, worker));
    } finally {
      await fd.close();
    }
    res = await fetch(`${st.baseUrl}/stat?path=${enc(remotePath)}`, { headers, signal: abortAfter(30000) });
    if (!res.ok) throw new Error(`fastd stat failed: HTTP ${res.status}`);
    const info = await res.json() as { size: number };
    if (info.size !== size) throw new Error(`fastd upload size mismatch: remote ${info.size} != local ${size}`);
    return { bytes: size, ms: Date.now() - t0 };
  }

  private async fastDownload(remotePath: string, localPath: string): Promise<{ bytes: number; ms: number }> {
    const st = this.fastd;
    if (st.status !== 'ready') throw new Error('fast channel not ready');
    const enc = encodeURIComponent;
    const headers = { 'X-Fastd-Token': st.token };
    const t0 = Date.now();
    const res = await fetch(`${st.baseUrl}/stat?path=${enc(remotePath)}`, { headers, signal: abortAfter(30000) });
    if (!res.ok) throw new Error(`fastd stat failed: HTTP ${res.status}`);
    const info = await res.json() as { size: number; isdir?: boolean };
    if (info.isdir) throw new Error('fast channel cannot download directories');
    const size = info.size;
    mkdirSync(dirname(localPath), { recursive: true });
    const fd = await openFileHandle(localPath, 'w');
    await fd.truncate(size);
    await fd.close();
    const chunkCount = size === 0 ? 0 : Math.ceil(size / FAST_CHUNK);
    let nextChunk = 0;
    const wfd = await openFileHandle(localPath, 'r+');
    try {
      const worker = async (): Promise<void> => {
        for (;;) {
          const i = nextChunk++;
          if (i >= chunkCount) return;
          const start = i * FAST_CHUNK;
          const end = Math.min(start + FAST_CHUNK, size) - 1;
          const r = await fetch(`${st.baseUrl}/read?path=${enc(remotePath)}`, {
            headers: { ...headers, Range: `bytes=${start}-${end}` },
            signal: abortAfter(300000),
          });
          if (!r.ok && r.status !== 206) throw new Error(`fastd read failed: HTTP ${r.status}`);
          const ab = await r.arrayBuffer();
          if (ab.byteLength !== end - start + 1) {
            throw new Error(`fastd short read at offset ${start}: got ${ab.byteLength}, want ${end - start + 1}`);
          }
          await wfd.write(Buffer.from(ab), 0, ab.byteLength, start);
        }
      };
      await Promise.all(Array.from({ length: Math.min(FAST_CONCURRENCY, chunkCount) }, worker));
    } finally {
      await wfd.close();
    }
    return { bytes: size, ms: Date.now() - t0 };
  }

  async installFastChannel(): Promise<string> {
    await this.ensureConnected();
    const sftp = await this.getSftp();
    const home = await this.getRemoteHome();
    const dir = `${home}/.agent-ssh-mcp`;
    await new Promise<void>((resolve, reject) => {
      sftp.mkdir(dir, (err: any) => (err && err.code !== 4 && err.code !== 2 ? reject(err) : resolve()));
    });
    await new Promise<void>((resolve, reject) => {
      sftp.writeFile(`${dir}/fastd.py`, FASTD_SCRIPT, (err: any) => (err ? reject(err) : resolve()));
    });
    // Same echo-proof marker trick as probeAndStartFastd
    const py = await this.executeDirect('command -v python3 >/dev/null 2>&1 && python3 -V 2>&1 || echo "__NO_$((100+3))PYTHON3"');
    if (py.output.includes('__NO_103PYTHON3')) {
      return `Helper script installed at ${dir}/fastd.py, but python3 is not available on this host. ` +
        'Install it with the distro package manager (apt install python3 / dnf install python3 / apk add python3 / pacman -S python) ' +
        'and call install-fast-channel again. Transfers will use SFTP until then.';
    }
    const chk = await this.executeDirect(`python3 -m py_compile "${dir}/fastd.py" && echo "SYNTAX_$((200+1))OK"`);
    if (!chk.output.includes('SYNTAX_201OK')) {
      throw new McpError(ErrorCode.InternalError, `fastd.py failed syntax check: ${chk.output}`);
    }
    this.fastd = { status: 'unchecked' }; // re-probe on the next transfer
    return `Fast channel helper installed at ${dir}/fastd.py (${py.output.trim()}). ` +
      'It is detected automatically on upload-file/download-file and started on demand; transfers fall back to SFTP if unreachable. ' +
      'Security note: while running, the helper binds 0.0.0.0 on an ephemeral port gated by a per-session random token and exits after 30 minutes idle.';
  }

  private stopFastd(): void {
    const st = this.fastd;
    if (st.status !== 'ready' || !st.pid || !this.conn) return;
    try {
      this.conn.exec(`kill ${st.pid} 2>/dev/null; rm -f "${st.remoteDir}/fastd.port"`, () => {});
    } catch { /* connection may already be gone */ }
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
    if (/<<\s*'?[A-Za-z_][A-Za-z0-9_]*'?/.test(command)) {
      return {
        output: '[ERROR] heredoc syntax (<<EOF) causes tmux sessions to hang. Use the write-remote-file tool to write file contents instead.',
        exitCode: 1,
      };
    }

    this.lastCommand = command;
    this.resetInactivityTimer();
    await this.executeDirect(`tmux clear-history -t ${this.tmuxSessionName}:0.0 2>/dev/null`);

    const token = randomUUID();
    const startMarker = `__MCP_START__${token}__`;
    const endMarker = `__MCP_DONE__${token}__`;

    const escapedCmd = command.replace(/'/g, "'\\''");
    const sendCmd = `echo ${startMarker}; ${escapedCmd}; echo ${endMarker}$?`;
    const sendResult = await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName}:0.0 '${sendCmd}' Enter`);
    if (sendResult.exitCode !== 0) {
      throw new Error(`tmux send-keys failed: ${sendResult.output}`);
    }

    // Persist markers so executeInteractiveInput can continue polling if we return -2
    this.tmuxPendingMarkers = { startMarker, endMarker, lastSnapshot: '' };

    const result = await this.pollForCompletion(startMarker, endMarker, 30000);
    if (result.exitCode === -2) {
      this.tmuxWaitingForInput = true;
      this.tmuxPendingMarkers.lastSnapshot = result.output;
    } else {
      this.tmuxPendingMarkers = null;
    }
    return result;
  }

  // Shared poll loop used by both executeViaTmux and executeInteractiveInput.
  // Returns exitCode -2 if an interactive prompt is detected (waiting for input),
  // exitCode -1 on timeout, or the real exit code on completion.
  private async pollForCompletion(
    startMarker: string,
    endMarker: string,
    maxWaitMs: number,
  ): Promise<{ output: string; exitCode: number }> {
    const pollIntervalMs = 300;
    const STABLE_THRESHOLD = 4;
    const startTime = Date.now();
    let pollCount = 0;
    let lastTail = '';
    let stablePollCount = 0;
    const startMarkerRe = new RegExp(`\\n${escapeRegex(startMarker)}\\n`);
    const endMarkerRe = new RegExp(`${escapeRegex(endMarker)}(\\d+)(?:\\n|$)`, 'm');

    while (Date.now() - startTime < maxWaitMs) {
      await new Promise(r => setTimeout(r, pollIntervalMs));
      pollCount++;

      const capResult = await this.executeDirect(`tmux capture-pane -t ${this.tmuxSessionName}:0.0 -p -S -200 2>&1`);
      if (capResult.exitCode !== 0 && pollCount <= 3) continue;
      if (capResult.exitCode !== 0) throw new Error(`tmux capture-pane failed: ${capResult.output}`);

      const pane = capResult.output;

      // End marker → command finished
      const endMatch = pane.match(endMarkerRe);
      if (endMatch) {
        const exitCode = parseInt(endMatch[1], 10);
        const endMarkerStart = endMatch.index!;
        const startMatch = pane.match(startMarkerRe);
        let cmdOutput: string;
        if (startMatch) {
          const afterStartMarker = startMatch.index! + 1 + startMatch[0].length - 1;
          cmdOutput = pane.slice(afterStartMarker, endMarkerStart);
        } else {
          cmdOutput = pane.slice(0, endMarkerStart);
        }
        this.tmuxPendingMarkers = null;
        this.tmuxWaitingForInput = false;
        return { output: cleanPaneOutput(cmdOutput), exitCode: Number.isNaN(exitCode) ? 0 : exitCode };
      }

      // Prompt detection: skip first 2 polls to let command start
      if (pollCount < 2) continue;

      // Check region after start marker if visible, otherwise the full pane
      const startMatch = pane.match(startMarkerRe);
      const region = startMatch
        ? pane.slice(startMatch.index! + 1 + startMatch[0].length - 1)
        : pane;
      const regionTrimmed = region.trim();

      if (regionTrimmed) {
        // Pattern: immediately recognisable interactive prompt
        if (INTERACTIVE_PROMPT_RE.test(regionTrimmed)) {
          return { output: cleanPaneOutput(region), exitCode: -2 };
        }
        // Stability: last few lines unchanged for STABLE_THRESHOLD polls,
        // AND last visible line must end with a prompt-like character.
        // This prevents false positives when a script pauses during network I/O.
        const cleanedRegion = cleanPaneOutput(region);
        const visibleLines = cleanedRegion.split('\n').filter(l => l.trim());
        const lastLine = visibleLines.at(-1) ?? '';
        const endsLikePrompt = /[?:>\]#$）)]\s*$/.test(lastLine) || /\[.*[yYnN/]\]\s*$/.test(lastLine);
        const tail = visibleLines.slice(-5).join('\n');
        if (tail && tail === lastTail && endsLikePrompt) {
          stablePollCount++;
          if (stablePollCount >= STABLE_THRESHOLD) {
            return { output: cleanedRegion, exitCode: -2 };
          }
        } else {
          stablePollCount = 0;
          lastTail = tail;
        }
      }
    }

    const { output: finalPane } = await this.executeDirect(`tmux capture-pane -t ${this.tmuxSessionName}:0.0 -p -S -200 2>&1`);
    return { output: cleanPaneOutput(finalPane), exitCode: -1 };
  }

  // Called instead of executeViaTmux when the session is in tmuxWaitingForInput state.
  // Sends raw keystrokes (no marker wrapping) and resumes polling for the original end marker.
  private async executeInteractiveInput(input: string): Promise<{ output: string; exitCode: number }> {
    this.tmuxWaitingForInput = false;
    const { startMarker, endMarker, lastSnapshot } = this.tmuxPendingMarkers!;

    this.lastCommand = input;
    this.resetInactivityTimer();

    // Pre-check: capture pane before sending to detect if state has already changed.
    const preCapture = await this.executeDirect(`tmux capture-pane -t ${this.tmuxSessionName}:0.0 -p -S -200 2>&1`);
    if (preCapture.exitCode === 0) {
      const endMarkerRe = new RegExp(`${escapeRegex(endMarker)}(\\d+)(?:\\n|$)`, 'm');
      const endMatch = preCapture.output.match(endMarkerRe);
      if (endMatch) {
        // Script already finished — return its result without sending our input
        const exitCode = parseInt(endMatch[1], 10);
        const startMarkerRe = new RegExp(`\\n${escapeRegex(startMarker)}\\n`);
        const startMatch = preCapture.output.match(startMarkerRe);
        const cmdOutput = startMatch
          ? preCapture.output.slice(startMatch.index! + 1 + startMatch[0].length - 1, endMatch.index!)
          : preCapture.output.slice(0, endMatch.index!);
        this.tmuxPendingMarkers = null;
        return { output: cleanPaneOutput(cmdOutput), exitCode: Number.isNaN(exitCode) ? 0 : exitCode };
      }

      // Check if pane content has drifted significantly from when -2 was returned.
      // If so, return the new state without sending — let the AI re-assess.
      const currentClean = cleanPaneOutput(preCapture.output);
      if (lastSnapshot && currentClean !== lastSnapshot) {
        // Find overlap: if the prompt text we saw is no longer in the pane, state has changed
        const snapshotLastLine = lastSnapshot.split('\n').filter(l => l.trim()).at(-1) ?? '';
        if (snapshotLastLine && !currentClean.includes(snapshotLastLine)) {
          this.tmuxWaitingForInput = true;
          this.tmuxPendingMarkers!.lastSnapshot = currentClean;
          return { output: `[State changed before input was sent. Current pane:]\n${currentClean}`, exitCode: -2 };
        }
      }
    }

    // State still matches — send raw input
    const escapedInput = input.replace(/'/g, "'\\''");
    const sendResult = await this.executeDirect(`tmux send-keys -t ${this.tmuxSessionName}:0.0 '${escapedInput}' Enter`);
    if (sendResult.exitCode !== 0) {
      throw new Error(`tmux send-keys failed: ${sendResult.output}`);
    }

    const result = await this.pollForCompletion(startMarker, endMarker, 30000);
    if (result.exitCode === -2) {
      this.tmuxWaitingForInput = true;
      this.tmuxPendingMarkers!.lastSnapshot = result.output;
    }
    return result;
  }

  forwardPort(localPort: number, remoteHost: string, remotePort: number, sockets: Set<net.Socket>): Promise<net.Server> {
    return new Promise((resolve, reject) => {
      if (!this.conn) {
        reject(new McpError(ErrorCode.InternalError, 'SSH connection not ready'));
        return;
      }
      const conn = this.conn;
      const tcpServer = net.createServer((localSocket) => {
        sockets.add(localSocket);
        localSocket.once('close', () => sockets.delete(localSocket));
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
    this.stopFastd();
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

    if (this.fastd.status === 'ready' && this.fastd.localServer) {
      this.fastd.localServer.close();
    }
    this.fastd = { status: 'unchecked' };

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