#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client as SSHClient, ConnectConfig } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// Example usage: node build/index.js --host=1.2.3.4 --port=22 --user=root --password=pass --key=path/to/key --timeout=5000
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string> = {};
  for (const arg of args) {
    const match = arg.match(/^--([^=]+)=(.*)$/);
    if (match) {
      config[match[1]] = match[2];
    }
  }
  return config;
}
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
const argvConfig = isCliEnabled ? parseArgv() : {} as Record<string, string>;

const DEFAULT_HOST = argvConfig.host;
const DEFAULT_PORT = (() => {
  if (typeof argvConfig.port === 'string') {
    const parsed = parseInt(argvConfig.port, 10);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }
  return 22;
})();
const DEFAULT_USERNAME = argvConfig.user;
const DEFAULT_PASSWORD = argvConfig.password;
const DEFAULT_KEY_PATH = argvConfig.key;
const DEFAULT_AGENT = argvConfig.agent;
const DEFAULT_TIMEOUT = (() => {
  if (typeof argvConfig.timeout === 'string') {
    const parsed = parseInt(argvConfig.timeout, 10);
    if (!Number.isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 60000; // 60 seconds default timeout
})();
let defaultPrivateKeyCache: string | null | undefined;

const envAllowListPath = process.env.SSH_MCP_ALLOWLIST;

function resolvePathFromCwd(filePath: string): string {
  return path.isAbsolute(filePath) ? filePath : path.resolve(process.cwd(), filePath);
}

const DEFAULT_ALLOWLIST_PATH = (() => {
  if (typeof argvConfig.allowlist === 'string' && argvConfig.allowlist.trim()) {
    return resolvePathFromCwd(argvConfig.allowlist.trim());
  }
  if (typeof envAllowListPath === 'string' && envAllowListPath.trim()) {
    return resolvePathFromCwd(envAllowListPath.trim());
  }
  return fileURLToPath(new URL('../config/command-allowlist.json', import.meta.url));
})();
// Max characters configuration:
// - Default: 1000 characters
// - When set via --maxChars:
//   * a positive integer enforces that limit
//   * 0 or a negative value disables the limit (no max)
//   * the string "none" (case-insensitive) disables the limit (no max)
const MAX_CHARS_RAW = argvConfig.maxChars;
const MAX_CHARS = (() => {
  if (typeof MAX_CHARS_RAW === 'string') {
    const lowered = MAX_CHARS_RAW.toLowerCase();
    if (lowered === 'none') return Infinity;
    const parsed = parseInt(MAX_CHARS_RAW);
    if (isNaN(parsed)) return 1000;
    if (parsed <= 0) return Infinity;
    return parsed;
  }
  return 1000;
})();

function validateConfig(config: Record<string, string>) {
  const errors: string[] = [];
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');
  if (config.timeout && isNaN(Number(config.timeout))) errors.push('Invalid --timeout');
  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (isCliEnabled) {
  validateConfig(argvConfig);
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
  if (Number.isFinite(MAX_CHARS) && trimmedCommand.length > (MAX_CHARS as number)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Command is too long (max ${MAX_CHARS} characters)`
    );
  }
  
  return trimmedCommand;
}

// Escape command for use in shell contexts (like pkill)
export function escapeCommandForShell(command: string): string {
  // Replace single quotes with escaped single quotes
  return command.replace(/'/g, "'\"'\"'");
}

type ResolvedSshConfig = Omit<ConnectConfig, 'agent'> & {
  host: string;
  port: number;
  username: string;
  agent?: string;
};

type ResolveConfigInput = {
  host?: string;
  port?: number;
  username?: string;
  password?: string;
  privateKey?: string;
  privateKeyPath?: string;
  passphrase?: string;
  agent?: string;
};

async function readPrivateKeyFromPath(filePath: string): Promise<string> {
  try {
    return await readFile(filePath, 'utf8');
  } catch (error: any) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Unable to read private key from path \"${filePath}\": ${error?.message || error}`
    );
  }
}

async function loadDefaultPrivateKey(): Promise<string | null> {
  if (defaultPrivateKeyCache !== undefined) {
    return defaultPrivateKeyCache;
  }
  if (!DEFAULT_KEY_PATH) {
    defaultPrivateKeyCache = null;
    return null;
  }
  try {
    defaultPrivateKeyCache = await readFile(DEFAULT_KEY_PATH, 'utf8');
    return defaultPrivateKeyCache;
  } catch (error: any) {
    defaultPrivateKeyCache = null;
    throw new McpError(
      ErrorCode.InvalidParams,
      `Unable to read default private key from path \"${DEFAULT_KEY_PATH}\": ${error?.message || error}`
    );
  }
}

export async function resolveSshConfig(input: ResolveConfigInput): Promise<ResolvedSshConfig> {
  const host = input.host ?? DEFAULT_HOST;
  if (!host) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Host must be provided either via tool input or --host'
    );
  }

  if (host.includes('@')) {
    const segments = host.split('@');
    if (segments.length >= 2) {
      const suspectedUser = segments[0]?.trim();
      const suspectedHost = segments.slice(1).join('@').trim();
      if (suspectedUser && suspectedHost) {
        const guidanceUsername = input.username ?? DEFAULT_USERNAME;
        const hint = guidanceUsername
          ? `Set "host" to "${suspectedHost}" (without the username) and keep the username separate.`
          : `Provide the username using the "username" parameter (for example: "${suspectedUser}") and set "host" to "${suspectedHost}".`;
        throw new McpError(
          ErrorCode.InvalidParams,
          `Host value "${host}" appears to include a username. ${hint}`
        );
      }
    }
  }

  const username = input.username ?? DEFAULT_USERNAME;
  if (!username) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Username must be provided via the "username" parameter or the --user CLI flag (for example: "root").'
    );
  }

  const port = input.port ?? DEFAULT_PORT;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new McpError(ErrorCode.InvalidParams, 'Port must be an integer between 1 and 65535');
  }

  const config: ResolvedSshConfig = { host, port, username };

  const password = input.password ?? DEFAULT_PASSWORD;
  if (password) {
    config.password = password;
  }

  let privateKey = input.privateKey;
  if (!privateKey && input.privateKeyPath) {
    privateKey = await readPrivateKeyFromPath(input.privateKeyPath);
  }
  if (!privateKey && !password) {
    const defaultKey = await loadDefaultPrivateKey();
    if (defaultKey) {
      privateKey = defaultKey;
    }
  }
  if (privateKey) {
    config.privateKey = privateKey;
  }

  if (input.passphrase) {
    config.passphrase = input.passphrase;
  }

  const agent = input.agent ?? DEFAULT_AGENT;
  if (agent) {
    config.agent = agent;
  }

  return config;
}

type AllowListEntry = {
  pattern: string;
  regex: RegExp;
};

let allowListEntriesCache: AllowListEntry[] | null = null;
let allowListLoadPromise: Promise<AllowListEntry[]> | null = null;
let allowListOverride: AllowListEntry[] | null = null;

function normalizeCommandForMatching(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

function escapeRegExpChar(char: string): string {
  return char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function compileAllowListPattern(pattern: string): AllowListEntry {
  const trimmed = pattern.trim();
  if (!trimmed) {
    throw new McpError(ErrorCode.InvalidParams, 'Allowlist patterns cannot be empty');
  }

  const normalized = normalizeCommandForMatching(trimmed);
  let regexBody = '';
  for (const char of normalized) {
    if (char === '*') {
      regexBody += '.*';
    } else if (char === ' ') {
      regexBody += '\\s+';
    } else {
      regexBody += escapeRegExpChar(char);
    }
  }

  return {
    pattern: trimmed,
    regex: new RegExp(`^${regexBody}$`),
  };
}

async function loadAllowListFromFile(filePath: string): Promise<AllowListEntry[]> {
  try {
    const raw = await readFile(filePath, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Failed to parse allowlist configuration at "${filePath}": ${error?.message || error}`
      );
    }

    if (!Array.isArray(parsed)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Allowlist configuration at "${filePath}" must be an array of patterns`
      );
    }

    return parsed.map((item, index) => {
      if (typeof item !== 'string') {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Allowlist entry at index ${index} must be a string`
        );
      }
      return compileAllowListPattern(item);
    });
  } catch (error: any) {
    if (error instanceof McpError) {
      throw error;
    }
    throw new McpError(
      ErrorCode.InvalidParams,
      `Unable to load allowlist configuration from "${filePath}": ${error?.message || error}`
    );
  }
}

async function getAllowListEntries(): Promise<AllowListEntry[]> {
  if (allowListOverride) {
    return allowListOverride;
  }
  if (allowListEntriesCache) {
    return allowListEntriesCache;
  }
  if (!allowListLoadPromise) {
    allowListLoadPromise = loadAllowListFromFile(DEFAULT_ALLOWLIST_PATH)
      .then((entries) => {
        allowListEntriesCache = entries;
        allowListLoadPromise = null;
        return entries;
      })
      .catch((error) => {
        allowListLoadPromise = null;
        throw error;
      });
  }
  return allowListLoadPromise;
}

function extractSegmentsForAllowList(command: string): string[] {
  if (command.includes('\n') || command.includes('\r')) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot contain newline characters');
  }

  const segments: string[] = [];
  let current: string[] = [];
  let inSingle = false;
  let inDouble = false;
  const length = command.length;

  const flushSegment = () => {
    const segment = normalizeCommandForMatching(current.join(''));
    if (!segment) {
      throw new McpError(ErrorCode.InvalidParams, 'Command segment cannot be empty');
    }
    segments.push(segment);
    current = [];
  };

  let i = 0;
  while (i < length) {
    const ch = command[i];
    const nextTwo = command.slice(i, i + 2);

    if (!inSingle && !inDouble) {
      if (nextTwo === '&&') {
        throw new McpError(ErrorCode.InvalidParams, 'Command chaining with && is not allowed');
      }
      if (nextTwo === '||') {
        throw new McpError(ErrorCode.InvalidParams, 'Command chaining with || is not allowed');
      }
      if (ch === ';') {
        throw new McpError(ErrorCode.InvalidParams, 'Semicolons are not allowed in commands');
      }
      if (ch === '&') {
        throw new McpError(ErrorCode.InvalidParams, 'Ampersands are not allowed in commands');
      }
      if (ch === '`') {
        throw new McpError(ErrorCode.InvalidParams, 'Backticks are not allowed in commands');
      }
      if (ch === '$' && command[i + 1] === '(') {
        throw new McpError(ErrorCode.InvalidParams, 'Command substitution with $() is not allowed');
      }
      if (ch === '<') {
        throw new McpError(ErrorCode.InvalidParams, 'Input redirection (<) is not allowed');
      }

      if (ch === '|') {
        flushSegment();
        i++;
        continue;
      }

      if (ch === '>') {
        // Remove trailing whitespace
        while (current.length > 0 && /\s/.test(current[current.length - 1])) {
          current.pop();
        }
        // Remove trailing file descriptor digits
        while (current.length > 0 && /[0-9]/.test(current[current.length - 1])) {
          current.pop();
        }

        i++;
        if (command[i] === '>') {
          i++;
        }

        while (i < length && /\s/.test(command[i])) {
          i++;
        }
        if (i >= length) {
          throw new McpError(ErrorCode.InvalidParams, 'Redirection is missing a /tmp target');
        }

        let target = '';
        if (command[i] === '"' || command[i] === '\'') {
          const quoteChar = command[i];
          i++;
          while (i < length && command[i] !== quoteChar) {
            if (quoteChar === '"' && command[i] === '\\' && i + 1 < length) {
              target += command[i + 1];
              i += 2;
              continue;
            }
            target += command[i];
            i++;
          }
          if (i >= length) {
            throw new McpError(ErrorCode.InvalidParams, 'Unterminated quoted path in redirection');
          }
          i++;
        } else {
          while (i < length && !/\s|[|;]/.test(command[i])) {
            target += command[i];
            i++;
          }
        }

        const normalizedTarget = target.trim();
        if (!normalizedTarget) {
          throw new McpError(ErrorCode.InvalidParams, 'Redirection target cannot be empty');
        }
        if (!normalizedTarget.startsWith('/tmp/')) {
          throw new McpError(ErrorCode.InvalidParams, `Redirection target "${normalizedTarget}" must be under /tmp`);
        }

        let peek = i;
        while (peek < length && /\s/.test(command[peek])) {
          peek++;
        }
        if (peek < length && command[peek] !== '|') {
          throw new McpError(ErrorCode.InvalidParams, 'Only whitespace or a pipe may follow a redirection target');
        }
        i = peek;
        continue;
      }
    }

    if (ch === '\'' && !inDouble) {
      inSingle = !inSingle;
      current.push(ch);
      i++;
      continue;
    }

    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current.push(ch);
      i++;
      continue;
    }

    current.push(ch);
    i++;
  }

  if (inSingle || inDouble) {
    throw new McpError(ErrorCode.InvalidParams, 'Command contains unterminated quotes');
  }

  flushSegment();

  return segments;
}

export async function ensureCommandAllowed(command: string): Promise<void> {
  const segments = extractSegmentsForAllowList(command);
  const entries = await getAllowListEntries();

  for (const segment of segments) {
    const isAllowed = entries.some((entry) => entry.regex.test(segment));
    if (!isAllowed) {
      const allowedPatterns = entries.map((entry) => `- ${entry.pattern}`).join('\n');
      throw new McpError(
        ErrorCode.InvalidParams,
        `Command segment "${segment}" is not permitted by the allowlist. Allowed commands:\n${allowedPatterns}`
      );
    }
  }
}

export function __setAllowListForTesting(patterns: string[] | null): void {
  if (patterns === null) {
    allowListOverride = null;
    allowListEntriesCache = null;
    allowListLoadPromise = null;
    return;
  }
  allowListOverride = patterns.map((pattern) => compileAllowListPattern(pattern));
}

function credentialFingerprint(config: Pick<ResolvedSshConfig, 'password' | 'privateKey' | 'passphrase' | 'agent'>): string {
  const hash = createHash('sha256');
  hash.update(config.password ?? '');
  hash.update(config.privateKey ?? '');
  hash.update(config.passphrase ?? '');
  if (config.agent) {
    hash.update(config.agent);
  }
  return hash.digest('hex');
}

function parseOptionalInteger(
  value: number | string | undefined,
  fieldName: string,
  { min, max }: { min?: number; max?: number } = {}
): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  const parsed = typeof value === 'number' ? value : parseInt(value, 10);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) {
    throw new McpError(ErrorCode.InvalidParams, `${fieldName} must be an integer value`);
  }

  if (typeof min === 'number' && parsed < min) {
    throw new McpError(ErrorCode.InvalidParams, `${fieldName} must be >= ${min}`);
  }

  if (typeof max === 'number' && parsed > max) {
    throw new McpError(ErrorCode.InvalidParams, `${fieldName} must be <= ${max}`);
  }

  return parsed;
}

// SSH Connection Manager to maintain persistent connection
export class SSHConnectionManager {
  private conn: SSHClient | null = null;
  private sshConfig: ResolvedSshConfig;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;

  constructor(config: ResolvedSshConfig) {
    this.sshConfig = config;
  }

  async connect(): Promise<void> {
    if (this.conn && this.isConnected()) {
      return; // Already connected
    }

    if (this.isConnecting && this.connectionPromise) {
      return this.connectionPromise; // Wait for ongoing connection
    }

    this.isConnecting = true;
    this.connectionPromise = new Promise((resolve, reject) => {
      this.conn = new SSHClient();
      
      const timeoutId = setTimeout(() => {
        this.conn?.end();
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'SSH connection timeout'));
      }, 30000); // 30 seconds connection timeout

      this.conn.on('ready', () => {
        clearTimeout(timeoutId);
        this.isConnecting = false;
        console.error('SSH connection established');
        resolve();
      });

      this.conn.on('error', (err) => {
        clearTimeout(timeoutId);
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      });

      this.conn.on('end', () => {
        console.error('SSH connection ended');
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.on('close', () => {
        console.error('SSH connection closed');
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.connect(this.sshConfig);
    });

    return this.connectionPromise;
  }

  isConnected(): boolean {
    return this.conn !== null && (this.conn as any)._sock && !(this.conn as any)._sock.destroyed;
  }

  async ensureConnected(): Promise<void> {
    if (!this.isConnected()) {
      await this.connect();
    }
  }

  getConnection(): SSHClient {
    if (!this.conn) {
      throw new McpError(ErrorCode.InternalError, 'SSH connection not established');
    }
    return this.conn;
  }

  close(): void {
    if (this.conn) {
      this.conn.end();
      this.conn = null;
    }
  }
}

type ManagerEntry = {
  manager: SSHConnectionManager;
  fingerprint: string;
};

const connectionManagers = new Map<string, ManagerEntry>();

function getConnectionKey(config: ResolvedSshConfig): string {
  return `${config.username}@${config.host}:${config.port}`;
}

function getOrCreateConnectionManager(config: ResolvedSshConfig): SSHConnectionManager {
  const key = getConnectionKey(config);
  const fingerprint = credentialFingerprint(config);
  const existing = connectionManagers.get(key);

  if (existing) {
    if (existing.fingerprint === fingerprint) {
      return existing.manager;
    }

    // Credentials changed for this host/user combo; replace the existing manager
    existing.manager.close();
    connectionManagers.delete(key);
  }

  const manager = new SSHConnectionManager(config);
  connectionManagers.set(key, { manager, fingerprint });
  return manager;
}

function closeAllConnectionManagers(): void {
  for (const { manager } of connectionManagers.values()) {
    manager.close();
  }
  connectionManagers.clear();
}

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '1.2.0',
  capabilities: {
    resources: {},
    tools: {},
  },
});

server.tool(
  "exec",
  "Execute a shell command on the remote SSH server and return the output.",
  {
    command: z.string().describe("Shell command to execute on the remote SSH server"),
    host: z.string().min(1).describe("Hostname or IP address of the SSH server").optional(),
    port: z.union([z.number().int(), z.string().regex(/^\d+$/)]).describe("Port number for the SSH server").optional(),
    username: z.string().min(1).describe("Username for SSH authentication").optional(),
    password: z.string().describe("Password for SSH authentication").optional(),
    privateKey: z.string().describe("PEM-encoded private key contents for SSH authentication").optional(),
    privateKeyPath: z.string().describe("Path on the MCP server to a PEM-encoded private key").optional(),
    passphrase: z.string().describe("Passphrase for the provided private key, if required").optional(),
    agent: z.string().describe("Path to an SSH agent socket (e.g., SSH_AUTH_SOCK)").optional(),
    timeoutMs: z.union([z.number().int(), z.string().regex(/^\d+$/)]).describe("Execution timeout in milliseconds").optional(),
    reuseConnection: z.boolean().describe("Reuse a persistent SSH connection when available").optional(),
  },
  async (input) => {
    const {
      command,
      host,
      port,
      username,
      password,
      privateKey,
      privateKeyPath,
      passphrase,
      agent,
      timeoutMs,
      reuseConnection,
    } = input;

    // Sanitize command input
    const sanitizedCommand = sanitizeCommand(command);
    await ensureCommandAllowed(sanitizedCommand);

    try {
      const parsedPort = parseOptionalInteger(port as any, 'port', { min: 1, max: 65535 });
      const parsedTimeout = parseOptionalInteger(timeoutMs as any, 'timeoutMs', { min: 1 });

      const sshConfig = await resolveSshConfig({
        host,
        port: parsedPort,
        username,
        password,
        privateKey,
        privateKeyPath,
        passphrase,
        agent,
      });

      const effectiveTimeout = parsedTimeout ?? DEFAULT_TIMEOUT;
      const shouldReuseConnection = reuseConnection !== false;

      if (shouldReuseConnection) {
        const manager = getOrCreateConnectionManager(sshConfig);
        await manager.ensureConnected();
        return await execSshCommandWithConnection(manager, sanitizedCommand, effectiveTimeout);
      }

      return await execSshCommand(sshConfig, sanitizedCommand, effectiveTimeout);
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// New function that uses persistent connection
export async function execSshCommandWithConnection(
  manager: SSHConnectionManager,
  command: string,
  timeoutMs: number = DEFAULT_TIMEOUT
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  const sanitizedCommand = sanitizeCommand(command);
  await ensureCommandAllowed(sanitizedCommand);
  return new Promise((resolve, reject) => {
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;
    
    const conn = manager.getConnection();

    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        // Try to abort the running command
        const abortTimeout = setTimeout(() => {
          // If abort command itself times out, we'll just reject
        }, 5000);
        
        conn.exec("timeout 3s pkill -f '" + escapeCommandForShell(sanitizedCommand) + "' 2>/dev/null || true", (err, abortStream) => {
          if (abortStream) {
            abortStream.on('close', () => {
              clearTimeout(abortTimeout);
            });
          } else {
            clearTimeout(abortTimeout);
          }
        });
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);
    
    conn.exec(sanitizedCommand, (err, stream) => {
      if (err) {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
        }
        return;
      }
      let stdout = '';
      let stderr = '';
      stream.on('close', (code: number, signal: string) => {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          if (stderr) {
            reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
          } else {
            resolve({
              content: [{
                type: 'text',
                text: stdout,
              }],
            });
          }
        }
      });
      stream.on('data', (data: Buffer) => {
        stdout += data.toString();
      });
      stream.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });
    });
  });
}

// Keep the old function for backward compatibility (used in tests)
export async function execSshCommand(
  sshConfig: any,
  command: string,
  timeoutMs: number = DEFAULT_TIMEOUT
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  const sanitizedCommand = sanitizeCommand(command);
  await ensureCommandAllowed(sanitizedCommand);
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;
    
    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        // Try to abort the running command before closing connection
        const abortTimeout = setTimeout(() => {
          // If abort command itself times out, force close connection
          conn.end();
        }, 5000); // 5 second timeout for abort command
        
        conn.exec("timeout 3s pkill -f '" + escapeCommandForShell(sanitizedCommand) + "' 2>/dev/null || true", (err, abortStream) => {
          if (abortStream) {
            abortStream.on('close', () => {
              clearTimeout(abortTimeout);
              conn.end();
            });
          } else {
            clearTimeout(abortTimeout);
            conn.end();
          }
        });
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);
    
    conn.on('ready', () => {
      conn.exec(sanitizedCommand, (err, stream) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
          }
          conn.end();
          return;
        }
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number, signal: string) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            if (stderr) {
              reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
            } else {
              resolve({
                content: [{
                  type: 'text',
                  text: stdout,
                }],
              });
            }
          }
        });
        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
      });
    });
    conn.on('error', (err) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      }
    });
    conn.connect(sshConfig);
  });
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SSH MCP Server running on stdio");

  // Handle graceful shutdown
  const cleanup = () => {
    console.error("Shutting down SSH MCP Server...");
    closeAllConnectionManagers();
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    closeAllConnectionManagers();
  });
}

if (process.env.SSH_MCP_DISABLE_MAIN !== '1') {
  main().catch((error) => {
    console.error("Fatal error in main():", error);
    closeAllConnectionManagers();
    process.exit(1);
  });
}

export { parseArgv, validateConfig };
