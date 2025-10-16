#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client as SSHClient, ConnectConfig } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from 'http';
import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import path from 'path';
import os from 'os';
import { parse as parseSshConfig } from 'ssh-config';
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

function getArgValue(config: Record<string, string>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(config, key)) {
      const value = config[key];
      if (typeof value === 'string' && value.length > 0) {
        return value;
      }
    }
  }
  return undefined;
}

function parseOptionalBoolean(value: string | undefined, fieldLabel: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }

  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }

  throw new Error(`${fieldLabel} must be one of: true, false, 1, 0, yes, no, on, off`);
}

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
const DEFAULT_KEY_PATH = argvConfig.key ? resolvePathFromCwd(argvConfig.key) : undefined;
const DEFAULT_AGENT = argvConfig.agent;
const DEFAULT_PROXY_HOST = argvConfig.proxyHost;
const DEFAULT_PROXY_PORT = (() => {
  if (typeof argvConfig.proxyPort === 'string') {
    const parsed = parseInt(argvConfig.proxyPort, 10);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }
  return undefined;
})();
const DEFAULT_PROXY_USERNAME = argvConfig.proxyUser;
const DEFAULT_PROXY_PASSWORD = argvConfig.proxyPassword;
const DEFAULT_PROXY_KEY_PATH = argvConfig.proxyKey ? resolvePathFromCwd(argvConfig.proxyKey) : undefined;
const DEFAULT_PROXY_PASSPHRASE = argvConfig.proxyPassphrase;
const DEFAULT_PROXY_AGENT = argvConfig.proxyAgent;
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
let defaultProxyPrivateKeyCache: string | null | undefined;
let sshConfigCache: any | null | undefined;
let sshConfigLoadPromise: Promise<any | null> | null = null;
let sshConfigFilePath: string | null = null;

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
  const httpPortRaw = getArgValue(config, 'httpPort', 'http-port');
  if (httpPortRaw !== undefined) {
    const parsed = Number(httpPortRaw);
    if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65535) {
      errors.push('Invalid --httpPort (must be an integer between 1 and 65535)');
    }
  }

  const transportRaw = getArgValue(config, 'transport', 'mode');
  if (transportRaw) {
    const normalized = transportRaw.toLowerCase();
    if (normalized !== 'stdio' && normalized !== 'http') {
      errors.push('Invalid --transport (expected "stdio" or "http")');
    }
  }

  const booleanArgs: Array<{ key: string; label: string }> = [
    { key: 'http', label: '--http' },
    { key: 'httpEnabled', label: '--httpEnabled' },
    { key: 'enableHttp', label: '--enableHttp' },
    { key: 'disableStdio', label: '--disableStdio' },
    { key: 'stdioDisabled', label: '--stdioDisabled' },
    { key: 'noStdio', label: '--noStdio' },
  ];

  for (const { key, label } of booleanArgs) {
    if (config[key] !== undefined) {
      try {
        parseOptionalBoolean(config[key], label);
      } catch (err: any) {
        errors.push(err?.message || `${label} has an invalid value`);
      }
    }
  }

  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (isCliEnabled) {
  validateConfig(argvConfig);
}

const transportRaw = getArgValue(argvConfig, 'transport', 'mode');
const httpFlagRaw = getArgValue(argvConfig, 'http', 'httpEnabled', 'enableHttp');
const disableStdioRaw = getArgValue(argvConfig, 'disableStdio', 'stdioDisabled', 'noStdio');
const httpPortRaw = getArgValue(argvConfig, 'httpPort', 'http-port');
const httpHostRaw = getArgValue(argvConfig, 'httpHost', 'http-host');

const parsedHttpFlag = parseOptionalBoolean(httpFlagRaw, '--http');
const parsedDisableStdio = parseOptionalBoolean(disableStdioRaw, '--disableStdio');

const TRANSPORT_MODE: 'stdio' | 'http' = (() => {
  if (transportRaw) {
    const normalized = transportRaw.toLowerCase();
    if (normalized === 'http' || normalized === 'stdio') {
      return normalized;
    }
  }

  if (parsedDisableStdio === true) {
    return 'http';
  }

  if (parsedHttpFlag === true) {
    return 'http';
  }

  if (httpPortRaw !== undefined) {
    return 'http';
  }

  return 'stdio';
})();

const HTTP_PORT = (() => {
  if (httpPortRaw !== undefined) {
    return parseInt(httpPortRaw, 10);
  }
  return 3000;
})();

const HTTP_HOST = httpHostRaw ?? '0.0.0.0';

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
  proxyJump?: ResolvedProxyConfig | null;
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
  proxyJump?: ResolveProxyInput;
};

type ResolveProxyInput = {
  host?: string;
  port?: number;
  username?: string;
  password?: string;
  privateKey?: string;
  privateKeyPath?: string;
  passphrase?: string;
  agent?: string;
};

type ResolvedProxyConfig = {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
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
      `Unable to read default private key from path "${DEFAULT_KEY_PATH}": ${error?.message || error}`
    );
  }
}

async function loadDefaultProxyPrivateKey(): Promise<string | null> {
  if (defaultProxyPrivateKeyCache !== undefined) {
    return defaultProxyPrivateKeyCache;
  }
  if (!DEFAULT_PROXY_KEY_PATH) {
    defaultProxyPrivateKeyCache = null;
    return null;
  }
  try {
    defaultProxyPrivateKeyCache = await readFile(DEFAULT_PROXY_KEY_PATH, 'utf8');
    return defaultProxyPrivateKeyCache;
  } catch (error: any) {
    defaultProxyPrivateKeyCache = null;
    throw new McpError(
      ErrorCode.InvalidParams,
      `Unable to read default proxy private key from path "${DEFAULT_PROXY_KEY_PATH}": ${error?.message || error}`
    );
  }
}

function mergeProxyInputs(base?: ResolveProxyInput, override?: ResolveProxyInput): ResolveProxyInput | undefined {
  if (!base && !override) {
    return undefined;
  }
  const merged: ResolveProxyInput = { ...(base ?? {}) };
  if (override) {
    for (const key of Object.keys(override) as (keyof ResolveProxyInput)[]) {
      const value = override[key];
      if (value !== undefined) {
        (merged as any)[key] = value;
      }
    }
  }
  return merged;
}

async function loadSshConfig(): Promise<any | null> {
  if (sshConfigCache !== undefined) {
    return sshConfigCache;
  }

  if (!sshConfigLoadPromise) {
    sshConfigLoadPromise = (async () => {
      const overridePath = process.env.SSH_MCP_SSH_CONFIG_PATH;
      const configPath = overridePath
        ? (path.isAbsolute(overridePath) ? overridePath : path.resolve(process.cwd(), overridePath))
        : path.join(os.homedir(), '.ssh', 'config');
      try {
        const content = await readFile(configPath, 'utf8');
        sshConfigFilePath = configPath;
        return parseSshConfig(content);
      } catch (error: any) {
        if (error?.code !== 'ENOENT') {
          console.warn(`Unable to read SSH config at ${configPath}: ${error?.message || error}`);
        }
        return null;
      }
    })();
  }

  try {
    sshConfigCache = await sshConfigLoadPromise;
  } finally {
    sshConfigLoadPromise = null;
  }
  return sshConfigCache;
}

async function getSshConfigEntry(host: string): Promise<any | null> {
  const config = await loadSshConfig();
  if (!config) {
    return null;
  }
  try {
    const entry = config.compute(host);
    if (!entry) {
      return null;
    }
    return entry;
  } catch {
    return null;
  }
}

function getSshConfigValue(entry: any, key: string): any {
  if (!entry) {
    return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(entry, key)) {
    return entry[key];
  }
  const lowerKey = key.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(entry, lowerKey)) {
    return entry[lowerKey];
  }
  const upperKey = key.toUpperCase();
  if (Object.prototype.hasOwnProperty.call(entry, upperKey)) {
    return entry[upperKey];
  }
  return undefined;
}

function getFirstStringValue(entry: any, key: string): string | undefined {
  const value = getSshConfigValue(entry, key);
  if (Array.isArray(value)) {
    return value.length ? String(value[0]) : undefined;
  }
  if (value !== undefined) {
    return String(value);
  }
  return undefined;
}

function getStringArrayValue(entry: any, key: string): string[] {
  const value = getSshConfigValue(entry, key);
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.map((item) => String(item));
  }
  return [String(value)];
}

function resolveSshConfigPath(value: string, host: string, username?: string): string {
  let resolved = value.replace(/%h/g, host);
  if (username) {
    resolved = resolved.replace(/%u/g, username);
  }
  if (resolved.startsWith('~')) {
    resolved = path.join(os.homedir(), resolved.slice(1));
  } else if (!path.isAbsolute(resolved) && sshConfigFilePath && /[\\/]/.test(resolved)) {
    resolved = path.resolve(path.dirname(sshConfigFilePath), resolved);
  }
  return resolved;
}

function parseProxyJumpSpec(spec: string): { host: string; username?: string; port?: number } {
  const trimmed = spec.trim();
  const match = trimmed.match(/^(?:(?<user>[^@]+)@)?(?<host>[^:@]+)(?::(?<port>\d+))?$/);
  if (!match || !match.groups?.host) {
    throw new McpError(ErrorCode.InvalidParams, `Unable to parse ProxyJump directive: "${spec}"`);
  }
  const port = match.groups.port ? parseInt(match.groups.port, 10) : undefined;
  return {
    host: match.groups.host,
    username: match.groups.user || undefined,
    port: Number.isFinite(port) ? port : undefined,
  };
}

async function deriveProxyJumpFromConfig(hostAlias: string, entry: any): Promise<ResolveProxyInput | undefined> {
  const proxyJumpValue = getSshConfigValue(entry, 'ProxyJump');
  if (!proxyJumpValue) {
    return undefined;
  }
  const valueList = Array.isArray(proxyJumpValue) ? proxyJumpValue : [proxyJumpValue];
  const first = valueList.find((item: string) => typeof item === 'string' && item.trim().length > 0);
  if (!first) {
    return undefined;
  }

  const spec = String(first).split(',')[0]!.trim();
  if (!spec) {
    return undefined;
  }

  const parsed = parseProxyJumpSpec(spec);
  let proxyHost = parsed.host;
  let proxyUsername = parsed.username;
  let proxyPort = parsed.port;

  const proxyEntry = await getSshConfigEntry(proxyHost);
  if (proxyEntry) {
    const hostName = getFirstStringValue(proxyEntry, 'HostName');
    if (hostName) {
      proxyHost = hostName;
    }
    if (!proxyUsername) {
      const proxyUser = getFirstStringValue(proxyEntry, 'User');
      if (proxyUser) {
        proxyUsername = proxyUser;
      }
    }
    if (!proxyPort) {
      const proxyPortValue = getFirstStringValue(proxyEntry, 'Port');
      if (proxyPortValue) {
        const parsedPort = parseInt(proxyPortValue, 10);
        if (!Number.isNaN(parsedPort)) {
          proxyPort = parsedPort;
        }
      }
    }
    const identityFiles = getStringArrayValue(proxyEntry, 'IdentityFile');
    const identityFile = identityFiles.length ? identityFiles[0] : undefined;
    const identityAgent = getFirstStringValue(proxyEntry, 'IdentityAgent');
    if (getSshConfigValue(proxyEntry, 'ProxyJump')) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Nested ProxyJump directives are not supported (encountered for proxy host "${parsed.host}")`
      );
    }

    const proxyInput: ResolveProxyInput = {
      host: proxyHost,
      username: proxyUsername,
      port: proxyPort,
    };

    if (identityFile) {
      proxyInput.privateKeyPath = resolveSshConfigPath(identityFile, proxyHost, proxyUsername);
    }

    if (identityAgent) {
      proxyInput.agent = resolveSshConfigPath(identityAgent, proxyHost, proxyUsername);
    }

    return proxyInput;
  }

  return {
    host: proxyHost,
    username: proxyUsername,
    port: proxyPort,
  };
}

export function __resetSshConfigCacheForTesting(): void {
  sshConfigCache = undefined;
  sshConfigLoadPromise = null;
  sshConfigFilePath = null;
}

async function resolveProxyConfig(input?: ResolveProxyInput): Promise<ResolvedProxyConfig | null> {
  const candidateHost = input?.host ?? DEFAULT_PROXY_HOST;
  if (!candidateHost) {
    return null;
  }

  if (candidateHost.includes('@')) {
    const segments = candidateHost.split('@');
    if (segments.length >= 2) {
      const suspectedUser = segments[0]?.trim();
      const suspectedHost = segments.slice(1).join('@').trim();
      if (suspectedUser && suspectedHost) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Proxy host value "${candidateHost}" appears to include a username. Provide the username via "proxyJump.username" (for example: "${suspectedUser}") and host as "${suspectedHost}".`
        );
      }
    }
  }

  const portValue = input?.port ?? DEFAULT_PROXY_PORT;
  const port = parseOptionalInteger(portValue as any, 'proxyJump.port', { min: 1, max: 65535 }) ?? 22;

  const username = input?.username ?? DEFAULT_PROXY_USERNAME;
  if (!username) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Proxy username must be provided via "proxyJump.username" or the --proxyUser CLI flag.'
    );
  }

  const password = input?.password ?? DEFAULT_PROXY_PASSWORD;

  let privateKey: string | null | undefined = input?.privateKey ?? null;
  const privateKeyPath = input?.privateKeyPath
    ? resolvePathFromCwd(input.privateKeyPath)
    : DEFAULT_PROXY_KEY_PATH;

  if (!privateKey && privateKeyPath) {
    if (input?.privateKeyPath) {
      privateKey = await readPrivateKeyFromPath(privateKeyPath);
    } else {
      privateKey = await loadDefaultProxyPrivateKey();
    }
  }

  const passphrase = input?.passphrase ?? DEFAULT_PROXY_PASSPHRASE;
  const agent = input?.agent ?? DEFAULT_PROXY_AGENT ?? DEFAULT_AGENT;

  const resolvedPassword = password ?? undefined;
  const resolvedPrivateKey = privateKey ?? undefined;
  const resolvedPassphrase = passphrase ?? undefined;
  const resolvedAgent = agent ?? undefined;

  return {
    host: candidateHost,
    port,
    username,
    password: resolvedPassword,
    privateKey: resolvedPrivateKey,
    passphrase: resolvedPassphrase,
    agent: resolvedAgent,
  };
}

export async function resolveSshConfig(input: ResolveConfigInput): Promise<ResolvedSshConfig> {
  const requestedHost = input.host ?? DEFAULT_HOST;
  if (!requestedHost) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Host must be provided either via tool input or --host'
    );
  }

  if (requestedHost.includes('@')) {
    const segments = requestedHost.split('@');
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
          `Host value "${requestedHost}" appears to include a username. ${hint}`
        );
      }
    }
  }

  const sshConfigEntry = await getSshConfigEntry(requestedHost);
  const configHostName = getFirstStringValue(sshConfigEntry, 'HostName');

  let host = configHostName ?? requestedHost;

  const configUser = getFirstStringValue(sshConfigEntry, 'User');
  let username = input.username ?? configUser ?? DEFAULT_USERNAME;
  if (!username) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Username must be provided via the "username" parameter or the --user CLI flag (for example: "root").'
    );
  }

  const configPortValue = getFirstStringValue(sshConfigEntry, 'Port');
  const rawPort = input.port ?? configPortValue ?? DEFAULT_PORT;
  const port = parseOptionalInteger(rawPort as any, 'port', { min: 1, max: 65535 }) ?? 22;

  let agent = input.agent ?? DEFAULT_AGENT;
  if (!agent) {
    const configAgent = getFirstStringValue(sshConfigEntry, 'IdentityAgent');
    if (configAgent) {
      agent = resolveSshConfigPath(configAgent, host, username);
    }
  }

  const password = input.password ?? DEFAULT_PASSWORD;

  let privateKey = input.privateKey ?? null;
  if (!privateKey && input.privateKeyPath) {
    privateKey = await readPrivateKeyFromPath(resolvePathFromCwd(input.privateKeyPath));
  }
  if (!privateKey && !password) {
    const defaultKey = await loadDefaultPrivateKey();
    if (defaultKey) {
      privateKey = defaultKey;
    }
  }
  if (!privateKey && !password && sshConfigEntry) {
    const identityFiles = getStringArrayValue(sshConfigEntry, 'IdentityFile');
    for (const identity of identityFiles) {
      const resolvedIdentityPath = resolveSshConfigPath(identity, host, username);
      privateKey = await readPrivateKeyFromPath(resolvedIdentityPath);
      break;
    }
  }

  if (sshConfigEntry) {
    const proxyCommand = getFirstStringValue(sshConfigEntry, 'ProxyCommand');
    if (proxyCommand) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `ProxyCommand directives are not supported (encountered for host "${requestedHost}").`
      );
    }
  }

  const configProxyInput = sshConfigEntry
    ? await deriveProxyJumpFromConfig(requestedHost, sshConfigEntry)
    : undefined;
  const mergedProxyInput = mergeProxyInputs(configProxyInput, input.proxyJump);
  const proxyJumpResolved = await resolveProxyConfig(mergedProxyInput);

  const config: ResolvedSshConfig = { host, port, username };

  if (password) {
    config.password = password;
  }
  if (privateKey) {
    config.privateKey = privateKey;
  }
  if (input.passphrase) {
    config.passphrase = input.passphrase;
  }
  if (agent) {
    config.agent = agent;
  }
  config.proxyJump = proxyJumpResolved ?? null;

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

function credentialFingerprint(config: Pick<ResolvedSshConfig, 'password' | 'privateKey' | 'passphrase' | 'agent' | 'proxyJump'> & { username: string; host: string; port: number }): string {
  const hash = createHash('sha256');
  hash.update(config.password ?? '');
  hash.update(config.privateKey ?? '');
  hash.update(config.passphrase ?? '');
  if (config.agent) {
    hash.update(config.agent);
  }
  if (config.proxyJump) {
    hash.update(config.proxyJump.host);
    hash.update(String(config.proxyJump.port));
    hash.update(config.proxyJump.username);
    hash.update(config.proxyJump.password ?? '');
    hash.update(config.proxyJump.privateKey ?? '');
    hash.update(config.proxyJump.passphrase ?? '');
    hash.update(config.proxyJump.agent ?? '');
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
  private proxyConn: SSHClient | null = null;
  private sshConfig: ResolvedSshConfig;
  private proxyConfig: ResolvedProxyConfig | null;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private isProxyConnecting = false;
  private proxyConnectionPromise: Promise<void> | null = null;

  constructor(config: ResolvedSshConfig) {
    this.sshConfig = config;
    this.proxyConfig = config.proxyJump ?? null;
  }

  private isProxyConnected(): boolean {
    return this.proxyConn !== null && (this.proxyConn as any)._sock && !(this.proxyConn as any)._sock.destroyed;
  }

  private async ensureProxyConnected(): Promise<void> {
    if (!this.proxyConfig) {
      return;
    }

    if (this.proxyConn && this.isProxyConnected()) {
      return;
    }

    if (this.isProxyConnecting && this.proxyConnectionPromise) {
      await this.proxyConnectionPromise;
      return;
    }

    this.isProxyConnecting = true;
    this.proxyConnectionPromise = new Promise((resolve, reject) => {
      const proxy = new SSHClient();
      this.proxyConn = proxy;

      const timeoutId = setTimeout(() => {
        proxy.end();
        this.proxyConn = null;
        this.isProxyConnecting = false;
        this.proxyConnectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'SSH proxy connection timeout'));
      }, 30000);

      proxy.on('ready', () => {
        clearTimeout(timeoutId);
        this.isProxyConnecting = false;
        this.proxyConnectionPromise = null;
        console.error('SSH proxy connection established');
        resolve();
      });

      proxy.on('error', (err) => {
        clearTimeout(timeoutId);
        proxy.end();
        this.proxyConn = null;
        this.isProxyConnecting = false;
        this.proxyConnectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, `SSH proxy connection error: ${err.message}`));
      });

      const handleProxyTermination = () => {
        this.proxyConn = null;
      };

      proxy.on('end', handleProxyTermination);
      proxy.on('close', handleProxyTermination);

      const proxyConnectConfig: ConnectConfig = { ...this.proxyConfig! };
      proxy.connect(proxyConnectConfig);
    });

    await this.proxyConnectionPromise;
  }

  private buildTargetConnectConfig(overrides: Partial<ConnectConfig> = {}): ConnectConfig {
    const { proxyJump, ...rest } = this.sshConfig;
    return { ...rest, ...overrides } as ConnectConfig;
  }

  async connect(): Promise<void> {
    if (this.conn && this.isConnected()) {
      return;
    }

    if (this.isConnecting && this.connectionPromise) {
      await this.connectionPromise;
      return;
    }

    if (this.proxyConfig) {
      await this.ensureProxyConnected();
    }

    this.isConnecting = true;
    this.connectionPromise = new Promise((resolve, reject) => {
      this.conn = new SSHClient();

      const cleanup = () => {
        this.isConnecting = false;
        this.connectionPromise = null;
      };

      const timeoutId = setTimeout(() => {
        this.conn?.end();
        this.conn = null;
        cleanup();
        reject(new McpError(ErrorCode.InternalError, 'SSH connection timeout'));
      }, 30000);

      this.conn.on('ready', () => {
        clearTimeout(timeoutId);
        cleanup();
        console.error('SSH connection established');
        resolve();
      });

      this.conn.on('error', (err) => {
        clearTimeout(timeoutId);
        this.conn = null;
        cleanup();
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      });

      const handleTermination = () => {
        console.error('SSH connection closed');
        this.conn = null;
      };

      this.conn.on('end', handleTermination);
      this.conn.on('close', handleTermination);

      const initiateConnection = (overrides: Partial<ConnectConfig> = {}) => {
        const connectConfig = this.buildTargetConnectConfig(overrides);
        if (overrides.sock) {
          delete (connectConfig as any).host;
          delete (connectConfig as any).port;
        }
        delete (connectConfig as any).proxyJump;
        this.conn?.connect(connectConfig);
      };

      if (this.proxyConfig) {
        if (!this.proxyConn) {
          cleanup();
          reject(new McpError(ErrorCode.InternalError, 'SSH proxy connection not available'));
          return;
        }
        this.proxyConn.forwardOut('127.0.0.1', 0, this.sshConfig.host, this.sshConfig.port, (err, stream) => {
          if (err) {
            clearTimeout(timeoutId);
            this.conn = null;
            cleanup();
            reject(new McpError(ErrorCode.InternalError, `SSH proxy forwarding error: ${err.message}`));
            return;
          }
          initiateConnection({ sock: stream });
        });
      } else {
        initiateConnection();
      }
    });

    await this.connectionPromise;
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
    if (this.proxyConn) {
      this.proxyConn.end();
      this.proxyConn = null;
    }
    this.isConnecting = false;
    this.connectionPromise = null;
    this.isProxyConnecting = false;
    this.proxyConnectionPromise = null;
  }
}

type ManagerEntry = {
  manager: SSHConnectionManager;
  fingerprint: string;
};

const connectionManagers = new Map<string, ManagerEntry>();

function getConnectionKey(config: ResolvedSshConfig): string {
  let key = `${config.username}@${config.host}:${config.port}`;
  if (config.proxyJump) {
    key += `|proxy=${config.proxyJump.username}@${config.proxyJump.host}:${config.proxyJump.port}`;
  }
  return key;
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
    proxyJump: z.object({
      host: z.string().min(1).describe("Hostname or IP address of the proxy (bastion) server").optional(),
      port: z.union([z.number().int(), z.string().regex(/^\d+$/)]).describe("Port number for the proxy server").optional(),
      username: z.string().min(1).describe("Username for proxy SSH authentication").optional(),
      password: z.string().describe("Password for proxy SSH authentication").optional(),
      privateKey: z.string().describe("PEM-encoded private key contents for proxy authentication").optional(),
      privateKeyPath: z.string().describe("Path on the MCP server to a PEM-encoded private key for the proxy").optional(),
      passphrase: z.string().describe("Passphrase for the proxy private key, if required").optional(),
      agent: z.string().describe("Path to an SSH agent socket to use for the proxy").optional(),
    }).partial().describe("Proxy (bastion) connection configuration").optional(),
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
      proxyJump,
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
        proxyJump,
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
  sshConfig: ResolvedSshConfig,
  command: string,
  timeoutMs: number = DEFAULT_TIMEOUT
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  const sanitizedCommand = sanitizeCommand(command);
  await ensureCommandAllowed(sanitizedCommand);

  const manager = new SSHConnectionManager(sshConfig);
  try {
    await manager.ensureConnected();
    return await execSshCommandWithConnection(manager, sanitizedCommand, timeoutMs);
  } finally {
    manager.close();
  }
}

async function main() {
  let stdioTransport: StdioServerTransport | null = null;
  let httpTransport: StreamableHTTPServerTransport | null = null;
  let httpServer: ReturnType<typeof createServer> | null = null;
  let isCleaningUp = false;
  let httpTransportClosed = false;

  if (TRANSPORT_MODE === 'http') {
    httpTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    await server.connect(httpTransport);

    httpServer = createServer((req, res) => {
      httpTransport!.handleRequest(req as any, res).catch((error) => {
        console.error("Error handling HTTP request:", error);
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end('Internal Server Error');
        } else {
          try {
            res.end();
          } catch {
            // ignore errors while attempting to end the response
          }
        }
      });
    });

    await new Promise<void>((resolve, reject) => {
      if (!httpServer) {
        reject(new Error('HTTP server was not created'));
        return;
      }

      const initialErrorListener = (error: Error) => {
        reject(error);
      };

      httpServer.on('error', initialErrorListener);
      httpServer.listen(HTTP_PORT, HTTP_HOST, () => {
        httpServer?.off('error', initialErrorListener);
        httpServer?.on('error', (error) => {
          console.error("HTTP server error:", error);
        });

        const address = httpServer?.address();
        if (address && typeof address === 'object') {
          const host = address.address === '::' ? 'localhost' : address.address;
          console.error(`SSH MCP Server running over HTTP on http://${host}:${address.port}`);
        } else {
          console.error(`SSH MCP Server running over HTTP on port ${HTTP_PORT}`);
        }
        resolve();
      });
    });
  } else {
    stdioTransport = new StdioServerTransport();
    await server.connect(stdioTransport);
    console.error("SSH MCP Server running on stdio");
  }

  const cleanup = () => {
    if (isCleaningUp) {
      return;
    }
    isCleaningUp = true;

    console.error("Shutting down SSH MCP Server...");
    closeAllConnectionManagers();

    if (httpTransport && httpServer) {
      httpTransportClosed = true;
      httpTransport.close().catch((error) => {
        console.error("Error closing HTTP transport:", error);
      }).finally(() => {
        httpServer?.close((err) => {
          if (err) {
            console.error("Error closing HTTP server:", err);
          }
          process.exit(0);
        });
      });
    } else {
      process.exit(0);
    }
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    closeAllConnectionManagers();
    if (httpTransport && !httpTransportClosed) {
      httpTransport.close().catch((error) => {
        console.error("Error closing HTTP transport during exit:", error);
      });
    }
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
