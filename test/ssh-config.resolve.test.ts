import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { resolveSshConfig, __resetSshConfigCacheForTesting } from '../src/index';

const tmpRoot = path.join(os.tmpdir(), 'ssh-mcp-config-tests');
let configDir: string;
let configPath: string;

async function ensureDir(dir: string) {
  await fs.mkdir(dir, { recursive: true });
}

async function writeConfig(content: string) {
  await fs.writeFile(configPath, content, 'utf8');
  __resetSshConfigCacheForTesting();
}

describe('SSH config host resolution', () => {
  beforeAll(async () => {
    await ensureDir(tmpRoot);
    configDir = await fs.mkdtemp(path.join(tmpRoot, 'cfg-'));
    configPath = path.join(configDir, 'config');
    process.env.SSH_MCP_SSH_CONFIG_PATH = configPath;
  });

  afterAll(async () => {
    delete process.env.SSH_MCP_SSH_CONFIG_PATH;
    if (configDir) {
      await fs.rm(configDir, { recursive: true, force: true });
    }
  });

  beforeEach(() => {
    __resetSshConfigCacheForTesting();
  });

  it('applies host aliases and proxy jumps from SSH config', async () => {
    await writeConfig(`Host k3s1
  User andreavilla
  HostName 10.0.0.41
  ProxyJump lb1a.host.linkorb.cloud

Host lb1a.host.linkorb.cloud
  User bastion
  HostName bastion.internal
  Port 2200
`);

    const config = await resolveSshConfig({ host: 'k3s1', password: 'target-secret' });

    expect(config.host).toBe('10.0.0.41');
    expect(config.username).toBe('andreavilla');
    expect(config.proxyJump).toBeDefined();
    expect(config.proxyJump?.host).toBe('bastion.internal');
    expect(config.proxyJump?.port).toBe(2200);
    expect(config.proxyJump?.username).toBe('bastion');
  });

  it('allows per-call overrides to take precedence over SSH config', async () => {
    await writeConfig(`Host nfs4
  User andreavilla
  HostName private-ip.nfs4.host.linkorb.cloud
`);

    const config = await resolveSshConfig({ host: 'nfs4', username: 'override', password: 'pw' });

    expect(config.host).toBe('private-ip.nfs4.host.linkorb.cloud');
    expect(config.username).toBe('override');
  });

  it('throws for nested ProxyJump directives', async () => {
    await writeConfig(`Host app
  User appuser
  HostName app.internal
  ProxyJump intermediate

Host intermediate
  User jumpuser
  HostName intermediate.internal
  ProxyJump deeper

Host deeper
  User deepuser
  HostName deeper.internal
`);

    await expect(resolveSshConfig({ host: 'app', password: 'pw' })).rejects.toThrow('Nested ProxyJump');
  });
});
