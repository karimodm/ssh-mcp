import { describe, it, expect } from 'vitest';
import { resolveSshConfig } from '../src/index';

process.env.SSH_MCP_DISABLE_MAIN = '1';

describe('resolveSshConfig validation', () => {
  const baseInput = {
    password: 'secret',
  } as const;

  it('rejects hosts that embed a username when no username is provided', async () => {
    await expect(
      resolveSshConfig({ ...baseInput, host: 'ubuntu@10.0.0.5' })
    ).rejects.toThrow('appears to include a username');
    await expect(
      resolveSshConfig({ ...baseInput, host: 'ubuntu@10.0.0.5' })
    ).rejects.toThrow('Provide the username');
  });

  it('rejects hosts that embed a username even when a username parameter is supplied', async () => {
    await expect(
      resolveSshConfig({ ...baseInput, host: 'dbadmin@db.internal', username: 'dbadmin' })
    ).rejects.toThrow('appears to include a username');
    await expect(
      resolveSshConfig({ ...baseInput, host: 'dbadmin@db.internal', username: 'dbadmin' })
    ).rejects.toThrow('Set "host" to "db.internal"');
  });

  it('reminds caller to provide username when missing', async () => {
    await expect(
      resolveSshConfig({ ...baseInput, host: 'db.internal' })
    ).rejects.toThrow('Username must be provided');
  });
});
