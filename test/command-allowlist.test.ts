import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ensureCommandAllowed, __setAllowListForTesting } from '../src/index';

process.env.SSH_MCP_DISABLE_MAIN = '1';

describe('command allowlist', () => {
  beforeEach(() => {
    __setAllowListForTesting([
      'ping *',
      'echo',
      'echo *',
      'curl *',
      'nc -vz *',
      'grep *',
      'cat *'
    ]);
  });

  afterEach(() => {
    __setAllowListForTesting(null);
  });

  it('allows commands that match wildcard patterns', async () => {
    await expect(ensureCommandAllowed('ping -c 1 1.1.1.1')).resolves.toBeUndefined();
    await expect(ensureCommandAllowed('curl https://example.com')).resolves.toBeUndefined();
    await expect(ensureCommandAllowed('nc -vz example.com 443')).resolves.toBeUndefined();
    await expect(ensureCommandAllowed('grep pattern /tmp/file')).resolves.toBeUndefined();
  });

  it('normalizes whitespace before matching', async () => {
    await expect(ensureCommandAllowed('ping   -c   1   8.8.8.8')).resolves.toBeUndefined();
  });

  it('rejects commands that do not match the allowlist', async () => {
    await expect(ensureCommandAllowed('traceroute example.com')).rejects.toThrow('Allowed commands');
    await expect(ensureCommandAllowed('nc -l 8080')).rejects.toThrow('Allowed commands');
  });

  it('allows pipelines when each segment is whitelisted', async () => {
    await expect(ensureCommandAllowed('cat /etc/hosts | grep localhost')).resolves.toBeUndefined();
  });

  it('rejects pipelines containing a non-whitelisted segment', async () => {
    await expect(ensureCommandAllowed('cat /etc/hosts | nc -l 8080')).rejects.toThrow('Command segment "nc -l 8080"');
  });

  it('blocks disallowed chaining constructs', async () => {
    await expect(ensureCommandAllowed('cat /etc/hosts || echo fail')).rejects.toThrow('Command chaining with || is not allowed');
    await expect(ensureCommandAllowed('cat /etc/hosts; ls')).rejects.toThrow('Semicolons');
    await expect(ensureCommandAllowed('cat /etc/hosts &')).rejects.toThrow('Ampersands');
  });

  it('blocks command substitution with $() and backticks', async () => {
    await expect(ensureCommandAllowed('ping $(whoami)')).rejects.toThrow('Command substitution');
    await expect(ensureCommandAllowed('ping `whoami`')).rejects.toThrow('Backticks');
  });

  it('allows output redirection to /tmp', async () => {
    await expect(ensureCommandAllowed('echo hello > /tmp/hello.txt')).resolves.toBeUndefined();
    await expect(ensureCommandAllowed('curl https://example.com 2>>/tmp/curl.log')).resolves.toBeUndefined();
    await expect(ensureCommandAllowed('cat /etc/hosts >> "/tmp/hosts copy"')).resolves.toBeUndefined();
  });

  it('rejects redirection outside /tmp or use of input redirection', async () => {
    await expect(ensureCommandAllowed('echo hello > /etc/passwd')).rejects.toThrow('Redirection target "/etc/passwd" must be under /tmp');
    await expect(ensureCommandAllowed('cat /tmp/input < /tmp/output')).rejects.toThrow('Input redirection (<) is not allowed');
  });

  it('lists allowed commands when rejecting', async () => {
    await expect(ensureCommandAllowed('printf "hello"')).rejects.toThrow(/Command segment "printf "hello""/);
    await expect(ensureCommandAllowed('printf "hello"')).rejects.toThrow(/Allowed commands:\n- ping \*/);
  });
});
