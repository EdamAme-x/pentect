import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  expectedChecksum,
  downloadWithRetry,
  installationPath,
  releaseAsset,
  retryableStatus,
} from './install.js';

test('maps supported npm platforms to release assets', () => {
  assert.equal(releaseAsset('win32', 'x64'), 'pentect-windows-x86_64.exe');
  assert.equal(releaseAsset('linux', 'arm64'), 'pentect-linux-aarch64');
  assert.equal(releaseAsset('darwin', 'x64'), 'pentect-macos-x86_64');
});

test('rejects unsupported platforms', () => {
  assert.throws(() => releaseAsset('freebsd', 'x64'), /does not provide/);
});

test('accepts only a complete SHA-256 checksum record', () => {
  const hash = 'a'.repeat(64);
  assert.equal(expectedChecksum(`${hash}  pentect-linux-x86_64\n`), hash);
  assert.throws(() => expectedChecksum('not-a-checksum'), /invalid/);
});

test('retries only transient download failures', () => {
  assert.equal(retryableStatus(408), true);
  assert.equal(retryableStatus(429), true);
  assert.equal(retryableStatus(503), true);
  assert.equal(retryableStatus(404), false);
  assert.equal(retryableStatus(401), false);
});

test('retries transient responses before returning a complete body', async () => {
  const statuses = [503, 429, 200];
  const waits = [];
  const cancelled = [];
  const response = await downloadWithRetry('https://example.invalid/pentect', {
    request: async () => {
      const status = statuses.shift();
      if (status === 200) return new Response('pentect', { status });
      return {
        ok: false,
        status,
        statusText: 'transient',
        body: { cancel: async () => cancelled.push(status) },
      };
    },
    timeout: () => undefined,
    wait: async (milliseconds) => waits.push(milliseconds),
  });
  assert.equal(response.status, 200);
  assert.equal(response.bytes.toString('utf8'), 'pentect');
  assert.deepEqual(waits, [250, 500]);
  assert.deepEqual(cancelled, [503, 429]);
});

test('retries when a successful response fails during body download', async () => {
  let requests = 0;
  const waits = [];
  const response = await downloadWithRetry('https://example.invalid/pentect', {
    request: async () => {
      requests += 1;
      if (requests === 1) {
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          arrayBuffer: async () => {
            throw new Error('body download timed out');
          },
        };
      }
      return new Response('complete', { status: 200 });
    },
    timeout: () => undefined,
    wait: async (milliseconds) => waits.push(milliseconds),
  });
  assert.equal(requests, 2);
  assert.deepEqual(waits, [250]);
  assert.equal(response.bytes.toString('utf8'), 'complete');
});

test('uses a user-writable versioned cache for the installed binary', () => {
  const cache = join(tmpdir(), 'pentect-test-cache');
  assert.equal(
    installationPath('0.0.33', {
      platform: 'linux',
      environment: { XDG_CACHE_HOME: cache },
      home: join(tmpdir(), 'pentect-test-home'),
    }),
    join(cache, 'pentect', 'npm', '0.0.33', 'pentect'),
  );
  assert.throws(() => installationPath('../escape'), /version is invalid/);
});

test('does not rely on npm lifecycle scripts', async () => {
  const metadata = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.equal(metadata.scripts.postinstall, undefined);
});

test('npm launcher passes structured installation context instead of a shell command', async () => {
  const launcher = await readFile(new URL('./bin/pentect.js', import.meta.url), 'utf8');
  assert.match(launcher, /PENTECT_NPM_PACKAGE_ROOT/);
  assert.match(launcher, /PENTECT_NPM_SCOPE/);
  assert.doesNotMatch(launcher, /npm update -g/);
});
