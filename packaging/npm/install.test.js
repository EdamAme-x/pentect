import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expectedChecksum, installationPath, releaseAsset } from './install.js';

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
