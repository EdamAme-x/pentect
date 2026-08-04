import test from 'node:test';
import assert from 'node:assert/strict';
import { expectedChecksum, releaseAsset } from './install.js';

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
