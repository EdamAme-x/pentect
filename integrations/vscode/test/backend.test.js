const assert = require('node:assert/strict');
const test = require('node:test');
const { parseReady } = require('../out/backend.js');

test('accepts an authenticated loopback handshake', () => {
  const token = 'a'.repeat(64);
  assert.deepEqual(parseReady(JSON.stringify({
    protocol: 1,
    baseUrl: `http://127.0.0.1:4321/${token}`,
    model: 'gpt-5',
  })), {
    protocol: 1,
    baseUrl: `http://127.0.0.1:4321/${token}`,
    model: 'gpt-5',
  });
});

test('rejects remote, credentialed, and unkeyed addresses', () => {
  const token = 'a'.repeat(64);
  for (const baseUrl of [
    `https://example.com/${token}`,
    `http://localhost:4321/${token}`,
    `http://user:pass@127.0.0.1:4321/${token}`,
    'http://127.0.0.1:4321/',
  ]) {
    assert.throws(() => parseReady(JSON.stringify({ protocol: 1, baseUrl, model: 'gpt-5' })));
  }
});
