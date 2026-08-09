const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));

test('registers the Pentect language-model provider on the stable API', () => {
  assert.deepEqual(manifest.contributes.languageModelChatProviders, [{
    vendor: 'pentect',
    displayName: 'Pentect',
    managementCommand: 'pentect.manageProvider',
  }]);
  assert.match(manifest.engines.vscode, /^\^1\.104/);
});

test('security-sensitive launcher settings cannot be supplied by a workspace', () => {
  const properties = manifest.contributes.configuration.properties;
  assert.equal(properties['pentect.executablePath'].scope, 'machine');
  assert.equal(properties['pentect.vscode.model'].scope, 'machine');
  assert.equal(properties['pentect.vscode.upstream'].scope, 'machine');
  assert.equal(Object.keys(properties).some(name => /key|token|secret|authorization/i.test(name)), false);
});
