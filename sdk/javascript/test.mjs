import assert from 'node:assert/strict';
import test from 'node:test';
import {Readable, Writable} from 'node:stream';
import {schema, serve} from './index.mjs';

test('serve preserves the request id', async () => {
  const input = Readable.from([`${JSON.stringify({schema, id: 9, hook: 'inspect', payload: {text: 'hello'}})}\n`]);
  let output = '';
  const sink = new Writable({write(chunk, _encoding, done) { output += chunk; done(); }});
  await serve(() => ({schema: 'attacker.schema', id: 99, type: 'other', spans: []}), {input, output: sink});
  const response = JSON.parse(output);
  assert.equal(response.id, 9);
  assert.equal(response.schema, schema);
  assert.equal(response.type, 'result');
});
