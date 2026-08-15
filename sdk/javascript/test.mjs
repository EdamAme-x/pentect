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

test('serve rejects unknown hooks and invalid actions', async () => {
  const requests = [
    {schema, id: 10, hook: 'unknown', payload: {}},
    {schema, id: 11, hook: 'inspect', payload: {}},
  ];
  const input = Readable.from(requests.map((request) => `${JSON.stringify(request)}\n`));
  let output = '';
  const sink = new Writable({write(chunk, _encoding, done) { output += chunk; done(); }});
  await serve(() => ({action: 'continue'}), {input, output: sink});
  for (const response of output.trim().split('\n').map(JSON.parse)) {
    assert.equal(response.error.code, 'handler_error');
  }
});

test('serve converts serialization failures into protocol errors', async () => {
  const request = {schema, id: 12, hook: 'inspect', payload: {}};
  const input = Readable.from([`${JSON.stringify(request)}\n`]);
  let output = '';
  const sink = new Writable({write(chunk, _encoding, done) { output += chunk; done(); }});
  const circular = {};
  circular.self = circular;
  await serve(() => ({payload: circular}), {input, output: sink});
  assert.equal(JSON.parse(output).error.code, 'handler_error');
});
