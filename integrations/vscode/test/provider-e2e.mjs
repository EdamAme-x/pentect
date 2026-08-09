import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { PentectBackend } from '../out/backend.js';

const binary = process.env.PENTECT_BIN;
if (!binary) {
  throw new Error('PENTECT_BIN must point to the Pentect executable.');
}

const secret = `${['sk', 'live'].join('_')}_${createHash('sha256').update('pentect-vscode-e2e').digest('hex').slice(0, 40)}`;
const providerKey = `provider_${createHash('sha256').update('pentect-provider-e2e').digest('hex')}`;
let upstreamRequest;
let upstreamAuthorization;

const upstream = createServer(async (request, response) => {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  upstreamRequest = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  upstreamAuthorization = request.headers.authorization;
  const serialized = JSON.stringify(upstreamRequest);
  assert.equal(serialized.includes(secret), false, 'plaintext reached the fake upstream');
  const handle = serialized.match(/<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}>>/)?.[0];
  assert.ok(handle, 'the fake upstream did not receive a handle');

  response.writeHead(200, { 'content-type': 'text/event-stream' });
  response.write(`data: ${JSON.stringify({ choices: [{ delta: { content: `Using ${handle}` } }] })}\n\n`);
  response.write(`data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, id: 'call_1', function: { name: 'shell', arguments: JSON.stringify({ token: handle }) } }] } }] })}\n\n`);
  response.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] })}\n\n`);
  response.end('data: [DONE]\n\n');
});

await new Promise((resolve, reject) => {
  upstream.once('error', reject);
  upstream.listen(0, '127.0.0.1', resolve);
});
const upstreamAddress = upstream.address();
assert.equal(typeof upstreamAddress, 'object');

process.env.OPENAI_API_KEY = providerKey;
const backend = new PentectBackend(() => ({
  executable: binary,
  model: 'e2e-model',
  upstream: `http://127.0.0.1:${upstreamAddress.port}/v1`,
}));

try {
  const ready = await backend.start();
  assert.equal(ready.protocol, 1);
  assert.equal(ready.model, 'e2e-model');
  assert.match(ready.baseUrl, /^http:\/\/127\.0\.0\.1:\d+\/[0-9a-f]{64}$/);

  const response = await fetch(`${ready.baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: 'Bearer pentect-local',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'e2e-model',
      messages: [{ role: 'user', content: `Use this credential in a local tool: ${secret}` }],
      tools: [{
        type: 'function',
        function: {
          name: 'shell',
          description: `Run locally with ${secret}`,
          parameters: {
            type: 'object',
            properties: { token: { type: 'string', description: `Credential ${secret}` } },
          },
        },
      }],
      stream: true,
    }),
  });
  assert.equal(response.status, 200);
  const body = await response.text();
  const events = body
    .split(/\r?\n\r?\n/)
    .map(block => block.replace(/^data:\s*/, ''))
    .filter(data => data && data !== '[DONE]')
    .map(data => JSON.parse(data));
  const responseText = events.map(event => event.choices?.[0]?.delta?.content ?? '').join('');
  const toolArguments = events
    .map(event => event.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments)
    .find(value => typeof value === 'string');
  assert.equal(upstreamAuthorization, `Bearer ${providerKey}`);
  assert.equal(JSON.stringify(upstreamRequest).includes(secret), false);
  assert.equal(responseText.includes(secret), false, 'ordinary provider text was restored');
  assert.equal(responseText.startsWith('Using <<'), true, 'ordinary provider handle was changed');
  assert.deepEqual(JSON.parse(toolArguments), { token: secret }, 'trusted tool arguments were not restored');
} finally {
  backend.dispose();
  delete process.env.OPENAI_API_KEY;
  await new Promise(resolve => upstream.close(resolve));
}
