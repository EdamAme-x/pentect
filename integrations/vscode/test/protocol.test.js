const assert = require('node:assert/strict');
const test = require('node:test');
const { ChatCompletionsStreamDecoder, toChatMessages } = require('../out/protocol.js');

test('converts text, tool calls, and tool results without changing values', () => {
  const messages = toChatMessages([
    { role: 'user', content: [{ kind: 'text', value: 'use <<API_KEY_ab12>>' }] },
    {
      role: 'assistant',
      content: [{ kind: 'tool-call', callId: 'call-1', name: 'shell', input: { key: '<<API_KEY_ab12>>' } }],
    },
    {
      role: 'user',
      content: [{ kind: 'tool-result', callId: 'call-1', content: [{ kind: 'text', value: 'done' }] }],
    },
  ]);
  assert.deepEqual(messages, [
    { role: 'user', content: 'use <<API_KEY_ab12>>' },
    {
      role: 'assistant',
      content: null,
      tool_calls: [{
        id: 'call-1',
        type: 'function',
        function: { name: 'shell', arguments: '{"key":"<<API_KEY_ab12>>"}' },
      }],
    },
    { role: 'tool', tool_call_id: 'call-1', content: 'done' },
  ]);
});

test('fails closed for invalid mixed tool results', () => {
  assert.throws(() => toChatMessages([{
    role: 'user',
    content: [
      { kind: 'text', value: 'mixed' },
      { kind: 'tool-result', callId: 'call-1', content: [{ kind: 'text', value: 'done' }] },
    ],
  }]), /cannot be mixed/);
});

test('decodes fragmented text and tool call SSE', () => {
  const decoder = new ChatCompletionsStreamDecoder();
  const events = [];
  events.push(...decoder.push('data: {"choices":[{"delta":{"content":"hel"}}]}\n\n'));
  events.push(...decoder.push('data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'));
  events.push(...decoder.push('data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_","function":{"name":"sh","arguments":"{\\"key\\":\\"<<API_"}}]}}]}\n\n'));
  events.push(...decoder.push('data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"1","function":{"name":"ell","arguments":"KEY_ab12>>\\"}"}}]}}]}\n\n'));
  events.push(...decoder.push('data: [DONE]\n\n'));
  events.push(...decoder.finish());
  assert.deepEqual(events, [
    { kind: 'text', value: 'hel' },
    { kind: 'text', value: 'lo' },
    { kind: 'tool-call', callId: 'call_1', name: 'shell', input: { key: '<<API_KEY_ab12>>' } },
  ]);
});

test('handles CRLF split across transport chunks', () => {
  const decoder = new ChatCompletionsStreamDecoder();
  assert.deepEqual(decoder.push('data: {"choices":[{"delta":{"content":"ok"}}]}\r'), []);
  assert.deepEqual(decoder.push('\n\r\n'), [{ kind: 'text', value: 'ok' }]);
  assert.deepEqual(decoder.push('data: [DONE]\r\n\r\n'), []);
  assert.deepEqual(decoder.push(''), []);
  assert.deepEqual(decoder.finish(), []);
});

test('never interprets ordinary response text as a tool call', () => {
  const decoder = new ChatCompletionsStreamDecoder();
  const events = decoder.push('data: {"choices":[{"delta":{"content":"<<API_KEY_ab12>>"}}]}\n\ndata: [DONE]\n\n');
  assert.deepEqual(events, [{ kind: 'text', value: '<<API_KEY_ab12>>' }]);
});

test('rejects invalid streamed tool arguments', () => {
  const decoder = new ChatCompletionsStreamDecoder();
  decoder.push('data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"shell","arguments":"{"}}]}}]}\n\n');
  assert.throws(() => decoder.push('data: [DONE]\n\n'), /invalid tool-call arguments/);
});

test('fails closed for multiple choices and unknown delta fields', () => {
  const multiple = new ChatCompletionsStreamDecoder();
  assert.throws(() => multiple.push('data: {"choices":[{"index":0,"delta":{}},{"index":1,"delta":{}}]}\n\n'), /one chat-completion choice/);

  const unknown = new ChatCompletionsStreamDecoder();
  assert.throws(() => unknown.push('data: {"choices":[{"index":0,"delta":{"audio":"unknown"}}]}\n\n'), /unknown chat delta field/);
});
