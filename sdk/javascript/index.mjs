import {createInterface} from 'node:readline';

export const schema = 'pentect.plugin.v1';
const hooks = new Set(['prepare', 'inspect', 'finalize', 'request', 'response', 'tool_call', 'file']);
const actions = new Set(['next', 'stop']);

export function result(request, values = {}) {
  const action = values.action ?? 'next';
  if (!actions.has(action)) throw new Error('invalid Pentect action');
  return {...values, schema, id: request.id, type: 'result', action};
}

export async function serve(handler, {input = process.stdin, output = process.stdout} = {}) {
  const lines = createInterface({input, crlfDelay: Infinity});
  for await (const line of lines) {
    let id = null;
    let response;
    try {
      const request = JSON.parse(line);
      id = request?.id;
      if (request?.schema !== schema || !Number.isSafeInteger(id) || id < 1 ||
          !hooks.has(request?.hook) || !('payload' in request)) {
        throw new Error('invalid Pentect request');
      }
      response = result(request, await handler(request) ?? {});
    } catch {
      response = {schema, id, type: 'result', action: 'next', error: {code: 'handler_error'}};
    }
    let encoded;
    try {
      encoded = JSON.stringify(response);
    } catch {
      encoded = JSON.stringify({schema, id, type: 'result', action: 'next', error: {code: 'handler_error'}});
    }
    output.write(`${encoded}\n`);
  }
}
