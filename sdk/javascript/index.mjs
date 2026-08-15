import {createInterface} from 'node:readline';

export const schema = 'pentect.plugin.v1';

export function result(request, values = {}) {
  return {...values, schema, id: request.id, type: 'result', action: values.action ?? 'next'};
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
          typeof request?.hook !== 'string' || !('payload' in request)) {
        throw new Error('invalid Pentect request');
      }
      response = result(request, await handler(request) ?? {});
    } catch {
      response = {schema, id, type: 'result', action: 'next', error: {code: 'handler_error'}};
    }
    output.write(`${JSON.stringify(response)}\n`);
  }
}
