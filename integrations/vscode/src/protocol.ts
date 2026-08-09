export type ChatRole = 'user' | 'assistant' | 'tool';

export interface ChatTextMessage {
  role: 'user' | 'assistant';
  content: string | null;
  tool_calls?: ChatToolCall[];
}

export interface ChatToolMessage {
  role: 'tool';
  tool_call_id: string;
  content: string;
}

export interface ChatToolCall {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string;
  };
}

export type ChatMessage = ChatTextMessage | ChatToolMessage;

export interface ChatTool {
  type: 'function';
  function: {
    name: string;
    description?: string;
    parameters: object;
  };
}

export interface NormalizedTextPart {
  kind: 'text';
  value: string;
}

export interface NormalizedToolCallPart {
  kind: 'tool-call';
  callId: string;
  name: string;
  input: unknown;
}

export interface NormalizedToolResultPart {
  kind: 'tool-result';
  callId: string;
  content: readonly NormalizedTextPart[];
}

export type NormalizedPart =
  | NormalizedTextPart
  | NormalizedToolCallPart
  | NormalizedToolResultPart;

export interface NormalizedMessage {
  role: 'user' | 'assistant';
  content: readonly NormalizedPart[];
}

export function toChatMessages(messages: readonly NormalizedMessage[]): ChatMessage[] {
  const output: ChatMessage[] = [];

  for (const message of messages) {
    const text: string[] = [];
    const calls: ChatToolCall[] = [];
    const results: ChatToolMessage[] = [];

    for (const part of message.content) {
      switch (part.kind) {
        case 'text':
          text.push(part.value);
          break;
        case 'tool-call':
          if (message.role !== 'assistant') {
            throw new Error('A tool call is only valid in an assistant message.');
          }
          calls.push({
            id: nonEmpty(part.callId, 'tool call ID'),
            type: 'function',
            function: {
              name: nonEmpty(part.name, 'tool name'),
              arguments: JSON.stringify(part.input ?? {}),
            },
          });
          break;
        case 'tool-result': {
          if (message.role !== 'user') {
            throw new Error('A tool result is only valid in a user message.');
          }
          const resultText = part.content.map(item => item.value).join('');
          results.push({
            role: 'tool',
            tool_call_id: nonEmpty(part.callId, 'tool result call ID'),
            content: resultText,
          });
          break;
        }
      }
    }

    if (results.length > 0) {
      if (text.length > 0 || calls.length > 0) {
        throw new Error('Tool results cannot be mixed with text or tool calls.');
      }
      output.push(...results);
      continue;
    }

    output.push({
      role: message.role,
      content: text.length > 0 ? text.join('') : null,
      ...(calls.length > 0 ? { tool_calls: calls } : {}),
    });
  }

  return output;
}

export interface StreamTextEvent {
  kind: 'text';
  value: string;
}

export interface StreamToolCallEvent {
  kind: 'tool-call';
  callId: string;
  name: string;
  input: unknown;
}

export type StreamEvent = StreamTextEvent | StreamToolCallEvent;

const MAX_PENDING_STREAM_BYTES = 8 * 1024 * 1024;
const MAX_TOOL_CALLS = 1024;

interface PendingToolCall {
  id: string;
  name: string;
  arguments: string;
}

export class ChatCompletionsStreamDecoder {
  private pending = '';
  private readonly calls = new Map<number, PendingToolCall>();
  private bufferedToolBytes = 0;
  private finished = false;

  push(chunk: string): StreamEvent[] {
    if (this.finished) {
      if (chunk.length === 0) {
        return [];
      }
      throw new Error('Received data after the stream ended.');
    }
    this.pending = (this.pending + chunk).replaceAll('\r\n', '\n');
    if (this.pending.length > MAX_PENDING_STREAM_BYTES) {
      throw new Error('The provider event stream exceeded the pending-data limit.');
    }
    const events: StreamEvent[] = [];
    let boundary: number;
    while ((boundary = this.pending.indexOf('\n\n')) !== -1) {
      const block = this.pending.slice(0, boundary);
      this.pending = this.pending.slice(boundary + 2);
      events.push(...this.decodeBlock(block));
    }
    return events;
  }

  finish(): StreamEvent[] {
    if (!this.finished && this.pending.trim().length > 0) {
      throw new Error('The provider returned a truncated event stream.');
    }
    return this.flushCalls();
  }

  private decodeBlock(block: string): StreamEvent[] {
    const data = block
      .split('\n')
      .filter(line => line.startsWith('data:'))
      .map(line => line.slice(5).trimStart())
      .join('\n');
    if (data.length === 0) {
      return [];
    }
    if (data === '[DONE]') {
      this.finished = true;
      return this.flushCalls();
    }

    let payload: unknown;
    try {
      payload = JSON.parse(data);
    } catch {
      throw new Error('The provider returned an invalid JSON event.');
    }
    if (!isRecord(payload) || !Array.isArray(payload.choices)) {
      throw new Error('The provider returned an unknown chat event.');
    }

    if (payload.choices.length > 1) {
      throw new Error('Pentect supports one chat-completion choice per request.');
    }
    const events: StreamEvent[] = [];
    for (const choice of payload.choices) {
      if (!isRecord(choice) || !isRecord(choice.delta)) {
        throw new Error('The provider returned an unknown chat choice.');
      }
      if (choice.index !== undefined && choice.index !== 0) {
        throw new Error('The provider returned an unexpected chat-choice index.');
      }
      const delta = choice.delta;
      const unknownDelta = Object.keys(delta).find(key => !['role', 'content', 'refusal', 'tool_calls'].includes(key));
      if (unknownDelta) {
        throw new Error(`Pentect blocked an unknown chat delta field: ${unknownDelta}.`);
      }
      if (delta.role !== undefined && delta.role !== 'assistant') {
        throw new Error('The provider returned an invalid streamed role.');
      }
      if (typeof delta.content === 'string' && delta.content.length > 0) {
        events.push({ kind: 'text', value: delta.content });
      } else if (delta.content !== undefined && delta.content !== null) {
        throw new Error('The provider returned unsupported non-text content.');
      }
      if (typeof delta.refusal === 'string' && delta.refusal.length > 0) {
        events.push({ kind: 'text', value: delta.refusal });
      } else if (delta.refusal !== undefined && delta.refusal !== null) {
        throw new Error('The provider returned unsupported refusal content.');
      }

      if (delta.tool_calls !== undefined) {
        if (!Array.isArray(delta.tool_calls)) {
          throw new Error('The provider returned invalid tool calls.');
        }
        for (const raw of delta.tool_calls) {
          if (!isRecord(raw) || !Number.isSafeInteger(raw.index) || (raw.index as number) < 0) {
            throw new Error('The provider returned an invalid tool-call index.');
          }
          const index = raw.index as number;
          const unknownCallField = Object.keys(raw).find(key => !['index', 'id', 'type', 'function'].includes(key));
          if (unknownCallField || (raw.type !== undefined && raw.type !== 'function')) {
            throw new Error('The provider returned an unknown tool-call format.');
          }
          if (!this.calls.has(index) && this.calls.size >= MAX_TOOL_CALLS) {
            throw new Error('The provider returned too many tool calls.');
          }
          const current = this.calls.get(index) ?? { id: '', name: '', arguments: '' };
          if (typeof raw.id === 'string') {
            current.id += raw.id;
            this.bufferedToolBytes += raw.id.length;
          } else if (raw.id !== undefined) {
            throw new Error('The provider returned an invalid tool-call ID.');
          }
          if (raw.function !== undefined) {
            if (!isRecord(raw.function)) {
              throw new Error('The provider returned an invalid function call.');
            }
            const unknownFunctionField = Object.keys(raw.function).find(key => !['name', 'arguments'].includes(key));
            if (unknownFunctionField) {
              throw new Error('The provider returned an unknown function-call format.');
            }
            if (typeof raw.function.name === 'string') {
              current.name += raw.function.name;
              this.bufferedToolBytes += raw.function.name.length;
            } else if (raw.function.name !== undefined) {
              throw new Error('The provider returned an invalid function name.');
            }
            if (typeof raw.function.arguments === 'string') {
              current.arguments += raw.function.arguments;
              this.bufferedToolBytes += raw.function.arguments.length;
            } else if (raw.function.arguments !== undefined) {
              throw new Error('The provider returned invalid function arguments.');
            }
          }
          if (this.bufferedToolBytes > MAX_PENDING_STREAM_BYTES) {
            throw new Error('The provider tool calls exceeded the pending-data limit.');
          }
          this.calls.set(index, current);
        }
      }
    }
    return events;
  }

  private flushCalls(): StreamEvent[] {
    const events = [...this.calls.entries()]
      .sort(([left], [right]) => left - right)
      .map(([, call]) => {
        const callId = nonEmpty(call.id, 'streamed tool call ID');
        const name = nonEmpty(call.name, 'streamed tool name');
        let input: unknown;
        try {
          input = JSON.parse(call.arguments || '{}');
        } catch {
          throw new Error('The provider returned invalid tool-call arguments.');
        }
        return { kind: 'tool-call', callId, name, input } satisfies StreamToolCallEvent;
      });
    this.calls.clear();
    this.bufferedToolBytes = 0;
    return events;
  }
}

function nonEmpty(value: string, name: string): string {
  if (value.trim().length === 0) {
    throw new Error(`Missing ${name}.`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
