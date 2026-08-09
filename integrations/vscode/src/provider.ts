import * as vscode from 'vscode';
import { PentectBackend } from './backend';
import {
  ChatCompletionsStreamDecoder,
  ChatTool,
  NormalizedMessage,
  NormalizedPart,
  StreamEvent,
  toChatMessages,
} from './protocol';

const DEFAULT_MAX_INPUT_TOKENS = 128_000;
const DEFAULT_MAX_OUTPUT_TOKENS = 16_384;
const MAX_REQUEST_BYTES = 64 * 1024 * 1024;
const MAX_TOOLS = 1024;

export class PentectChatModelProvider implements vscode.LanguageModelChatProvider, vscode.Disposable {
  private readonly modelInformationChanged = new vscode.EventEmitter<void>();
  readonly onDidChangeLanguageModelChatInformation = this.modelInformationChanged.event;

  constructor(private readonly backend: PentectBackend) {}

  refresh(): void {
    this.modelInformationChanged.fire();
  }

  dispose(): void {
    this.modelInformationChanged.dispose();
  }

  provideLanguageModelChatInformation(
    _options: { silent: boolean },
    _token: vscode.CancellationToken,
  ): vscode.ProviderResult<vscode.LanguageModelChatInformation[]> {
    const model = configuredModel();
    return [{
      id: model,
      name: `${model} through Pentect`,
      family: model,
      version: '1',
      maxInputTokens: DEFAULT_MAX_INPUT_TOKENS,
      maxOutputTokens: DEFAULT_MAX_OUTPUT_TOKENS,
      detail: 'Requests pass through the local Pentect boundary.',
      capabilities: {
        imageInput: false,
        toolCalling: true,
      },
    }];
  }

  async provideLanguageModelChatResponse(
    model: vscode.LanguageModelChatInformation,
    messages: readonly vscode.LanguageModelChatRequestMessage[],
    options: vscode.ProvideLanguageModelChatResponseOptions,
    progress: vscode.Progress<vscode.LanguageModelResponsePart>,
    token: vscode.CancellationToken,
  ): Promise<void> {
    if (token.isCancellationRequested) {
      return;
    }
    const controller = new AbortController();
    const cancellation = token.onCancellationRequested(() => controller.abort());
    try {
      const ready = await this.backend.start();
      if (token.isCancellationRequested) {
        return;
      }
      if (model.id !== ready.model) {
        throw new Error('Pentect model configuration changed. Restart the provider and try again.');
      }

      const normalized = messages.map(normalizeMessage);
      const body = {
        model: ready.model,
        messages: toChatMessages(normalized),
        tools: normalizeTools(options.tools),
        ...(options.tools && options.tools.length > 0
          ? { tool_choice: options.toolMode === vscode.LanguageModelChatToolMode.Required ? 'required' : 'auto' }
          : {}),
        n: 1,
        stream: true,
      };
      const encoded = JSON.stringify(body);
      if (Buffer.byteLength(encoded, 'utf8') > MAX_REQUEST_BYTES) {
        throw new Error('Pentect blocked a VS Code model request larger than 64 MiB.');
      }
      const response = await fetch(`${ready.baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'authorization': 'Bearer pentect-local',
          'content-type': 'application/json',
          'accept': 'text/event-stream',
        },
        body: encoded,
        signal: controller.signal,
      });
      if (!response.ok) {
        const detail = await safeError(response);
        throw new Error(`Pentect provider request failed (${response.status})${detail}.`);
      }
      if (!response.body) {
        throw new Error('Pentect provider returned an empty response.');
      }

      const decoder = new TextDecoder();
      const stream = new ChatCompletionsStreamDecoder();
      const reader = response.body.getReader();
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) {
          break;
        }
        reportEvents(stream.push(decoder.decode(chunk.value, { stream: true })), progress);
      }
      reportEvents(stream.push(decoder.decode()), progress);
      reportEvents(stream.finish(), progress);
    } catch (error) {
      if (token.isCancellationRequested) {
        return;
      }
      throw error;
    } finally {
      cancellation.dispose();
    }
  }

  async provideTokenCount(
    _model: vscode.LanguageModelChatInformation,
    value: string | vscode.LanguageModelChatRequestMessage,
    _token: vscode.CancellationToken,
  ): Promise<number> {
    const serialized = typeof value === 'string'
      ? value
      : JSON.stringify(toChatMessages([normalizeMessage(value)]));
    // This is intentionally a conservative estimate rather than a claim to
    // implement every upstream tokenizer.
    return Math.max(1, Math.ceil(new TextEncoder().encode(serialized).length / 3));
  }
}

function normalizeMessage(message: vscode.LanguageModelChatRequestMessage): NormalizedMessage {
  if (message.name !== undefined && !/^[A-Za-z0-9_-]{1,64}$/.test(message.name)) {
    throw new Error('Pentect blocked an invalid VS Code message name.');
  }
  const role = message.role === vscode.LanguageModelChatMessageRole.User
    ? 'user'
    : message.role === vscode.LanguageModelChatMessageRole.Assistant
      ? 'assistant'
      : undefined;
  if (!role) {
    throw new Error('Pentect blocked an unknown VS Code message role.');
  }
  const parts: NormalizedPart[] = [];
  for (const part of message.content) {
    if (part instanceof vscode.LanguageModelTextPart) {
      parts.push({ kind: 'text', value: part.value });
    } else if (part instanceof vscode.LanguageModelToolCallPart) {
      parts.push({ kind: 'tool-call', callId: part.callId, name: part.name, input: part.input });
    } else if (part instanceof vscode.LanguageModelToolResultPart) {
      const content = part.content.map(item => {
        if (!(item instanceof vscode.LanguageModelTextPart)) {
          throw new Error('Pentect does not support this tool-result content type yet.');
        }
        return { kind: 'text' as const, value: item.value };
      });
      parts.push({ kind: 'tool-result', callId: part.callId, content });
    } else {
      throw new Error('Pentect blocked an unknown VS Code message part.');
    }
  }
  return { role, content: parts };
}

function normalizeTools(tools: readonly vscode.LanguageModelChatTool[] | undefined): ChatTool[] | undefined {
  if (tools && tools.length > MAX_TOOLS) {
    throw new Error('Pentect blocked a request with more than 1024 tools.');
  }
  return tools?.map(tool => ({
    type: 'function',
    function: {
      name: tool.name,
      ...(tool.description ? { description: tool.description } : {}),
      parameters: tool.inputSchema ?? { type: 'object', properties: {} },
    },
  }));
}

function reportEvents(
  events: readonly StreamEvent[],
  progress: vscode.Progress<vscode.LanguageModelResponsePart>,
): void {
  for (const event of events) {
    if (event.kind === 'text') {
      progress.report(new vscode.LanguageModelTextPart(event.value));
    } else {
      if (typeof event.input !== 'object' || event.input === null || Array.isArray(event.input)) {
        throw new Error('Pentect blocked non-object tool-call arguments.');
      }
      progress.report(new vscode.LanguageModelToolCallPart(event.callId, event.name, event.input));
    }
  }
}

async function safeError(response: Response): Promise<string> {
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().startsWith('text/plain')) {
    return '';
  }
  const text = (await response.text()).trim();
  return text.length > 0 && text.length <= 512 ? `: ${text}` : '';
}

function configuredModel(): string {
  return vscode.workspace.getConfiguration('pentect').get<string>('vscode.model', 'gpt-5').trim() || 'gpt-5';
}
