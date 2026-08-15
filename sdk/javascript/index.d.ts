import type {Readable} from 'node:stream';

export type Hook = 'prepare' | 'inspect' | 'finalize' | 'request' | 'response' | 'tool_call' | 'file';
export interface Request<T = unknown> {schema: 'pentect.plugin.v1'; id: number; hook: Hook; payload: T; metadata?: unknown; config?: Record<string, unknown> | null}
export interface Span {start: number; end: number; label: string; category?: 'secret' | 'identifier' | 'endpoint' | 'pii' | 'other'; confidence?: 'high' | 'medium' | 'low'}
export interface Values {action?: 'next' | 'stop'; outcome?: 'block' | 'respond'; payload?: unknown; message?: string; spans?: Span[]; error?: {code: string}}
export type PluginInput = Readable;
export interface PluginOutput {write(chunk: string): unknown}
export declare const schema: 'pentect.plugin.v1';
export declare function result(request: Request, values?: Values): Values & {schema: typeof schema; id: number; type: 'result'; action: 'next' | 'stop'};
export declare function serve(handler: (request: Request) => Values | void | Promise<Values | void>, options?: {input?: PluginInput; output?: PluginOutput}): Promise<void>;
