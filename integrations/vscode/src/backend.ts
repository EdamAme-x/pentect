import { ChildProcessWithoutNullStreams, spawn } from 'node:child_process';

export interface BackendSettings {
  executable: string;
  model: string;
  upstream?: string;
}

export interface BackendReady {
  protocol: 1;
  baseUrl: string;
  model: string;
}

const START_TIMEOUT_MS = 10_000;
const MAX_HANDSHAKE_BYTES = 16 * 1024;

export class PentectBackend {
  private child: ChildProcessWithoutNullStreams | undefined;
  private ready: Promise<BackendReady> | undefined;

  constructor(private readonly readSettings: () => BackendSettings) {}

  start(): Promise<BackendReady> {
    if (!this.ready) {
      this.ready = this.spawnBackend();
    }
    return this.ready;
  }

  restart(): void {
    this.stop();
  }

  dispose(): void {
    this.stop();
  }

  private async spawnBackend(): Promise<BackendReady> {
    const settings = this.readSettings();
    const args = ['provider', 'vscode', '--model', nonEmpty(settings.model, 'model')];
    if (settings.upstream) {
      args.push('--upstream', settings.upstream);
    }

    const child = spawn(nonEmpty(settings.executable, 'Pentect executable'), args, {
      shell: false,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child = child;
    child.stdin.on('error', () => {
      // A process that exits while VS Code is closing can reject stdin writes.
    });
    // Pentect diagnostics are deliberately value-free. Drain them, but do not
    // copy provider process output into the extension host's logs.
    child.stderr.resume();

    let ready: BackendReady;
    try {
      const line = await firstLine(child, START_TIMEOUT_MS);
      ready = parseReady(line);
    } catch (error) {
      terminate(child);
      if (this.child === child) {
        this.child = undefined;
        this.ready = undefined;
      }
      throw error;
    }
    child.stdout.resume();
    const onExit = () => {
      if (this.child === child) {
        this.child = undefined;
        this.ready = undefined;
      }
    };
    child.once('exit', onExit);
    if (child.exitCode !== null || child.signalCode !== null) {
      onExit();
      throw new Error('Pentect exited immediately after provider startup.');
    }
    return ready;
  }

  private stop(): void {
    const child = this.child;
    this.child = undefined;
    this.ready = undefined;
    if (!child) {
      return;
    }
    terminate(child);
  }
}

function terminate(child: ChildProcessWithoutNullStreams): void {
  child.stdin.end();
  if (!child.killed) {
    child.kill();
  }
}

export function parseReady(line: string): BackendReady {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new Error('Pentect returned an invalid provider handshake.');
  }
  if (!isRecord(value) || value.protocol !== 1 || typeof value.baseUrl !== 'string' || typeof value.model !== 'string') {
    throw new Error('Pentect returned an unsupported provider handshake.');
  }

  const url = new URL(value.baseUrl);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.search || url.hash) {
    throw new Error('Pentect returned an unsafe provider address.');
  }
  if (!/^\/[0-9a-f]{64}\/?$/.test(url.pathname)) {
    throw new Error('Pentect returned an invalid local authorization path.');
  }
  return { protocol: 1, baseUrl: url.toString().replace(/\/$/, ''), model: nonEmpty(value.model, 'model') };
}

async function firstLine(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    let timer: NodeJS.Timeout;
    const cleanup = () => {
      clearTimeout(timer);
      child.off('error', onError);
      child.off('exit', onExit);
      child.stdout.off('data', onData);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(new Error(`Could not start Pentect: ${error.message}`));
    };
    const onExit = (code: number | null) => {
      cleanup();
      reject(new Error(`Pentect exited before startup${code === null ? '' : ` (code ${code})`}.`));
    };
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length > MAX_HANDSHAKE_BYTES) {
        cleanup();
        reject(new Error('Pentect provider handshake exceeded 16 KiB.'));
        return;
      }
      const newline = buffered.indexOf(0x0a);
      if (newline === -1) {
        return;
      }
      const line = buffered.subarray(0, newline).toString('utf8').replace(/\r$/, '');
      cleanup();
      resolve(line);
    };
    timer = setTimeout(() => {
      cleanup();
      reject(new Error('Pentect did not start within 10 seconds.'));
    }, timeoutMs);
    child.once('error', onError);
    child.once('exit', onExit);
    child.stdout.on('data', onData);
  });
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
