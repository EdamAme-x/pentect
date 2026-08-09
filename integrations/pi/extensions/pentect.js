import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";

const require = createRequire(import.meta.url);
const STATE = Symbol.for("@pentect/pi/provider-state");
const MAX_READY_BYTES = 16 * 1024;
const START_TIMEOUT_MS = 10_000;

function sharedState() {
  if (!globalThis[STATE]) {
    globalThis[STATE] = {
      openaiApiKey: process.env.OPENAI_API_KEY,
      upstreamAuthorization: process.env.PENTECT_UPSTREAM_AUTHORIZATION,
    };
  }
  return globalThis[STATE];
}

export function providerArguments(env = process.env) {
  const model = env.PENTECT_PI_MODEL?.trim() || "gpt-5";
  const api = env.PENTECT_PI_API?.trim() || "chat";
  return ["provider", "pi", "--model", model, "--api", api];
}

export function parseReady(line) {
  let ready;
  try {
    ready = JSON.parse(line);
  } catch {
    throw new Error("Pentect provider returned invalid readiness data");
  }
  if (
    ready?.protocol !== 1 ||
    ready?.integration !== "pi" ||
    typeof ready?.baseUrl !== "string" ||
    !/^http:\/\/127\.0\.0\.1:\d+\/[a-f0-9]{64}\/?$/.test(ready.baseUrl) ||
    typeof ready?.model !== "string" ||
    !["openai-completions", "openai-responses"].includes(ready?.api)
  ) {
    throw new Error("Pentect provider returned unsupported readiness data");
  }
  return ready;
}

export function providerDefinition(ready) {
  return {
    name: "Pentect",
    baseUrl: ready.baseUrl,
    apiKey: "pentect-local",
    authHeader: true,
    api: ready.api,
    models: [
      {
        id: ready.model,
        name: ready.model,
        reasoning: ready.api === "openai-responses",
        input: ["text", "image"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 128000,
        maxTokens: 32768,
      },
    ],
  };
}

function pentectScript() {
  const manifest = require.resolve("pentect/package.json");
  return resolve(dirname(manifest), "packaging", "npm", "bin", "pentect.js");
}

async function startProvider() {
  const state = sharedState();
  const env = { ...process.env };
  if (state.openaiApiKey) env.OPENAI_API_KEY = state.openaiApiKey;
  else delete env.OPENAI_API_KEY;
  if (state.upstreamAuthorization) {
    env.PENTECT_UPSTREAM_AUTHORIZATION = state.upstreamAuthorization;
  } else {
    delete env.PENTECT_UPSTREAM_AUTHORIZATION;
  }

  const child = spawn(
    process.execPath,
    [pentectScript(), ...providerArguments(env)],
    { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
  );
  process.env.OPENAI_API_KEY = "pentect-local";
  delete process.env.PENTECT_UPSTREAM_AUTHORIZATION;

  let errors = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    if (errors.length < MAX_READY_BYTES) {
      errors += chunk.slice(0, MAX_READY_BYTES - errors.length);
    }
  });

  try {
    const line = await firstLine(child);
    return { child, ready: parseReady(line) };
  } catch (error) {
    child.kill();
    const detail = errors.trim();
    throw new Error(detail || error.message, { cause: error });
  }
}

function firstLine(child) {
  return new Promise((resolveLine, reject) => {
    let output = "";
    const timeout = setTimeout(() => {
      reject(new Error("Pentect provider did not become ready"));
    }, START_TIMEOUT_MS);
    timeout.unref?.();

    const finish = (callback, value) => {
      clearTimeout(timeout);
      child.stdout.removeAllListeners();
      child.removeListener("error", onError);
      child.removeListener("exit", onExit);
      callback(value);
    };
    const onError = (error) => finish(reject, error);
    const onExit = (code) =>
      finish(reject, new Error(`Pentect provider exited before startup (${code})`));

    child.once("error", onError);
    child.once("exit", onExit);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      output += chunk;
      if (output.length > MAX_READY_BYTES) {
        finish(reject, new Error("Pentect provider readiness data is too large"));
        return;
      }
      const newline = output.indexOf("\n");
      if (newline >= 0) finish(resolveLine, output.slice(0, newline));
    });
  });
}

function stopProvider(child) {
  if (!child || child.exitCode !== null || child.killed) return;
  child.stdin.end();
  const timeout = setTimeout(() => child.kill(), 2_000);
  timeout.unref?.();
  child.once("exit", () => clearTimeout(timeout));
}

export default async function pentect(pi) {
  const { child, ready } = await startProvider();
  pi.registerProvider("pentect", providerDefinition(ready));
  pi.on("session_shutdown", () => stopProvider(child));
}
