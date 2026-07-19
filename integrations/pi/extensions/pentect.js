import { spawn } from "node:child_process";
import { delimiter, dirname } from "node:path";
import {
  createBashTool,
  createLocalBashOperations,
} from "@earendil-works/pi-coding-agent";

const SAFE_TEXT = "[Content unavailable]";
const BRIDGE_REQUEST_TIMEOUT_MS = 10_000;
const REQUIRED_SESSION_ENVIRONMENT = [
  "PENTECT_BIN",
  "PENTECT_MEMORY_STORE_ADDR",
  "PENTECT_MEMORY_STORE_TOKEN",
  "PENTECT_AGENT_LAUNCHED",
];
const SESSION_ENVIRONMENT = new Set([
  ...REQUIRED_SESSION_ENVIRONMENT,
  "PENTECT_EXTENSION_CONFIGS",
  "PENTECT_EXTENSION_ADAPTERS",
]);

function replaceObject(target, source) {
  for (const key of Object.keys(target)) delete target[key];
  Object.assign(target, source);
}

function createPentectBridge() {
  const child = spawn("pentect", ["bridge"], {
    stdio: ["pipe", "pipe", "ignore"],
    windowsHide: true,
  });
  let nextId = 1;
  const pending = new Map();
  let buffered = "";
  let closed = false;

  const fail = () => {
    if (closed) return;
    closed = true;
    for (const { reject, timer } of pending.values()) {
      clearTimeout(timer);
      reject(new Error("Pentect unavailable"));
    }
    pending.clear();
  };

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffered += chunk;
    for (;;) {
      const end = buffered.indexOf("\n");
      if (end < 0) break;
      const line = buffered.slice(0, end);
      buffered = buffered.slice(end + 1);
      let response;
      try {
        response = JSON.parse(line);
      } catch {
        child.kill();
        fail();
        return;
      }
      const waiter = pending.get(response.id);
      if (!waiter) continue;
      pending.delete(response.id);
      clearTimeout(waiter.timer);
      if (response.ok) {
        waiter.resolve(response.value);
      } else {
        const error = new Error(response.error?.message || "Operation unavailable");
        error.code = response.error?.code;
        error.phase = response.error?.phase;
        error.executed = response.error?.executed === true;
        waiter.reject(error);
      }
    }
  });
  child.on("error", fail);
  child.on("exit", fail);

  return {
    request(op, fields = {}) {
      if (closed) return Promise.reject(new Error("Pentect unavailable"));
      const id = nextId++;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          if (!pending.delete(id)) return;
          reject(new Error("Pentect unavailable"));
          child.kill();
          fail();
        }, BRIDGE_REQUEST_TIMEOUT_MS);
        pending.set(id, { resolve, reject, timer });
        try {
          child.stdin.write(
            `${JSON.stringify({ id, op, ...fields })}\n`,
            (error) => {
              if (!error) return;
              const waiter = pending.get(id);
              if (!waiter) return;
              pending.delete(id);
              clearTimeout(waiter.timer);
              reject(new Error("Pentect unavailable"));
              child.kill();
              fail();
            },
          );
        } catch {
          pending.delete(id);
          clearTimeout(timer);
          reject(new Error("Pentect unavailable"));
          child.kill();
          fail();
        }
      });
    },
    close() {
      if (closed) return;
      for (const { reject, timer } of pending.values()) {
        clearTimeout(timer);
        reject(new Error("Pentect unavailable"));
      }
      pending.clear();
      closed = true;
      child.kill();
    },
  };
}

function protectedChildEnvironment(optionsEnvironment, sessionEnvironment) {
  const environment = { ...process.env, ...optionsEnvironment };
  for (const name of Object.keys(environment)) {
    if (name.toUpperCase().startsWith("PENTECT_")) delete environment[name];
  }
  Object.assign(environment, sessionEnvironment);
  const pathName =
    Object.keys(environment).find((name) => name.toUpperCase() === "PATH") ||
    "PATH";
  const currentPath = environment[pathName] || "";
  environment[pathName] = `${dirname(sessionEnvironment.PENTECT_BIN)}${delimiter}${currentPath}`;
  return environment;
}

function readSessionEnvironment(values) {
  if (!values || typeof values !== "object" || Array.isArray(values)) {
    throw new Error("Pentect returned an invalid session");
  }
  for (const [name, value] of Object.entries(values)) {
    if (!SESSION_ENVIRONMENT.has(name) || typeof value !== "string" || !value) {
      throw new Error("Pentect returned an invalid session");
    }
  }
  for (const required of REQUIRED_SESSION_ENVIRONMENT) {
    if (typeof values[required] !== "string" || !values[required]) {
      throw new Error("Pentect returned an incomplete session");
    }
  }
  return Object.freeze({ ...values });
}

export default function pentectExtension(pi) {
  const localBash = createLocalBashOperations();
  let bridge;
  let contract = "";
  let sessionEnvironment;

  const activeBridge = () => {
    if (!bridge) throw new Error("Pentect unavailable");
    return bridge;
  };

  const protectedBash = {
    async exec(command, cwd, options) {
      const next = await activeBridge().request("before", {
        tool: "bash",
        value: { command },
      });
      if (!next || typeof next.command !== "string") {
        throw new Error("Pentect rejected the command");
      }
      if (!sessionEnvironment) throw new Error("Pentect unavailable");
      // The bridge keeps execution in Pi's Bash and masks each streamed chunk
      // before Pi's onData callback receives it.
      return localBash.exec(next.command, cwd, {
        ...options,
        env: protectedChildEnvironment(options.env, sessionEnvironment),
      });
    },
  };

  pi.on("session_start", async (_event, ctx) => {
    bridge?.close();
    sessionEnvironment = undefined;
    contract = "";
    bridge = createPentectBridge();
    try {
      const session = await bridge.request("session");
      if (!session || typeof session.contract !== "string") {
        throw new Error("Pentect returned an invalid session");
      }
      sessionEnvironment = readSessionEnvironment(session.environment);
      contract = session.contract;
      pi.registerTool(
        createBashTool(ctx.cwd, {
          operations: protectedBash,
        }),
      );
    } catch {
      bridge.close();
      bridge = undefined;
      throw new Error("Pentect unavailable");
    }
  });

  pi.on("before_agent_start", async (event) => {
    if (!contract || event.systemPrompt.includes(contract)) return {};
    return { systemPrompt: `${event.systemPrompt}\n\n${contract}` };
  });

  pi.on("input", async (event, ctx) => {
    try {
      const text = await activeBridge().request("prompt", { value: event.text });
      const images = event.images
        ? await activeBridge().request("media", { value: event.images })
        : event.images;
      return { action: "transform", text, images };
    } catch {
      if (ctx.hasUI) ctx.ui.notify("Pentect unavailable", "error");
      return { action: "handled" };
    }
  });

  pi.on("tool_call", async (event) => {
    if (event.toolName === "bash") return {};
    try {
      const next = await activeBridge().request("before", {
        tool: event.toolName,
        value: event.input,
      });
      replaceObject(event.input, next);
      return {};
    } catch (error) {
      return { block: true, reason: error?.message || "Tool unavailable" };
    }
  });

  pi.on("tool_result", async (event) => {
    try {
      return await activeBridge().request("after", {
        tool: event.toolName,
        input: event.input,
        value: {
          content: event.content,
          details: event.details,
          isError: event.isError,
        },
      });
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: error?.executed
              ? "Tool completed, but its output was unavailable. Check side effects before retrying."
              : SAFE_TEXT,
          },
        ],
        details: event.details,
        isError: event.isError,
      };
    }
  });

  pi.on("user_bash", async () => ({ operations: protectedBash }));

  pi.on("session_shutdown", async () => {
    bridge?.close();
    bridge = undefined;
    contract = "";
    sessionEnvironment = undefined;
  });
}
