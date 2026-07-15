import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import pentectExtension from "../extensions/pentect.js";

const e2eBin = process.env.PENTECT_E2E_BIN
  ? process.platform === "win32" &&
    !process.env.PENTECT_E2E_BIN.toLowerCase().endsWith(".exe")
    ? `${process.env.PENTECT_E2E_BIN}.exe`
    : process.env.PENTECT_E2E_BIN
  : undefined;
const privateSessionEnvironment = [
  "PENTECT_MEMORY_STORE_ADDR",
  "PENTECT_MEMORY_STORE_TOKEN",
  "PENTECT_PROCESS_HOST_READ_TOKEN",
  "PENTECT_PROCESS_HOST_WRITE_TOKEN",
  "PENTECT_PROCESS_HOST_ROOT",
  "PENTECT_AGENT_LAUNCHED",
];

class TestPi {
  constructor() {
    this.handlers = new Map();
    this.tools = new Map();
  }

  on(name, handler) {
    const handlers = this.handlers.get(name) || [];
    handlers.push(handler);
    this.handlers.set(name, handlers);
  }

  registerTool(tool) {
    this.tools.set(tool.name, tool);
  }

  async emit(name, event, context = {}) {
    const results = [];
    for (const handler of this.handlers.get(name) || []) {
      results.push(await handler(event, context));
    }
    return results;
  }
}

test(
  "native Pi extension shares one protected session",
  { skip: !e2eBin },
  async () => {
    const originalBin = process.env.PENTECT_BIN;
    const originalPath = process.env.PATH;
    process.env.PENTECT_BIN = e2eBin;
    process.env.PATH = `${dirname(e2eBin)}${delimiter}${originalPath || ""}`;
    const pi = new TestPi();
    pentectExtension(pi);

    try {
      await pi.emit(
        "session_start",
        { reason: "startup" },
        { cwd: process.cwd() },
      );
      for (const name of privateSessionEnvironment) {
        assert.equal(process.env[name], undefined, `${name} escaped into Pi`);
      }

      const contract = (
        await pi.emit("before_agent_start", { systemPrompt: "Pi" })
      )[0].systemPrompt;
      assert.match(contract, /Pentect agent contract/);

      const raw = ["sk-", "ABCDEFGHIJKLMNOPQRSTUVWX"].join("");
      const input = (
        await pi.emit(
          "input",
          {
            text: `OPENAI_API_KEY=${raw}`,
            source: "interactive",
          },
          { hasUI: false },
        )
      )[0];
      assert.equal(input.action, "transform");
      assert.doesNotMatch(input.text, new RegExp(raw));
      assert.match(input.text, /<<OPENAI_API_KEY_[a-f0-9]+>>/);

      const handle = input.text.split("=")[1];
      const alias = `PENTECT_${handle.slice(2, -2)}`;
      const command =
        process.platform === "win32"
          ? `Write-Output $env:${alias}`
          : `printf '%s\\n' "$${alias}"`;
      const updates = [];
      const toolInput = { command };
      const result = await pi.tools.get("bash").execute(
        "call-1",
        toolInput,
        undefined,
        (update) => updates.push(update),
        {},
      );
      const rendered = JSON.stringify({ result, updates });
      assert.doesNotMatch(rendered, new RegExp(raw));
      assert.match(rendered, /<<OPENAI_API_KEY_[a-f0-9]+>>/);
      assert.equal(toolInput.command, command);

      const connector = (
        await pi.emit("tool_result", {
          toolName: "connector",
          input: {},
          content: [{ type: "text", text: `OPENAI_API_KEY=${raw}` }],
          details: undefined,
          isError: false,
        })
      )[0];
      const renderedConnector = JSON.stringify(connector);
      assert.doesNotMatch(renderedConnector, new RegExp(raw));
      assert.match(renderedConnector, /<<OPENAI_API_KEY_[a-f0-9]+>>/);
      assert.equal(connector.isError, false);
    } finally {
      await pi.emit("session_shutdown", { reason: "quit" });
      if (originalBin === undefined) delete process.env.PENTECT_BIN;
      else process.env.PENTECT_BIN = originalBin;
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
    }
  },
);

test(
  "official Pi loads the package extension",
  { skip: !e2eBin, timeout: 30_000 },
  async () => {
    const agentDir = await mkdtemp(join(tmpdir(), "pentect-pi-"));
    const cli = fileURLToPath(
      new URL(
        "../node_modules/@earendil-works/pi-coding-agent/dist/cli.js",
        import.meta.url,
      ),
    );
    const extension = fileURLToPath(
      new URL("../extensions/pentect.js", import.meta.url),
    );
    try {
      const result = await new Promise((resolve, reject) => {
        const child = spawn(
          process.execPath,
          [cli, "-e", extension, "--mode", "rpc", "--no-session"],
          {
            env: {
              ...process.env,
              PATH: `${dirname(e2eBin)}${delimiter}${process.env.PATH || ""}`,
              PENTECT_BIN: e2eBin,
              PI_CODING_AGENT_DIR: agentDir,
            },
            stdio: ["pipe", "pipe", "pipe"],
            windowsHide: true,
          },
        );
        let stdout = "";
        let stderr = "";
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk) => (stdout += chunk));
        child.stderr.on("data", (chunk) => (stderr += chunk));
        child.on("error", reject);
        child.on("close", (code) => resolve({ code, stdout, stderr }));
        child.stdin.end(`${JSON.stringify({ id: "state", type: "get_state" })}\n`);
      });
      assert.equal(result.code, 0, result.stderr);
      const responses = result.stdout
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      assert.ok(
        responses.some(
          (response) =>
            response.id === "state" &&
            response.type === "response" &&
            response.success === true,
        ),
        result.stdout,
      );
    } finally {
      await rm(agentDir, { recursive: true, force: true });
    }
  },
);
