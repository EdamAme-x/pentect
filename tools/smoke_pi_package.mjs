import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const expectedVersion = process.argv[2];
const piVersion = process.argv[3];
const usePublishedBackend = process.argv.includes("--published-backend");
if (!expectedVersion) throw new Error("expected @pentect/pi version is required");
if (!piVersion) throw new Error("expected Pi version is required");

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const tempDir = mkdtempSync(join(tmpdir(), "pentect-pi-smoke-"));

function runResult(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: process.platform === "win32" && command.endsWith(".cmd"),
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr || `${command} exited with ${result.status}`);
  }
  return result;
}

function run(command, args, options = {}) {
  return runResult(command, args, options).stdout;
}

try {
  const packed = JSON.parse(
    run(
      npm,
      ["pack", "--json", "--pack-destination", tempDir],
      { stdio: ["ignore", "pipe", "inherit"] },
    ),
  );
  if (!Array.isArray(packed) || typeof packed[0]?.filename !== "string") {
    throw new Error("npm pack did not return a tarball filename");
  }

  const prefix = join(tempDir, "install");
  run(
    npm,
    [
      "install",
      "--global",
      "--prefix",
      prefix,
      join(tempDir, packed[0].filename),
      "--no-audit",
      "--no-fund",
    ],
    { stdio: "inherit" },
  );

  const packageRoot = join(
    prefix,
    ...(process.platform === "win32" ? [] : ["lib"]),
    "node_modules",
    "@pentect",
    "pi",
  );
  const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  if (manifest.version !== expectedVersion) {
    throw new Error(`expected @pentect/pi ${expectedVersion}, got ${manifest.version}`);
  }
  if (manifest.pi?.extensions?.[0] !== "extensions/pentect.js") {
    throw new Error("@pentect/pi does not declare its Pi extension");
  }
  const extension = await import(pathToFileURL(join(packageRoot, "extensions", "pentect.js")));
  const ready = extension.parseReady(JSON.stringify({
    protocol: 1,
    integration: "pi",
    baseUrl: `http://127.0.0.1:43123/${"a".repeat(64)}`,
    model: "gpt-5",
    api: "openai-completions",
  }));
  if (extension.providerDefinition(ready).models[0]?.id !== "gpt-5") {
    throw new Error("@pentect/pi extension could not register its model");
  }

  if (!usePublishedBackend) {
    // Pull-request CI cannot install an unpublished Rust backend. Use the
    // backend protocol fixture there; release CI uses the published binary.
    const packageRequire = createRequire(join(packageRoot, "package.json"));
    const pentectRoot = dirname(packageRequire.resolve("pentect/package.json"));
    writeFileSync(
      join(pentectRoot, "packaging", "npm", "bin", "pentect.js"),
      `#!/usr/bin/env node
const args = process.argv.slice(2);
const modelIndex = args.indexOf("--model");
const apiIndex = args.indexOf("--api");
const api = ["responses", "openai-responses"].includes(args[apiIndex + 1])
  ? "openai-responses"
  : "openai-completions";
console.log(JSON.stringify({
  protocol: 1,
  integration: "pi",
  baseUrl: "http://127.0.0.1:43123/${"a".repeat(64)}",
  model: args[modelIndex + 1] || "gpt-5",
  api,
}));
process.stdin.resume();
`,
    );
  }

  run(
    npm,
    [
      "install",
      "--global",
      "--prefix",
      prefix,
      `@earendil-works/pi-coding-agent@${piVersion}`,
      "--no-audit",
      "--no-fund",
    ],
    { stdio: "inherit" },
  );
  const pi = process.platform === "win32" ? join(prefix, "pi.cmd") : join(prefix, "bin", "pi");
  const models = runResult(pi, ["-e", packageRoot, "--list-models"], {
    env: {
      ...process.env,
      OPENAI_API_KEY: "sk-test-pi-extension-never-valid-123456789",
      OPENAI_BASE_URL: "http://127.0.0.1:9/v1",
    },
  });
  if (!/\bpentect\s+gpt-5\b/.test(`${models.stdout}${models.stderr}`)) {
    throw new Error("Pi did not discover the Pentect provider extension");
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
