import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const expectedVersion = process.argv[2];
const piVersion = process.argv[3];
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
  if (!`${models.stdout}${models.stderr}`.includes("pentect/gpt-5")) {
    throw new Error("Pi did not discover the Pentect provider extension");
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
