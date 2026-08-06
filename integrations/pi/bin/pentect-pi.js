#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createRequire } from "node:module";
import { invocation, piBinaryFromEntry } from "../lib/command.js";

const require = createRequire(import.meta.url);

function packageBinary(name, binary) {
  const manifestPath = require.resolve(`${name}/package.json`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const relative =
    typeof manifest.bin === "string" ? manifest.bin : manifest.bin?.[binary];
  if (typeof relative !== "string" || relative.length === 0) {
    throw new Error(`${name} does not provide the expected ${binary} command`);
  }
  return resolve(dirname(manifestPath), relative);
}

try {
  const pentectCli = packageBinary("pentect", "pentect");
  // Pi exports dist/index.js but intentionally does not export package.json.
  // Its pinned package exposes the adjacent dist/cli.js as the `pi` binary.
  const piCli = piBinaryFromEntry(
    require.resolve("@mariozechner/pi-coding-agent"),
  );
  const next = invocation(pentectCli, piCli, process.argv.slice(2));
  const result = spawnSync(next.command, next.args, { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.signal) process.kill(process.pid, result.signal);
  process.exitCode = result.status ?? 1;
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`pentect-pi: ${message}`);
  process.exitCode = 1;
}
