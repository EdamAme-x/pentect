import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const expectedVersion = process.argv[2];
if (!expectedVersion) throw new Error("expected Pi version is required");

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

  const launcher =
    process.platform === "win32"
      ? process.execPath
      : join(prefix, "bin", "pentect-pi");
  const launcherArgs =
    process.platform === "win32"
      ? [
          join(
            prefix,
            "node_modules",
            "@pentect",
            "pi",
            "bin",
            "pentect-pi.js",
          ),
          "--version",
        ]
      : ["--version"];
  const versionResult = runResult(launcher, launcherArgs);
  const actualVersion = `${versionResult.stdout}${versionResult.stderr}`.trim();
  if (actualVersion !== expectedVersion) {
    throw new Error(`expected Pi ${expectedVersion}, got ${actualVersion}`);
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
