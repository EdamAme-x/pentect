const { spawn } = require("node:child_process");

const childMarker = "PENTECT_CODEX_APP_SMOKE_CHILD";

if (process.env[childMarker] === "1") {
  // Stay alive long enough for Pentect's process probe to observe this exact
  // executable, then exit so the smoke test can verify session cleanup.
  setTimeout(() => process.exit(0), 5_000);
} else {
  const child = spawn(process.execPath, [], {
    detached: true,
    stdio: "ignore",
    env: { ...process.env, [childMarker]: "1" },
  });
  child.unref();
  process.exit(0);
}
