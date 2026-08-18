#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { ensureInstalled } from '../install.js';

let executable;
try {
  executable = await ensureInstalled();
} catch (error) {
  console.error(`pentect: ${error.message}`);
  process.exit(1);
}

const result = spawnSync(executable, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) {
  console.error(`pentect: ${result.error.message}`);
  process.exitCode = 1;
} else if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exitCode = result.status ?? 1;
}
