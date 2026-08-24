#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureInstalled } from '../install.js';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

function localProjectRoot() {
  const candidate = resolve(packageRoot, '../..');
  try {
    const metadata = JSON.parse(readFileSync(resolve(candidate, 'package.json'), 'utf8'));
    const sections = ['dependencies', 'devDependencies', 'optionalDependencies'];
    if (sections.some((section) => Object.hasOwn(metadata[section] || {}, 'pentect'))) {
      return candidate;
    }
  } catch {
    // A global package has no owning project package.json above node_modules.
  }
  return undefined;
}

let executable;
try {
  executable = await ensureInstalled();
} catch (error) {
  console.error(`pentect: ${error.message}`);
  process.exit(1);
}

const projectRoot = localProjectRoot();
const result = spawnSync(executable, process.argv.slice(2), {
  stdio: 'inherit',
  env: {
    ...process.env,
    PENTECT_NPM_PACKAGE_ROOT: packageRoot,
    PENTECT_NPM_SCOPE: projectRoot ? 'local' : 'global',
    ...(projectRoot ? { PENTECT_NPM_PROJECT_ROOT: projectRoot } : {}),
  },
});
if (result.error) {
  console.error(`pentect: ${result.error.message}`);
  process.exitCode = 1;
} else if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exitCode = result.status ?? 1;
}
