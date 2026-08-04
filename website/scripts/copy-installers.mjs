import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(websiteRoot, '..');
const outputRoot = resolve(websiteRoot, 'dist');

const installers = [
  ['tools/install.ps1', 'install/index.html'],
  ['tools/install.sh', 'install.sh'],
  ['tools/install-apt.sh', 'install-apt.sh'],
];

await Promise.all(
  installers.map(async ([source, destination]) => {
    const output = resolve(outputRoot, destination);
    await mkdir(dirname(output), { recursive: true });
    await copyFile(resolve(repositoryRoot, source), output);
  }),
);

console.log(`Published ${installers.length} installer endpoints.`);
