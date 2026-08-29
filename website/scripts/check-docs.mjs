import { access, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = path.join(root, 'src', 'content', 'docs');
const distRoot = path.join(root, 'dist');
const sourceFiles = await findFiles(sourceRoot, /\.mdx?$/i);
const problems = [];
let checked = 0;

await checkDetectorInventory(problems);

for (const file of sourceFiles) {
  const source = await readFile(file, 'utf8');
  const urls = [
    ...source.matchAll(/\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g),
    ...source.matchAll(/\bhref=["']([^"']+)["']/g),
  ].map((match) => match[1]);

  for (const url of urls) {
    if (!url.startsWith('/') || url.startsWith('//')) continue;
    checked += 1;
    const pathname = decodeURIComponent(url.split(/[?#]/, 1)[0]);
    const relative = pathname.replace(/^\/+/, '');
    const candidates = path.extname(relative)
      ? [path.join(distRoot, relative)]
      : [path.join(distRoot, relative, 'index.html')];
    if (pathname === '/') candidates[0] = path.join(distRoot, 'index.html');

    if (!(await anyExists(candidates))) {
      problems.push(`${path.relative(root, file)} -> ${url}`);
    }
  }
}

const generatedMarkdown = await findFiles(distRoot, /index\.md$/i);
if (generatedMarkdown.length !== sourceFiles.length) {
  problems.push(
    `generated Markdown page count is ${generatedMarkdown.length}; expected ${sourceFiles.length}`,
  );
}

if (problems.length) {
  throw new Error(`Documentation checks failed:\n${problems.map((item) => `- ${item}`).join('\n')}`);
}

console.log(`Checked ${sourceFiles.length} pages and ${checked} internal links.`);

async function anyExists(paths) {
  for (const candidate of paths) {
    try {
      await access(candidate);
      return true;
    } catch {
      // Try the next valid representation.
    }
  }
  return false;
}

async function findFiles(directory, pattern) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? findFiles(target, pattern) : [target];
  }));
  return nested.flat().filter((file) => pattern.test(file));
}

async function checkDetectorInventory(problems) {
  const repositoryRoot = path.resolve(root, '..');
  const inventoryPath = path.join(sourceRoot, 'protection', 'detectors.md');
  const inventory = await readFile(inventoryPath, 'utf8');
  const pipeline = await readFile(
    path.join(repositoryRoot, 'crates', 'pentect-core', 'src', 'pipeline', 'mod.rs'),
    'utf8',
  );
  const masking = await readFile(
    path.join(repositoryRoot, 'crates', 'pentect-runtime', 'src', 'masking.rs'),
    'utf8',
  );
  const credSweeper = JSON.parse(await readFile(
    path.join(
      repositoryRoot,
      'crates',
      'pentect-core',
      'vendors',
      'credsweeper-assets',
      'SOURCE.json',
    ),
    'utf8',
  ));
  const alcatraz = JSON.parse(await readFile(
    path.join(repositoryRoot, 'tools', 'alcatraz-helper', 'SOURCE.json'),
    'utf8',
  ));

  const standardStart = pipeline.indexOf('pub fn standard_stack_with_decode');
  const standardEnd = pipeline.indexOf('pub fn secret_scan_stack', standardStart);
  if (standardStart < 0 || standardEnd < 0) {
    problems.push('could not locate the standard detector stack');
    return;
  }
  const registrations = `${pipeline.slice(standardStart, standardEnd)}\n${masking}`;
  const detectors = new Set(
    [...registrations.matchAll(/Box::new\((?:crate::alcatraz::)?([A-Za-z]+Detector)/g)]
      .map((match) => match[1]),
  );
  const documentedDetectors = new Set(
    [...inventory.matchAll(/^\| `([A-Za-z]+Detector)` \|/gm)].map((match) => match[1]),
  );
  for (const detector of [...detectors].sort()) {
    if (!documentedDetectors.has(detector)) {
      problems.push(`detector inventory is missing ${detector}`);
    }
  }
  for (const detector of [...documentedDetectors].sort()) {
    if (!detectors.has(detector)) {
      problems.push(`detector inventory lists unregistered ${detector}`);
    }
  }
  for (const source of [credSweeper, alcatraz]) {
    for (const field of ['version', 'commit']) {
      if (!inventory.includes(source[field])) {
        problems.push(`detector inventory is missing ${source.repository} ${field} ${source[field]}`);
      }
    }
  }
}
