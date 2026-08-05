import { access, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = path.join(root, 'src', 'content', 'docs');
const distRoot = path.join(root, 'dist');
const sourceFiles = await findFiles(sourceRoot, /\.mdx?$/i);
const problems = [];
let checked = 0;

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
