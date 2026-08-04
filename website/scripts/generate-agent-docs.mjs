import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import remarkGfm from 'remark-gfm';
import remarkMdx from 'remark-mdx';
import remarkParse from 'remark-parse';
import remarkStringify from 'remark-stringify';
import { unified } from 'unified';

const websiteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = path.join(websiteRoot, 'src', 'content', 'docs');
const distRoot = path.join(websiteRoot, 'dist');
const sourceFiles = await findSourceFiles(sourceRoot);
const processor = unified()
  .use(remarkParse)
  .use(remarkMdx)
  .use(remarkGfm)
  .use(remarkStringify, {
    bullet: '-',
    fences: true,
    listItemIndent: 'one',
  });

let generated = 0;

for (const sourcePath of sourceFiles) {
  const source = await readFile(sourcePath, 'utf8');
  const { attributes, body } = splitFrontmatter(source);
  const title = frontmatterValue(attributes, 'title');
  if (!title) {
    throw new Error(`Agent Markdown generation found no title in ${sourcePath}`);
  }

  const relativeSourcePath = path.relative(sourceRoot, sourcePath).split(path.sep).join('/');
  const defaultSlug = relativeSourcePath
    .replace(/\.(md|mdx)$/i, '')
    .replace(/(^|\/)index$/, '');
  const slug = frontmatterValue(attributes, 'slug') ?? defaultSlug;
  const route = slug ? `/${slug.replace(/^\/+|\/+$/g, '')}/` : '/';
  const outputDirectory = path.join(distRoot, route.slice(1));
  const tree = processor.parse(body);
  const description = frontmatterValue(attributes, 'description');
  tree.children = [
    heading(title),
    ...(description ? [paragraph(description)] : []),
    ...rewriteNodes(tree.children),
  ];
  const markdown = processor.stringify(tree).trim();

  if (!markdown.startsWith('# ')) {
    throw new Error(`Agent Markdown generation produced no page heading for ${sourcePath}`);
  }

  const generatedNotice = [
    '<!-- Generated from the canonical documentation source. Do not edit directly. -->',
    `Canonical: ${new URL(route, 'https://pentect.dev').href}`,
    '',
  ].join('\n');

  await writeFile(
    path.join(outputDirectory, 'index.md'),
    `${generatedNotice}${markdown}\n`,
    'utf8',
  );
  generated += 1;
}

if (generated === 0) {
  throw new Error('Agent Markdown generation found no documentation pages');
}

console.log(`Generated ${generated} agent-readable Markdown pages.`);

function splitFrontmatter(source) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!match) return { attributes: '', body: source };
  return {
    attributes: match[1],
    body: source.slice(match[0].length),
  };
}

function frontmatterValue(attributes, key) {
  const match = attributes.match(new RegExp(`^${key}:\\s*(.+?)\\s*$`, 'm'));
  if (!match) return undefined;
  return match[1].replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, '$1$2').trim();
}

function rewriteNodes(nodes) {
  return nodes.flatMap((node) => {
    if (node.type === 'mdxjsEsm' || node.type === 'mdxFlowExpression') return [];
    if (node.type === 'mdxTextExpression') return [];

    if (node.type === 'mdxJsxFlowElement' || node.type === 'mdxJsxTextElement') {
      const children = rewriteNodes(node.children ?? []);
      const label = componentLabel(node);
      return label ? [heading(label, 3), ...children] : children;
    }

    if (Array.isArray(node.children)) {
      node.children = rewriteNodes(node.children);
    }
    return [node];
  });
}

function componentLabel(node) {
  if (!['TabItem', 'Card'].includes(node.name)) return undefined;
  const attributeName = node.name === 'TabItem' ? 'label' : 'title';
  const attribute = node.attributes?.find(
    (item) => item.type === 'mdxJsxAttribute' && item.name === attributeName,
  );
  return typeof attribute?.value === 'string' ? attribute.value : undefined;
}

function heading(value, depth = 1) {
  return {
    type: 'heading',
    depth,
    children: [{ type: 'text', value }],
  };
}

function paragraph(value) {
  return {
    type: 'paragraph',
    children: [{ type: 'text', value }],
  };
}

async function findSourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map((entry) => {
      const entryPath = path.join(directory, entry.name);
      return entry.isDirectory() ? findSourceFiles(entryPath) : [entryPath];
    }),
  );

  return files.flat().filter((file) => /\.(md|mdx)$/i.test(file));
}
