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
  const agentTitle = title.endsWith('_') ? title.slice(0, -1) : title;
  const agentBody = body.replace(/^:::\s*(?:code-group|tip|info|warning|danger)?\s*$/gm, '');
  const tree = processor.parse(agentBody);
  const description = frontmatterValue(attributes, 'description');
  tree.children = [
    heading(agentTitle),
    ...(description ? [paragraph(description)] : []),
    ...rewriteNodes(tree.children),
  ];
  const markdown = processor.stringify(tree).trim();

  if (!markdown.startsWith('# ')) {
    throw new Error(`Agent Markdown generation produced no page heading for ${sourcePath}`);
  }

  await writeFile(
    path.join(outputDirectory, 'index.md'),
    `${markdown}\n`,
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
      if (node.name === 'HomeInstall') {
        return [
          heading('Install', 2),
          paragraph('Choose one install method for your operating system.'),
          heading('npm — Windows, macOS, and Linux', 3),
          codeBlock('npm i -g pentect', 'sh'),
          heading('PowerShell — Windows', 3),
          codeBlock('irm https://pentect.dev/install | iex', 'powershell'),
          heading('Shell — macOS and Linux', 3),
          codeBlock('curl -fsSL https://pentect.dev/install.sh | sh', 'sh'),
          heading('Homebrew — macOS', 3),
          codeBlock('brew install EdamAme-x/pentect/pentect', 'sh'),
          heading('Nix — profile', 3),
          codeBlock('nix profile install github:EdamAme-x/pentect#pentect', 'sh'),
          heading('Nix — run without installing', 3),
          codeBlock('nix run github:EdamAme-x/pentect#pentect -- version', 'sh'),
          heading('APT — Debian and Ubuntu', 3),
          codeBlock('curl -fsSL https://pentect.dev/install-apt.sh | sudo sh', 'sh'),
          heading('AUR — Arch Linux', 3),
          codeBlock('paru -S pentect-bin', 'sh'),
          paragraph('For the development package, use `paru -S pentect-git`. `paru` is only an example; other AUR helpers or makepkg work too.'),
        ];
      }
      if (node.name === 'QuickInstall') {
        return [
          heading('Install', 2),
          paragraph('Use the recommended installer for your operating system, or open the install page for every package manager.'),
          heading('PowerShell — Windows', 3),
          codeBlock('irm https://pentect.dev/install | iex', 'powershell'),
          heading('Shell — macOS and Linux', 3),
          codeBlock('curl -fsSL https://pentect.dev/install.sh | sh', 'sh'),
          linkParagraph('All install options', agentMarkdownUrl('/start/install/index.md')),
        ];
      }
      if (node.name === 'a') {
        return [rewriteAnchor(node)];
      }
      if (node.name === 'div' && componentClass(node).includes('home-flow')) {
        return (node.children ?? [])
          .filter((child) => componentClass(child).includes('home-flow__step'))
          .flatMap((step) => {
            const number = componentAttribute(step, 'data-number');
            const title = componentAttribute(step, 'data-title');
            const description = componentAttribute(step, 'data-description');
            return [
              heading([number, title].filter(Boolean).join(' — '), 3),
              ...(description ? [paragraph(description)] : []),
            ];
          });
      }
      const children = rewriteNodes(node.children ?? []);
      const label = componentLabel(node);
      return label ? [heading(label, 3), ...children] : children;
    }

    if (node.type === 'link') {
      node.url = agentMarkdownUrl(node.url);
    }

    if (Array.isArray(node.children)) {
      node.children = rewriteNodes(node.children);
    }
    return [node];
  });
}

function rewriteAnchor(node) {
  const href = node.attributes?.find(
    (item) => item.type === 'mdxJsxAttribute' && item.name === 'href',
  );
  const url = agentMarkdownUrl(typeof href?.value === 'string' ? href.value : '#');
  const strong = findElement(node, 'strong');
  const span = findElement(node, 'span');
  const label = plainText(strong ?? node).trim() || url;
  const description = plainText(span).trim();

  return {
    type: 'paragraph',
    children: [
      { type: 'link', url, children: [{ type: 'text', value: label }] },
      ...(description ? [{ type: 'text', value: ` — ${description}` }] : []),
    ],
  };
}

function agentMarkdownUrl(url) {
  if (!url.startsWith('/')) return url;

  const match = url.match(/^([^?#]*)([?#].*)?$/);
  const pathname = match?.[1] ?? url;
  const suffix = match?.[2] ?? '';
  if (/\.[a-z0-9]+$/i.test(pathname)) return url;

  const normalized = pathname === '/' ? '/' : `${pathname.replace(/\/+$/, '')}/`;
  return `${normalized}index.md${suffix}`;
}

function findElement(node, name) {
  if (!node) return undefined;
  if ((node.type === 'mdxJsxFlowElement' || node.type === 'mdxJsxTextElement') && node.name === name) {
    return node;
  }
  for (const child of node.children ?? []) {
    const found = findElement(child, name);
    if (found) return found;
  }
  return undefined;
}

function plainText(node) {
  if (!node) return '';
  if (node.type === 'text' || node.type === 'inlineCode') return node.value ?? '';
  return (node.children ?? []).map(plainText).join(' ');
}

function componentLabel(node) {
  if (!['TabItem', 'Card'].includes(node.name)) return undefined;
  const attributeName = node.name === 'TabItem' ? 'label' : 'title';
  const attribute = node.attributes?.find(
    (item) => item.type === 'mdxJsxAttribute' && item.name === attributeName,
  );
  return typeof attribute?.value === 'string' ? attribute.value : undefined;
}

function componentClass(node) {
  return componentAttribute(node, 'class');
}

function componentAttribute(node, name) {
  const attribute = node?.attributes?.find(
    (item) => item.type === 'mdxJsxAttribute' && item.name === name,
  );
  return typeof attribute?.value === 'string' ? attribute.value : '';
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

function linkParagraph(label, url) {
  return {
    type: 'paragraph',
    children: [{
      type: 'link',
      url,
      children: [{ type: 'text', value: label }],
    }],
  };
}

function codeBlock(value, lang) {
  return { type: 'code', lang, value };
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
