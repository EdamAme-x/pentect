import { defineConfig } from 'vitepress';
import { fileURLToPath } from 'node:url';

const site = process.env.PENTECT_DOCS_SITE ?? 'https://pentect.dev';
const base = process.env.PENTECT_DOCS_BASE ?? '/';

const sidebar = [
  {
    text: 'Start here',
    items: [
      { text: 'What is Pentect?', link: '/start/what-is-pentect/' },
      { text: 'Install', link: '/start/install/' },
      { text: 'Quick start', link: '/start/quick-start/' },
      { text: 'How it works', link: '/start/how-it-works/' },
    ],
  },
  {
    text: 'Clients',
    items: [
      { text: 'Codex', link: '/clients/codex/' },
      { text: 'Claude', link: '/clients/claude/' },
      { text: 'Custom upstreams', link: '/clients/upstreams/' },
    ],
  },
  {
    text: 'Protection',
    items: [
      { text: 'Structured data', link: '/protection/structured-data/' },
      { text: 'Files and images', link: '/protection/files-and-images/' },
      { text: 'Security model', link: '/protection/security-model/' },
    ],
  },
  {
    text: 'Plugins',
    items: [
      { text: 'Overview', link: '/plugins/overview/' },
      { text: 'Build a plugin', link: '/plugins/build/' },
    ],
  },
  {
    text: 'Reference',
    items: [
      { text: 'CLI', link: '/reference/cli/' },
      { text: 'Configuration', link: '/reference/configuration/' },
      { text: 'Compatibility', link: '/reference/compatibility/' },
      { text: 'Troubleshooting', link: '/reference/troubleshooting/' },
    ],
  },
];

export default defineConfig({
  srcDir: './src/content/docs',
  outDir: './dist',
  cacheDir: './.vitepress/cache',
  vite: {
    publicDir: fileURLToPath(new URL('../public', import.meta.url)),
  },
  site,
  base,
  lang: 'en-US',
  title: 'Pentect',
  titleTemplate: ':title — Pentect',
  description: 'Let agents use secrets without seeing them.',
  cleanUrls: true,
  lastUpdated: true,
  rewrites(id) {
    if (id === 'index.md') return id;
    return id.replace(/\.md$/, '/index.md');
  },
  head: [
    ['link', { rel: 'icon', href: '/pentect-logo-transparent.png' }],
    ['meta', { name: 'theme-color', content: '#f7f5ef' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { name: 'twitter:card', content: 'summary' }],
  ],
  transformPageData(pageData) {
    const routePath = pageData.relativePath
      .replace(/(^|\/)index\.md$/, '$1')
      .replace(/\.md$/, '/');
    const route = `/${routePath}`;
    pageData.frontmatter.head ??= [];
    pageData.frontmatter.head.push(
      ['link', {
        rel: 'alternate',
        type: 'text/markdown',
        href: `${route}index.md`,
        title: 'Markdown version',
      }],
      ['meta', {
        name: 'agent-content',
        content: `A concise Markdown version of this page is available at ${route}index.md`,
      }],
      ['link', { rel: 'canonical', href: new URL(route, site).href }],
    );
  },
  sitemap: { hostname: site },
  themeConfig: {
    logo: {
      src: '/pentect-logo-transparent.png',
      alt: 'Pentect',
    },
    nav: [
      { text: 'Guide', link: '/start/what-is-pentect/' },
      { text: 'Reference', link: '/reference/cli/' },
      { text: 'Plugins', link: '/plugins/overview/' },
    ],
    sidebar,
    outline: { level: [2, 3], label: 'On this page' },
    search: { provider: 'local' },
    editLink: {
      pattern: 'https://github.com/EdamAme-x/pentect/edit/main/website/src/content/docs/:path',
      text: 'Edit this page on GitHub',
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/EdamAme-x/pentect' },
    ],
    footer: {
      message: 'Pentect is open source.',
      copyright: 'Released under the Apache-2.0 license.',
    },
    lastUpdated: { text: 'Updated' },
    docFooter: { prev: 'Previous', next: 'Next' },
  },
});
