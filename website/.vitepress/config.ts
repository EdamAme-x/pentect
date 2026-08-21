import { defineConfig } from 'vitepress';
import { fileURLToPath } from 'node:url';

const site = process.env.PENTECT_DOCS_SITE ?? 'https://pentect.dev';
const base = process.env.PENTECT_DOCS_BASE ?? '/';

const sidebarIcons = {
  home: '<path d="m3 11 9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M9 20v-6h6v6"/>',
  play: '<circle cx="12" cy="12" r="9"/><path d="m10 8 6 4-6 4Z"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
  download: '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 20h14"/>',
  flow: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M8 6h8M7 8l4 8m6-8-4 8"/>',
  examples: '<path d="M5 4h14v16H5Z"/><path d="M8 8h8M8 12h5M8 16h7"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8m-3 3 2 2m-5 1 2 2"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M13 15h4"/>',
  message: '<path d="M5 18 3 21l4-1.5A9 9 0 1 0 5 18Z"/><path d="M8 11h8M8 14h5"/>',
  network: '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="m7 11 10-4m-10 6 10 4"/>',
  gateway: '<path d="M4 7h11"/><path d="m12 4 3 3-3 3"/><path d="M20 17H9"/><path d="m12 14-3 3 3 3"/><path d="M4 4v16M20 4v16"/>',
  data: '<path d="M8 4 4 8l4 4"/><path d="m16 12 4 4-4 4"/><path d="m14 3-4 18"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m3 16 5-4 4 3 3-2 6 5"/>',
  shield: '<path d="M12 3 5 6v5c0 4.7 2.9 8 7 10 4.1-2 7-5.3 7-10V6Z"/><path d="m9 12 2 2 4-4"/>',
  plugin: '<path d="M8 3h3v4a2 2 0 1 0 4 0V3h3v6h3v6h-4v2a4 4 0 0 1-4 4h-2a4 4 0 0 1-4-4v-2H3V9h5Z"/>',
  build: '<path d="m14 6 4-3 3 3-3 4"/><path d="m16 8-9 9"/><path d="m5 15 4 4-2 2-4-4Z"/>',
  star: '<path d="m12 3 2.7 5.5 6.1.9-4.4 4.3 1 6-5.4-2.9-5.4 2.9 1-6-4.4-4.3 6.1-.9Z"/>',
  file: '<path d="M6 3h8l4 4v14H6Z"/><path d="M14 3v5h5M9 12h6m-6 4h6"/>',
  code: '<path d="m8 9-3 3 3 3m8-6 3 3-3 3m-2-9-4 12"/>',
  package: '<path d="m12 3 8 4-8 4-8-4Z"/><path d="m4 7 8 4 8-4v10l-8 4-8-4Z"/><path d="M12 11v10"/>',
  grid: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/>',
  settings: '<path d="M4 7h10M18 7h2M4 17h2m4 0h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  wrench: '<path d="M14 6a4 4 0 0 0-5 5L3 17l4 4 6-6a4 4 0 0 0 5-5l-3 2-3-3Z"/>',
};

function sidebarLabel(label: string, icon: keyof typeof sidebarIcons, brandIcon?: string) {
  const iconMarkup = brandIcon
    ? `<img class="sidebar-brand-icon" aria-hidden="true" src="${brandIcon}" alt="">`
    : `<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${sidebarIcons[icon]}</svg>`;
  return `<span class="sidebar-link-label">${iconMarkup}<span>${label}</span></span>`;
}

const sidebar = [
  { text: sidebarLabel('Home', 'home'), link: '/' },
  { text: sidebarLabel('Quick start', 'play'), link: '/start/quick-start/' },
  {
    text: 'Get started',
    items: [
      { text: sidebarLabel('What is Pentect?', 'info'), link: '/start/what-is-pentect/' },
      { text: sidebarLabel('Install', 'download'), link: '/start/install/' },
      { text: sidebarLabel('How it works', 'flow'), link: '/start/how-it-works/' },
      { text: sidebarLabel('Handles', 'key'), link: '/start/handles/' },
      { text: sidebarLabel('Examples', 'examples'), link: '/start/examples/' },
    ],
  },
  {
    text: 'Clients',
    items: [
      { text: sidebarLabel('Codex', 'terminal', '/brands/openai-blossom.svg'), link: '/clients/codex/' },
      { text: sidebarLabel('Claude', 'message', '/brands/claude.svg'), link: '/clients/claude/' },
      { text: sidebarLabel('OpenCode', 'terminal', '/brands/opencode.svg'), link: '/clients/opencode/' },
      { text: sidebarLabel('Pi', 'terminal', '/brands/pi.svg'), link: '/clients/pi/' },
      { text: sidebarLabel('Custom upstreams', 'gateway'), link: '/clients/upstreams/' },
    ],
  },
  {
    text: 'Protection',
    items: [
      { text: sidebarLabel('Prompts and tool results', 'message'), link: '/protection/prompts-and-tools/' },
      { text: sidebarLabel('Structured data', 'data'), link: '/protection/structured-data/' },
      { text: sidebarLabel('Files and images', 'image'), link: '/protection/files-and-images/' },
      { text: sidebarLabel('Security model', 'shield'), link: '/protection/security-model/' },
    ],
  },
  {
    text: 'Plugins',
    items: [
      { text: sidebarLabel('Overview', 'plugin'), link: '/plugins/overview/' },
      { text: sidebarLabel('Official plugins', 'star'), link: '/plugins/official/' },
      { text: sidebarLabel('Build a plugin', 'build'), link: '/plugins/build/' },
      { text: sidebarLabel('Command plugins', 'terminal'), link: '/plugins/command/' },
      { text: sidebarLabel('Middleware lifecycle', 'layers'), link: '/plugins/lifecycle/' },
      { text: sidebarLabel('Plugin recipes', 'examples'), link: '/plugins/recipes/' },
      { text: sidebarLabel('Plugin manifest', 'file'), link: '/plugins/manifest/' },
      { text: sidebarLabel('Rust SDK', 'code'), link: '/plugins/sdk/' },
      { text: sidebarLabel('Test and publish', 'package'), link: '/plugins/publish/' },
    ],
  },
  {
    text: 'Reference',
    items: [
      { text: sidebarLabel('Capabilities', 'grid'), link: '/reference/capabilities/' },
      { text: sidebarLabel('CLI', 'terminal'), link: '/reference/cli/' },
      { text: sidebarLabel('Configuration', 'settings'), link: '/reference/configuration/' },
      { text: sidebarLabel('Compatibility', 'check'), link: '/reference/compatibility/' },
      { text: sidebarLabel('Instructions for agents', 'shield'), link: '/reference/agents/' },
      { text: sidebarLabel('Troubleshooting', 'wrench'), link: '/reference/troubleshooting/' },
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
  description: 'Protect sensitive data before it reaches an AI model, while local tools keep working.',
  cleanUrls: true,
  lastUpdated: true,
  rewrites(id) {
    if (id === 'index.md') return id;
    return id.replace(/\.md$/, '/index.md');
  },
  head: [
    ['link', { rel: 'icon', href: '/pentect-logo-transparent.png' }],
    ['meta', { name: 'theme-color', content: '#ffffff' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Pentect' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
  ],
  transformPageData(pageData) {
    const routePath = pageData.relativePath
      .replace(/(^|\/)index\.md$/, '$1')
      .replace(/\.md$/, '/');
    const route = `/${routePath}`;
    const pageTitle = pageData.relativePath === 'index.md'
      ? 'Docs - Pentect'
      : `${pageData.title} — Pentect`;
    const pageDescription = String(
      pageData.frontmatter.description
      ?? 'Protect sensitive data before it reaches an AI model, while local tools keep working.',
    );
    const canonical = new URL(route, site).href;
    const socialImage = new URL('/og-docs.png', site).href;
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
      ['link', { rel: 'canonical', href: canonical }],
      ['meta', { property: 'og:title', content: pageTitle }],
      ['meta', { property: 'og:description', content: pageDescription }],
      ['meta', { property: 'og:url', content: canonical }],
      ['meta', { property: 'og:image', content: socialImage }],
      ['meta', { property: 'og:image:width', content: '1200' }],
      ['meta', { property: 'og:image:height', content: '630' }],
      ['meta', { property: 'og:image:alt', content: 'Docs - Pentect' }],
      ['meta', { name: 'twitter:title', content: pageTitle }],
      ['meta', { name: 'twitter:description', content: pageDescription }],
      ['meta', { name: 'twitter:image', content: socialImage }],
    );
  },
  sitemap: { hostname: site },
  themeConfig: {
    logo: {
      light: '/pentect-logo-transparent.png',
      dark: '/pentect-logo-dark.png',
      alt: 'Pentect',
    },
    nav: [],
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
      copyright: 'Released under the MIT license.',
    },
    lastUpdated: { text: 'Updated' },
    docFooter: { prev: 'Previous', next: 'Next' },
  },
});
