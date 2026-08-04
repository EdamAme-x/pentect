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
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M13 15h4"/>',
  message: '<path d="M5 18 3 21l4-1.5A9 9 0 1 0 5 18Z"/><path d="M8 11h8M8 14h5"/>',
  network: '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="m7 11 10-4m-10 6 10 4"/>',
  data: '<path d="M8 4 4 8l4 4"/><path d="m16 12 4 4-4 4"/><path d="m14 3-4 18"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m3 16 5-4 4 3 3-2 6 5"/>',
  shield: '<path d="M12 3 5 6v5c0 4.7 2.9 8 7 10 4.1-2 7-5.3 7-10V6Z"/><path d="m9 12 2 2 4-4"/>',
  plugin: '<path d="M8 3h3v4a2 2 0 1 0 4 0V3h3v6h3v6h-4v2a4 4 0 0 1-4 4h-2a4 4 0 0 1-4-4v-2H3V9h5Z"/>',
  build: '<path d="m14 6 4-3 3 3-3 4"/><path d="m16 8-9 9"/><path d="m5 15 4 4-2 2-4-4Z"/>',
  grid: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/>',
  settings: '<path d="M4 7h10M18 7h2M4 17h2m4 0h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  wrench: '<path d="M14 6a4 4 0 0 0-5 5L3 17l4 4 6-6a4 4 0 0 0 5-5l-3 2-3-3Z"/>',
};

function sidebarLabel(label: string, icon: keyof typeof sidebarIcons) {
  return `<span class="sidebar-link-label"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${sidebarIcons[icon]}</svg><span>${label}</span></span>`;
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
    ],
  },
  {
    text: 'Clients',
    items: [
      { text: sidebarLabel('Codex', 'terminal'), link: '/clients/codex/' },
      { text: sidebarLabel('Claude', 'message'), link: '/clients/claude/' },
      { text: sidebarLabel('Custom upstreams', 'network'), link: '/clients/upstreams/' },
    ],
  },
  {
    text: 'Protection',
    items: [
      { text: sidebarLabel('Structured data', 'data'), link: '/protection/structured-data/' },
      { text: sidebarLabel('Files and images', 'image'), link: '/protection/files-and-images/' },
      { text: sidebarLabel('Security model', 'shield'), link: '/protection/security-model/' },
    ],
  },
  {
    text: 'Plugins',
    items: [
      { text: sidebarLabel('Overview', 'plugin'), link: '/plugins/overview/' },
      { text: sidebarLabel('Build a plugin', 'build'), link: '/plugins/build/' },
    ],
  },
  {
    text: 'Reference',
    items: [
      { text: sidebarLabel('Capabilities', 'grid'), link: '/reference/capabilities/' },
      { text: sidebarLabel('CLI', 'terminal'), link: '/reference/cli/' },
      { text: sidebarLabel('Configuration', 'settings'), link: '/reference/configuration/' },
      { text: sidebarLabel('Compatibility', 'check'), link: '/reference/compatibility/' },
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
