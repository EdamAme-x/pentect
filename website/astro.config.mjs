import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const site = process.env.PENTECT_DOCS_SITE ?? 'https://pentect.dev';
const base = process.env.PENTECT_DOCS_BASE ?? '/';

export default defineConfig({
  site,
  base,
  integrations: [
    starlight({
      title: 'Pentect',
      description: 'Let agents use secrets without seeing them.',
      logo: {
        src: './src/assets/pentect-logo.png',
        alt: 'Pentect',
        replacesTitle: false,
      },
      favicon: '/pentect-logo-transparent.png',
      lastUpdated: true,
      customCss: ['./src/styles/custom.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/EdamAme-x/pentect',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/EdamAme-x/pentect/edit/main/website/',
      },
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#f3f0e8' } },
        { tag: 'meta', attrs: { property: 'og:type', content: 'website' } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary' } },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'What is Pentect?', slug: 'start/what-is-pentect' },
            { label: 'Install', slug: 'start/install' },
            { label: 'Quick start', slug: 'start/quick-start' },
            { label: 'How it works', slug: 'start/how-it-works' },
          ],
        },
        {
          label: 'Clients',
          items: [
            { label: 'Codex', slug: 'clients/codex' },
            { label: 'Claude', slug: 'clients/claude' },
            { label: 'Custom upstreams', slug: 'clients/upstreams' },
          ],
        },
        {
          label: 'Protection',
          items: [
            { label: 'Structured data', slug: 'protection/structured-data' },
            { label: 'Files and images', slug: 'protection/files-and-images' },
            { label: 'Security model', slug: 'protection/security-model' },
          ],
        },
        {
          label: 'Plugins',
          items: [
            { label: 'Overview', slug: 'plugins/overview' },
            { label: 'Build a plugin', slug: 'plugins/build' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'CLI', slug: 'reference/cli' },
            { label: 'Configuration', slug: 'reference/configuration' },
            { label: 'Compatibility', slug: 'reference/compatibility' },
            { label: 'Troubleshooting', slug: 'reference/troubleshooting' },
          ],
        },
      ],
    }),
  ],
});
