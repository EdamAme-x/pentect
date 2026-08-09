---
title: Docs - Pentect
displayTitle: Docs_
titleTemplate: false
description: AI can use your secrets without ever seeing them.
pageClass: docs-hub
aside: false
---

<div class="home-demo">
  <video
    playsinline
    controls
    preload="metadata"
    poster="/pentect-demo-poster.png?v=8"
    aria-label="Pentect replaces a Stripe secret with a handle before the request reaches the AI provider, then restores it for a local tool."
  >
    <source src="/pentect-demo.mp4?v=8" type="video/mp4" />
  </video>
</div>

<HomeInstall />

## Clients

<DocsGrid class="is-compact">
  <a href="/clients/codex/" class="docs-grid__item">
    <small>CLI + Desktop</small><strong>Codex</strong>
    <span>Protect Codex CLI or launch Codex App through Pentect.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/claude/" class="docs-grid__item">
    <small>Code + Desktop</small><strong>Claude</strong>
    <span>Protect Claude Code or supported Claude Desktop traffic.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/opencode/" class="docs-grid__item">
    <small>CLI</small><strong>OpenCode</strong>
    <span>Run OpenCode through a temporary protected provider.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/pi/" class="docs-grid__item">
    <small>CLI</small><strong>Pi</strong>
    <span>Run Pi through a temporary protected provider.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/antigravity/" class="docs-grid__item">
    <small>CLI</small><strong>Antigravity</strong>
    <span>Run the official Antigravity CLI through the Cloud Code gateway.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/reference/capabilities/#clients" class="docs-grid__item">
    <small>CLI + Editors</small><strong>More clients</strong>
    <span>Aider, Continue, Cline, Zed, Goose, Junie, and VS Code.</span><b aria-hidden="true">→</b>
  </a>
</DocsGrid>

## Explore

<DocsGrid>
  <a href="/protection/prompts-and-tools/" class="docs-grid__item">
    <strong>Prompts and tool results</strong>
    <span>Protect pasted secrets, accidental output, MCP results, and browser screenshots.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/start/how-it-works/" class="docs-grid__item">
    <strong>How it works</strong>
    <span>See how Pentect protects and restores a value.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/start/handles/" class="docs-grid__item">
    <strong>Handles</strong>
    <span>Learn how references, environment bindings, lifetime, and recovery work.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/protection/structured-data/" class="docs-grid__item">
    <strong>Structured data</strong>
    <span>Protect dotenv, Terraform, Kubernetes, and other supported formats.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/protection/files-and-images/" class="docs-grid__item">
    <strong>Files and images</strong>
    <span>Learn how Pentect checks uploads, images, and documents.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/upstreams/" class="docs-grid__item">
    <strong>Custom upstreams</strong>
    <span>Use Pentect with a compatible gateway or local model.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/plugins/overview/" class="docs-grid__item">
    <strong>Plugins</strong>
    <span>Build, test, and publish custom checks with regex or Wasm.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/reference/capabilities/" class="docs-grid__item">
    <strong>Everything Pentect can do</strong>
    <span>Browse clients, protected content, commands, settings, and plugins.</span><b aria-hidden="true">→</b>
  </a>
</DocsGrid>

## Common tasks

<DocsGrid>
  <a href="/start/quick-start/" class="docs-grid__item">
    <small>5 minutes</small><strong>Protect your first agent session</strong>
    <span>Install Pentect, launch Codex or Claude, and confirm a handle.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/start/examples/" class="docs-grid__item">
    <small>Recipes</small><strong>Use Pentect in real work</strong>
    <span>Mask a file, use a custom gateway, keep aliases, and apply project policy.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/reference/troubleshooting/" class="docs-grid__item">
    <small>Help</small><strong>Fix a blocked request</strong>
    <span>Find the protected path first, then use compatibility mode only when needed.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/protection/security-model/" class="docs-grid__item">
    <small>Trust</small><strong>Understand the boundary</strong>
    <span>See what stays local, what plugins can access, and what Pentect does not cover.</span><b aria-hidden="true">→</b>
  </a>
</DocsGrid>
