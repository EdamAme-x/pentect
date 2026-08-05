---
title: Docs_
description: Protect sensitive data before it reaches an AI model, while local tools keep working.
pageClass: docs-hub
aside: false
---

Pentect runs locally between supported AI clients and their providers. It
replaces sensitive values with useful handles, then restores those handles only
when a trusted local tool needs the value.

<div class="home-flow" aria-label="How Pentect protects a request">
  <div class="home-flow__step" data-number="01" data-title="Detect locally" data-description="Check text, config files, uploads, images, and tool output."><small>01</small><strong>Detect locally</strong><span>Check text, config files, uploads, images, and tool output.</span></div>
  <div class="home-flow__step" data-number="02" data-title="Send a handle" data-description="The provider sees a DATABASE_URL handle, not the value."><small>02</small><strong>Send a handle</strong><span>The provider sees <code>&lt;&lt;DATABASE_URL_...&gt;&gt;</code>, not the value.</span></div>
  <div class="home-flow__step" data-number="03" data-title="Use it locally" data-description="Restore known handles only at a trusted tool boundary."><small>03</small><strong>Use it locally</strong><span>Restore known handles only at a trusted tool boundary.</span></div>
</div>

<HomeInstall />

## Clients

<DocsGrid class="is-compact">
  <a href="/clients/codex/" class="docs-grid__item">
    <small>CLI</small><strong>Codex CLI</strong>
    <span>Run Codex through Pentect for the current session.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/claude/" class="docs-grid__item">
    <small>CLI</small><strong>Claude Code</strong>
    <span>Protect Claude Code requests with Pentect.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/codex/" class="docs-grid__item">
    <small>Desktop</small><strong>Codex App</strong>
    <span>Start one Codex App session through Pentect.</span><b aria-hidden="true">→</b>
  </a>
  <a href="/clients/claude/" class="docs-grid__item">
    <small>Desktop</small><strong>Claude Desktop</strong>
    <span>Protect supported Claude Desktop traffic.</span><b aria-hidden="true">→</b>
  </a>
</DocsGrid>

## Explore

<DocsGrid>
  <a href="/start/how-it-works/" class="docs-grid__item">
    <strong>How it works</strong>
    <span>See how Pentect protects and restores a value.</span><b aria-hidden="true">→</b>
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
