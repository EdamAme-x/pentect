<script setup lang="ts">
import DefaultTheme from 'vitepress/theme';
import { useData, useRoute } from 'vitepress';
import { computed, nextTick, onMounted, watch } from 'vue';

const { frontmatter } = useData();
const route = useRoute();
const title = computed(() => String(frontmatter.value.title ?? ''));
const hasAccentSuffix = computed(() => title.value.endsWith('_'));
const titleBase = computed(() => hasAccentSuffix.value ? title.value.slice(0, -1) : title.value);

function normalizedTabLabel(label: HTMLLabelElement) {
  return label.textContent?.trim().toLowerCase() ?? '';
}

function selectPlatformCodeTabs() {
  const platform = navigator.userAgentData?.platform ?? navigator.platform ?? navigator.userAgent;
  const isWindows = /windows|win32|win64/i.test(platform);

  for (const group of document.querySelectorAll<HTMLElement>('.vp-code-group')) {
    const labels = [...group.querySelectorAll<HTMLLabelElement>('.tabs label')];
    const names = labels.map(normalizedTabLabel);
    const hasWindows = names.some((name) => name.includes('windows') || name.includes('powershell'));
    const hasUnix = names.some((name) =>
      name.includes('macos') ||
      name.includes('linux') ||
      name.includes('bash') ||
      name.includes('zsh') ||
      name === 'shell'
    );

    if (!hasWindows || !hasUnix) continue;

    const selected = labels.find((label) => {
      const name = normalizedTabLabel(label);
      return isWindows
        ? name.includes('windows') || name.includes('powershell')
        : name.includes('macos') || name.includes('linux') || name.includes('bash') || name.includes('zsh') || name === 'shell';
    });

    selected?.click();
  }
}

onMounted(() => selectPlatformCodeTabs());
watch(() => route.path, async () => {
  await nextTick();
  selectPlatformCodeTabs();
});
</script>

<template>
  <DefaultTheme.Layout>
    <template #nav-bar-title-after>
      <span class="docs-wordmark">Docs</span>
    </template>
    <template #nav-bar-content-after>
      <a class="docs-nav-cta" href="/start/install/">Install</a>
    </template>
    <template #doc-before>
      <header v-if="frontmatter.title" class="doc-heading">
        <h1>{{ titleBase }}<span v-if="hasAccentSuffix" class="doc-heading__accent" aria-hidden="true">_</span></h1>
        <p v-if="frontmatter.description">{{ frontmatter.description }}</p>
      </header>
    </template>
  </DefaultTheme.Layout>
</template>
