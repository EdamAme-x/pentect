<script setup lang="ts">
import DefaultTheme from 'vitepress/theme';
import { useData } from 'vitepress';
import { computed } from 'vue';

const { frontmatter } = useData();
const title = computed(() => String(frontmatter.value.title ?? ''));
const hasAccentSuffix = computed(() => title.value.endsWith('_'));
const titleBase = computed(() => hasAccentSuffix.value ? title.value.slice(0, -1) : title.value);
</script>

<template>
  <DefaultTheme.Layout>
    <template #nav-bar-title-after>
      <span class="docs-wordmark">Docs</span>
    </template>
    <template #nav-bar-content-after>
      <a class="docs-nav-cta" href="/start/quick-start/">Get started</a>
    </template>
    <template #doc-before>
      <header v-if="frontmatter.title" class="doc-heading">
        <h1>{{ titleBase }}<span v-if="hasAccentSuffix" class="doc-heading__accent" aria-hidden="true">_</span></h1>
        <p v-if="frontmatter.description">{{ frontmatter.description }}</p>
      </header>
    </template>
  </DefaultTheme.Layout>
</template>
