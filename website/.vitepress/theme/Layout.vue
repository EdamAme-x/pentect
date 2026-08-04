<script setup lang="ts">
import DefaultTheme from 'vitepress/theme';
import { useData } from 'vitepress';

const { frontmatter } = useData();
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
        <h1>{{ frontmatter.title }}</h1>
        <p v-if="frontmatter.description">{{ frontmatter.description }}</p>
      </header>
    </template>
  </DefaultTheme.Layout>
</template>
