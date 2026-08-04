<script setup lang="ts">
import DefaultTheme from 'vitepress/theme';
import { useData } from 'vitepress';

const { frontmatter } = useData();
</script>

<template>
  <DefaultTheme.Layout>
    <template #doc-before>
      <header v-if="frontmatter.title" class="doc-heading">
        <h1>{{ frontmatter.title }}</h1>
        <p v-if="frontmatter.description">{{ frontmatter.description }}</p>
      </header>
    </template>
  </DefaultTheme.Layout>
</template>
