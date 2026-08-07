import DefaultTheme from 'vitepress/theme';
import DocsGrid from './DocsGrid.vue';
import HomeInstall from './HomeInstall.vue';
import QuickInstall from './QuickInstall.vue';
import Layout from './Layout.vue';
import './style.css';

export default {
  extends: DefaultTheme,
  Layout,
  enhanceApp({ app }) {
    app.component('DocsGrid', DocsGrid);
    app.component('HomeInstall', HomeInstall);
    app.component('QuickInstall', QuickInstall);
  },
};
