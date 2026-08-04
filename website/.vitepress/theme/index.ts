import DefaultTheme from 'vitepress/theme';
import HomeInstall from './HomeInstall.vue';
import Layout from './Layout.vue';
import './style.css';

export default {
  extends: DefaultTheme,
  Layout,
  enhanceApp({ app }) {
    app.component('HomeInstall', HomeInstall);
  },
};
