import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        devtools: resolve(__dirname, 'src/devtools/devtools.html'),
        panel: resolve(__dirname, 'src/panel/index.html'),
        background: resolve(__dirname, 'src/background/sw.js'),
        content: resolve(__dirname, 'src/content/content.js')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') {
            return 'background/sw.js';
          }
          if (chunkInfo.name === 'content') {
            return 'content/content.js';
          }
          if (chunkInfo.name === 'devtools') {
            return 'devtools/devtools.js';
          }
          if (chunkInfo.name === 'panel') {
            return 'panel/index.js';
          }
          return '[name].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name && assetInfo.name.endsWith('.html')) {
            if (assetInfo.name.includes('devtools')) {
              return 'devtools/devtools.html';
            }
            if (assetInfo.name.includes('index')) {
              return 'panel/index.html';
            }
            return '[name].[ext]';
          }
          if (assetInfo.name && assetInfo.name.endsWith('.css')) {
            return 'panel/styles.css';
          }
          return 'assets/[name].[ext]';
        }
      }
    }
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  }
});
