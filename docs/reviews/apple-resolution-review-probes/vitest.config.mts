import { defineConfig } from '../../../ui/node_modules/vitest/dist/config.js';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  root: fileURLToPath(new URL('../../../ui/', import.meta.url)),
  resolve: {
    alias: [{
      find: /^vitest$/,
      replacement: fileURLToPath(new URL('../../../ui/node_modules/vitest/dist/index.js', import.meta.url)),
    }],
  },
  test: {
    environment: 'jsdom',
    setupFiles: [fileURLToPath(new URL('../../../ui/src/test/setup.ts', import.meta.url))],
    include: [fileURLToPath(new URL('./resolution-review.test.ts', import.meta.url))],
  },
});
