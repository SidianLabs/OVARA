const { defineConfig } = require('../langchain/node_modules/vitest/dist/config.cjs');
const path = require('path');

module.exports = defineConfig({
  test: {
    globals: true,
    include: [path.resolve(__dirname, 'src/**/*.test.ts')],
  },
});