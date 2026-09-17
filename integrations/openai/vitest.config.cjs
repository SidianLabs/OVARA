// Standalone vitest config — must not depend on a sibling package's
// node_modules. Plain object export avoids importing vitest/config.
module.exports = {
  test: {
    globals: true,
    include: ['src/**/*.test.ts'],
  },
};
