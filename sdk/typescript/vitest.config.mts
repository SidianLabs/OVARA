import { defineConfig } from "vitest/config";

// The tests live in src/. The package's prepare step compiles them into
// dist/ with everything else, and without this list vitest would run those
// copies too: once as TypeScript, once as the CommonJS output, which newer
// vitest versions refuse to load.
export default defineConfig({
  test: { include: ["src/**/*.test.ts"] },
});
