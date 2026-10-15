// Flat config (ESLint 9+/10): lint the SDK's TypeScript sources.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", "**/*.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
    },
    rules: {
      // The SDK crosses dynamic JSON boundaries (API responses, parsed
      // bodies) where `any` is deliberate; surface them without failing.
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },
  {
    // Tests use throwaway values and stubs.
    files: ["src/**/__tests__/**", "src/**/*.test.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
    },
  },
);
