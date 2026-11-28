import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", "coverage/**", "pnpm-lock.yaml"],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["scripts/**/*.mjs", "attacks/**/*.mjs", "examples/**/*.mjs"],
    languageOptions: {
      globals: {
        Buffer: "readonly",
        URL: "readonly",
        console: "readonly",
        crypto: "readonly",
        fetch: "readonly",
        process: "readonly",
        setTimeout: "readonly",
        TextEncoder: "readonly",
      },
    },
  },
  {
    files: ["site/replay/**/*.js", "site/replay/**/*.mjs"],
    languageOptions: {
      globals: {
        URL: "readonly",
        Worker: "readonly",
        console: "readonly",
        crypto: "readonly",
        document: "readonly",
        Element: "readonly",
        fetch: "readonly",
        localStorage: "readonly",
        navigator: "readonly",
        self: "readonly",
        URLSearchParams: "readonly",
        setInterval: "readonly",
        setTimeout: "readonly",
        clearInterval: "readonly",
        FileReader: "readonly",
        TextEncoder: "readonly",
        window: "readonly",
      },
    },
  },
  {
    files: ["**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
);
