import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        window: "readonly",
        document: "readonly",
        console: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        crypto: "readonly",
        alert: "readonly",
        confirm: "readonly",
        navigator: "readonly",
        localStorage: "readonly",
        Promise: "readonly"
      }
    },
    rules: {
      "no-unused-vars": "off", // Let's turn this off because many functions are called from HTML
      "no-undef": "error"
    }
  }
];
