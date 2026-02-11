import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/ui",
  timeout: 60000,
  use: {
    baseURL: "http://127.0.0.1:5000",
    headless: true,
  },
});
