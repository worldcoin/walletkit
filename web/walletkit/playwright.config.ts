import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "tests",
  timeout: 60_000,
  workers: 1,
  use: { baseURL: "http://127.0.0.1:4173", channel: "chrome" },
  webServer: {
    command: "bun run test:serve",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
  },
});
