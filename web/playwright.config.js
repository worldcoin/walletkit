import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:4173' },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'webkit', use: { browserName: 'webkit' } }],
  webServer: {
    command: 'node server.mjs',
    url: 'http://127.0.0.1:4173',
    env: { WALLETKIT_BROWSER_TEST: '1' },
    reuseExistingServer: false,
  },
});
