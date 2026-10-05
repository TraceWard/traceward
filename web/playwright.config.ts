import {defineConfig} from '@playwright/test';
export default defineConfig({
  testDir: './e2e', timeout: 30000, workers: 1,
  use: {baseURL: 'http://127.0.0.1:8779', channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', screenshot: 'only-on-failure'},
  webServer: {command: '../.venv/bin/python e2e/server.py', url: 'http://127.0.0.1:8779/api/runs', reuseExistingServer: false},
});
