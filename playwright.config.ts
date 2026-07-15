import { defineConfig } from '@playwright/test';

// Accessibility gate. Runs against the production build served by `vite preview`,
// so what passes here is what actually ships to GitHub Pages. Run `npm run build`
// first (CI does).
const BASE = '/crypto-lab-kem-trap/';
const PORT = 4173;
const ORIGIN = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    url: `${ORIGIN}${BASE}`,
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: `${ORIGIN}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
