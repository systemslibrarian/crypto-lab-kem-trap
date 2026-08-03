import { defineConfig, devices } from '@playwright/test';

// Accessibility gate. Runs against the production build served by `vite preview`,
// so what passes here is what actually ships to GitHub Pages. Run `npm run build`
// first (CI does).
const BASE = '/crypto-lab-kem-trap/';
const PORT = 4657;
const ORIGIN = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  webServer: {
    // Build before serving. `preview` only serves whatever is already in
    // dist/; without the build in front, a failing build leaves the previous
    // good bundle on disk and the suite passes green against code that no
    // longer compiles — silently invalidating mutation checks.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `${ORIGIN}${BASE}`,
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: `${ORIGIN}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    // Chromium runs everything, including the full axe accessibility scan.
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    // The other engines + a mobile viewport run the functional smoke only, to
    // prove portability without paying for axe on every engine.
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testMatch: /smoke\.spec\.ts/ },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, testMatch: /smoke\.spec\.ts/ },
    { name: 'mobile-safari', use: { ...devices['iPhone 13'] }, testMatch: /smoke\.spec\.ts/ },
  ],
});
