import { defineConfig } from 'vite';

// Real repo name — deployed under this GitHub Pages subpath. Root-absolute
// asset paths 404 under a project subpath, so all in-page assets use `./` or
// data: URIs (see index.html favicon).
export default defineConfig({
  base: process.env.VITE_BASE_PATH ?? '/crypto-lab-kem-trap/',
  test: {
    // Playwright specs live in e2e/ — keep them out of the Vitest run.
    include: ['src/**/*.test.ts'],
    environment: 'happy-dom',
  },
});
