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
    coverage: {
      provider: 'v8',
      // Gate coverage on the cryptographic layer — where correctness is the
      // whole point. The UI (src/ui, main.ts) is exercised by the Playwright
      // a11y + smoke suites instead, so it is excluded from the unit-coverage bar.
      include: ['src/kem/**/*.ts'],
      exclude: ['src/kem/types.ts', 'src/kem/vectors.ts'],
      thresholds: {
        statements: 95,
        functions: 95,
        lines: 95,
        branches: 90,
      },
      reporter: ['text-summary', 'html'],
    },
  },
});
