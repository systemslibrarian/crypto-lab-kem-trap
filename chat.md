# KEM Trap: path to gold standard

## Bottom line

This repo is already closer to gold standard than most labs. The hard parts are already right: real ML-KEM plus a transparent FO reconstruction with KAT checks (README.md:15-20, README.md:75-79), honest scoping and non-goals (README.md:13, README.md:20-24), strong pedagogy around the actual failure mode (README.md:29-30, src/ui/lab.ts:122, src/ui/lab.ts:311), strict TypeScript settings (tsconfig.json:14-17), and CI-gated deploy, tests, and accessibility (.github/workflows/deploy.yml:27-34, README.md:79).

Verified on 2026-07-15:

- `npm test` passed: 25 of 25 tests.
- `npm run build` passed: current production output is 51.62 kB JS / 18.71 kB gzip.
- `npm run test:a11y` passed: 2 of 2 Playwright accessibility checks.

If the goal is gold standard, I would focus on four areas: measurable quality, cross-browser confidence, public artifact polish, and reproducible pedagogy.

## Highest-leverage moves

### 1. Add coverage as a first-class gate

Why this matters:

Your own fleet template says the definition of done includes tests passing with state count and coverage (CRYPTO-LAB-TEMPLATE.md:100), but the repo only exposes build, typecheck, unit test, and a11y scripts today (package.json:6-13). This is the clearest standards gap.

What to add:

- `vitest --coverage` with explicit thresholds.
- A CI step that fails below threshold.
- A short README note with current coverage numbers.

Suggested bar:

- `src/kem/*`: 95%+ statements, functions, and lines.
- Overall branches: 90%+ because the lab's value lives in branch behavior.

### 2. Expand browser and device coverage beyond Chromium

Why this matters:

The test story is already good, but Playwright only runs a Chromium project (playwright.config.ts:25) while the README claims mobile support and both themes (README.md:45, README.md:79). Gold standard means proving portability, not assuming it.

What to add:

- Firefox and WebKit projects.
- One mobile viewport project.
- A smoke flow for valid, bit-flipped, and truncated ciphertext states.

Pragmatic version:

Keep the full axe pass in Chromium if runtime cost matters. Add lighter smoke assertions for Firefox, WebKit, and mobile.

### 3. Add visual regression for the teaching-critical states

Why this matters:

This lab teaches through visual semantics, not just return values. The README explicitly calls out the SAFE vs. BROKEN split and the separate crypto-result versus verdict indicators (README.md:29-30), and the UI code preserves that separation in the rendered copy (src/ui/lab.ts:311). A CSS or layout regression could leave the tests green while weakening the lesson.

What to add:

- Screenshot tests for valid ciphertext, bit-flipped ciphertext, and truncated ciphertext.
- Both themes.
- Desktop plus one mobile viewport.
- Explicit checks that ACCEPT, REJECT, and ALARM remain visually and textually distinct.

### 4. Add repo hygiene and toolchain reproducibility

Why this matters:

TypeScript strictness is already strong (tsconfig.json:14-17), but there is no ESLint config, no `.editorconfig`, no Prettier config, and no visible Node or package-manager pin in the repo root. The GitHub Action uses Node 22 (.github/workflows/deploy.yml:18-25), but the local developer contract is implicit. Gold standard repos remove that ambiguity.

What to add:

- An ESLint flat config for TypeScript.
- `.editorconfig`.
- Either Prettier or an explicit eslint-only formatting decision.
- `packageManager` in package.json.
- `engines` in package.json or a `.nvmrc` / `.node-version` matching CI.

### 5. Add public artifact polish: license and share metadata

Why this matters:

The app shell has the core metadata right now: title, description, color-scheme, favicon, skip link, shared header, and theme toggle (index.html:12-18, index.html:80, index.html:98, index.html:131). But there is no `LICENSE` file in the repo root, no visible Open Graph or Twitter metadata in index.html, and no preview image asset in the repo. That is the difference between an excellent demo and an excellent public artifact.

What to add:

- A root `LICENSE` file.
- Matching `license` metadata in package.json.
- `og:title`, `og:description`, `og:image`, `twitter:card`, and canonical metadata.
- A social preview image that shows either the FO branch or the SAFE vs. BROKEN comparison.

### 6. Make the pedagogy reproducible and shareable

Why this matters:

The current interaction is strong because the learner causes the failure against the real mechanism (README.md:29, src/ui/lab.ts:122), but there is no obvious way to deep-link or replay a specific scenario. Gold standard teaching artifacts are citeable and reproducible.

What to add:

- URL state for mutation kind, resident buffer mode, and theme.
- Named presets such as single bit flip, wrong recipient, and length corruption.
- Copyable scenario links.
- Optional teacher mode that reveals the full sequence in a stable scripted order.

### 7. Add a bundle and performance budget while the build is still small

Why this matters:

The current build is excellent at 51.62 kB of JavaScript and 18.71 kB gzip, but nothing in the repo enforces staying there. Gold standard means protecting wins, not just achieving them once.

What to add:

- A bundle size check in CI.
- A documented size envelope in the README.
- A fail-open policy only with an explicit exception when a budget is exceeded.

## What I would not change

- Do not replace the real primitive or the transparent FO reconstruction. That is the core differentiator, and it is already the strongest part of the repo (README.md:15-20, README.md:29, README.md:75-79).
- Do not simplify the SAFE vs. BROKEN split into a single green-red result. The current separation between cryptographic fact and system verdict is exactly the right teaching move (README.md:30, src/ui/lab.ts:311).
- Do not trade honesty for slickness. The README's scoping discipline is unusually good already (README.md:13, README.md:20-24).

## Recommended order

1. Coverage gate.
2. Cross-browser and mobile smoke coverage.
3. Visual regression snapshots.
4. ESLint, editor config, and toolchain pinning.
5. License and social metadata.
6. URL-permalinked scenarios.
7. Bundle budget.

If you only do three things, do 1, 2, and 5. Those are the highest-signal improvements for gold standard rather than just very good.