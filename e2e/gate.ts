import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this replaces
 *     opened every scan with `addStyleTag({ content: '*{animation:none!important;
 *     transition:none!important}' })`. That does not merely steady the page — it
 *     BYPASSES this lab's own `@media (prefers-reduced-motion: reduce)` block
 *     instead of exercising it, so the suite was structurally unable to see a
 *     defect in the code path a motion-sensitive reader gets. It then stripped
 *     `[hidden]` from every element and force-added `.active/.is-active/.open/
 *     .is-revealed`, which on this lab fabricates a page no visitor can reach:
 *     the FO panel reveals its six steps one press at a time, and un-hiding them
 *     all also stamps `is-active` on all six at once — six simultaneous
 *     "currently revealed" rings, a state the lab cannot produce.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST. axe over an empty
 *     container passes having checked nothing.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * `process` without `@types/node`.
 *
 * `tsconfig.json` includes `e2e/` and sets `types: ["vite/client"]`, so the bare
 * global does not typecheck and `npm run build` would fail. Reading it off
 * `globalThis` keeps the collection switch working under Playwright's Node
 * runtime without adding a dependency the app does not otherwise need.
 */
const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This lab is one edit away from it: `@keyframes step-in` runs the newly
 * revealed FO step up from `opacity: 0.25`, and the reduced-motion block does
 * not disable the animation, it collapses it to `0.001ms` with
 * `animation-iteration-count: 1`. That lands on the `to` frame, which is why it
 * is correct today — but it is correct by a hair, and nothing else here checks.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!env?.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/** `await`-able soft wrapper for the assertions that live inside a helper. */
async function softCall(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String((e as Error).message ?? e));
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The SHIPPED DEFAULTS are asserted rather than assumed, because which half of
 * this lab a scan sees depends entirely on them: the ciphertext arrives
 * UNTAMPERED, so both callers read ACCEPT and the alarm palette is not on
 * screen at all; the FO panel shows ONE of its six steps; and the fail-open
 * buffer starts holding stack garbage rather than a previous secret. A gate
 * written from the markup would be asserting a page that never loads.
 *
 * The URL is reset to `.` with no hash first. The lab serialises its scenario
 * into `location.hash` on every change and restores from it on load, so a
 * previous test's mutation would otherwise survive into this one.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true);
  // index.html's anti-flash script stamps `data-theme` unconditionally
  // (`saved ?? 'dark'`) from the same 'theme' key the shared header's toggle
  // writes, so both themes are checkable by attribute here.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('#app .panel')).toHaveCount(5);
  await expect(page.locator('.cl-hero-title')).toHaveText('KEM Trap');

  // Shipped defaults, asserted.
  await expect(page.locator('.mutation-status')).toHaveText(
    'Current ciphertext: valid ciphertext (untouched).',
  );
  await expect(page.locator('#fo .step:not([hidden])')).toHaveCount(1);
  await expect(page.locator('#fo .step-controls, #fo .control-row button').first()).toContainText(
    'Reveal next step  (1 of 6)',
  );
  await expect(verdict(page, 'safe')).toHaveText('ACCEPT');
  await expect(verdict(page, 'broken')).toHaveText('ACCEPT');
  await expect(page.locator('#buffer')).toContainText('stack garbage');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/** The SECURITY verdict of a caller card — [0] is the crypto result. */
export function verdict(page: Page, caller: 'safe' | 'broken') {
  return page.locator(`.caller-${caller} .indicator .indicator-text`).nth(1);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints wrapped hex byte grids, a four-column oracle
 * table with no scroller around it, and a `<pre>` block of C.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab does not have
    // that rule today; the check stays honest against one being added.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide `.code` block inside its own `overflow: auto` box has a huge
    // bounding rect but is clipped by its scroller and contributes nothing to
    // the document's scroll width — naming it sends you off fixing the wrong
    // element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0]!;
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * The lab's `.bytes` views and `.code` block already carry `tabindex="0"`; this
 * asserts that after every state change, including the ones that grow a view
 * past its `max-height` cap.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less `<div>` hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *
 * WCAG 1.4.11 (non-text contrast) and generated content have NO oracle here;
 * both were measured by hand from screenshot pixels during this sweep and the
 * fixes are in `src/style.css`.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await softCall(() => expectNotBlank(page, label));
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await softCall(() => expectScrollersReachable(page, label));
  await softCall(() => expectNoHorizontalOverflow(page, label));
  await expectNoNewNonTextFailures(page, label);
}

/** A button inside the lab, found by its visible label. */
function btn(page: Page, label: string) {
  return page.locator('#app button', { hasText: label });
}

/**
 * Walk the FO panel's six steps one press at a time, scanning each.
 *
 * The reveal is the lab's headline mechanism and it is progressive: unrevealed
 * steps carry the `hidden` attribute and the newly revealed one carries
 * `.is-active`, which is the only place the accent ring and the `step-in`
 * animation appear. The replaced gate stripped `hidden` from all six at once,
 * which both skipped the animation entirely and produced six simultaneous
 * active rings — a state the lab cannot reach.
 */
async function walkFoSteps(page: Page, label: string): Promise<void> {
  for (let shown = 1; shown <= 6; shown++) {
    await expect(page.locator('#fo .step:not([hidden])')).toHaveCount(shown);
    await expect(page.locator('#fo .step.is-active')).toHaveCount(1);
    await scan(page, `${label} / FO step ${shown} of 6`);
    if (shown < 6) await btn(page, 'Reveal next step').click();
  }
  // At the end the control becomes "Replay from the start" — a different label
  // on the same button, and the state a reader lands in after finishing.
  await expect(btn(page, 'Replay from the start')).toBeVisible();
  await btn(page, 'Replay from the start').click();
  await expect(page.locator('#fo .step:not([hidden])')).toHaveCount(1);
  await scan(page, `${label} / FO replayed to step 1`);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * The mutation is this lab's single axis and it drives all five panels at once,
 * so each mutation is set and then the whole page is scanned:
 *
 *  - VALID (the shipped default) — both callers ACCEPT, the FO compare passes,
 *    the oracle table's "valid ct" column is the live one.
 *  - BIT FLIP — SAFE rejects, BROKEN alarms; this is the ONLY route to the red
 *    alarm palette and to `.compare-ne`, and the byte views gain their
 *    `.byte-diff` highlight.
 *  - LENGTH CORRUPTION — Decaps never reaches the FO branch, so the panel swaps
 *    to a `callout-reject` and the buffer panel reports the untouched buffer.
 *
 * Both resident-buffer branches are driven under the corrupted length, because
 * that is the only mutation where what was resident in the buffer reaches the
 * session key. "Reset to a valid ciphertext" and "Generate fresh keys" are the
 * lab's two resets and both are exercised.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint (valid ciphertext)`);

  // The skip link is `top: -3rem` until focused. Its focused rendering is the
  // only one a keyboard user ever sees, and it is the first tab stop.
  await page.keyboard.press('Tab');
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await scan(page, `${theme} / skip link focused`);

  await walkFoSteps(page, `${theme} / valid`);

  /* -- Bit flip: the alarm palette, and the only failing FO compare -------- */
  await btn(page, 'Flip a random bit').click();
  await expect(verdict(page, 'safe')).toHaveText('REJECT');
  await expect(verdict(page, 'broken')).toHaveText('ALARM');
  await expect(page.locator('.byte-diff').first()).toBeVisible();
  await scan(page, `${theme} / bit flipped`);
  await walkFoSteps(page, `${theme} / bit flipped`);
  // `walkFoSteps` finishes by replaying to step 1, which re-hides the compare
  // paragraph — so the failing compare is reached again through the lab's other
  // reveal control, which jumps straight to all six.
  await btn(page, 'Reveal whole branch').click();
  await expect(page.locator('#fo .step:not([hidden])')).toHaveCount(6);
  await expect(page.locator('.compare-ne')).toBeVisible();
  await scan(page, `${theme} / bit flipped, whole branch, FO compare failed`);

  /* -- The named presets, which are reproducible fixed scenarios ----------- */
  await btn(page, 'Single bit flip').click();
  await expect(page.locator('.mutation-status')).toContainText('byte 512');
  await scan(page, `${theme} / preset: single bit flip`);

  await btn(page, 'Length corruption').click();
  await expect(page.locator('#fo .callout-reject')).toBeVisible();
  await expect(verdict(page, 'broken')).toHaveText('ALARM');
  // No FO branch to step through, so the reveal controls are gone entirely.
  await expect(page.locator('#fo .control-row button')).toHaveCount(0);
  await scan(page, `${theme} / preset: length corruption (garbage resident)`);

  // The other branch of the resident-buffer fork. Only reachable — as a
  // difference that matters — while the length is corrupt, because that is the
  // only case where Decaps leaves the buffer untouched.
  await btn(page, "A previous call's shared secret").click();
  await expect(page.locator('#buffer')).toContainText("previous call's secret");
  await scan(page, `${theme} / length corruption (previous secret resident)`);

  await btn(page, 'Uninitialized stack garbage').click();
  await expect(page.locator('#buffer')).toContainText('stack garbage');
  await scan(page, `${theme} / length corruption (garbage resident, restored)`);

  /* -- Copy the scenario link: a transient confirmation state -------------- */
  await btn(page, 'Copy scenario link').click();
  await expect(page.locator('.copy-status')).toHaveText('Link copied.');
  await scan(page, `${theme} / scenario link copied`);

  /* -- Reset 1: back to a valid ciphertext --------------------------------- */
  await btn(page, 'Reset to a valid ciphertext').click();
  await expect(page.locator('.mutation-status')).toContainText('valid ciphertext (untouched)');
  await expect(verdict(page, 'safe')).toHaveText('ACCEPT');
  await scan(page, `${theme} / reset to valid`);

  /* -- Reset 2: fresh keys -------------------------------------------------- */
  await btn(page, 'Generate fresh keys').click();
  await expect(page.locator('.mutation-status')).toContainText('valid ciphertext (untouched)');
  await expect(page.locator('#fo .step:not([hidden])')).toHaveCount(1);
  await scan(page, `${theme} / fresh keys`);

  /* -- The last unpressed control: the "Valid" preset ----------------------- */
  // Pressed from a tampered state so it actually changes something. Matched
  // exactly, because `hasText` is a substring match and "Reset to a valid
  // ciphertext" contains it.
  await btn(page, 'Single bit flip').click();
  await expect(verdict(page, 'broken')).toHaveText('ALARM');
  await page.getByRole('button', { name: 'Valid', exact: true }).click();
  await expect(page.locator('.mutation-status')).toContainText('valid ciphertext (untouched)');
  await expect(verdict(page, 'broken')).toHaveText('ACCEPT');
  await scan(page, `${theme} / preset: valid`);
}

/**
 * The scenario permalink is a real entry point: the lab restores the mutation
 * from `location.hash` before first paint, so a linked scenario is somebody's
 * FIRST view of the page — including the alarm palette, which the default load
 * never shows. Scanned as its own arrival state.
 */
export async function driveLinkedScenario(page: Page, theme: string): Promise<void> {
  await page.goto('./#m=flip.512.3&r=previous');
  // A hash-only change is a same-document navigation: the bundle is not
  // re-evaluated, so `applyScenarioFromUrl()` — which runs once at module init —
  // never sees the new hash. Reloading forces the real load a visitor following
  // a shared link actually gets. Without this the drive would scan the previous
  // state while believing it was scanning the linked one.
  await page.reload();
  await expect(page.locator('.mutation-status')).toContainText('byte 512');
  await expect(verdict(page, 'broken')).toHaveText('ALARM');
  await expect(page.locator('#buffer')).toContainText("previous call's secret");
  await settle(page);
  await scan(page, `${theme} / arrived on a linked alarm scenario`);
  await btn(page, 'Reveal whole branch').click();
  await expect(page.locator('#fo .step:not([hidden])')).toHaveCount(6);
  await scan(page, `${theme} / linked scenario, whole branch revealed`);
}
