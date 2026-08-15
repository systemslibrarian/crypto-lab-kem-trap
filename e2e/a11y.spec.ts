import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  driveLinkedScenario,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where the
 * ciphertext is untampered, both callers read ACCEPT and the alarm palette is
 * nowhere on screen; the skip link focused; the FO branch walked ONE PRESS AT A
 * TIME through all six steps and then replayed, for a valid ciphertext and
 * again for a flipped bit, because only the flipped bit produces `.compare-ne`,
 * the red ALARM indicator and the `.byte-diff` highlight; both named presets;
 * the corrupted length, where Decaps never reaches the FO branch and the panel
 * swaps to a rejection callout with the reveal controls gone; both branches of
 * the resident-buffer fork under that corruption, which is the only state where
 * what was in the buffer reaches the session key; the transient "Link copied"
 * confirmation; both resets; and a scenario PERMALINK, which is a real entry
 * point that puts a reader on the alarm palette before first paint. Every one
 * of those states is scanned, in both themes, at desktop and phone width.
 *
 * Clipboard permission is granted because "Copy scenario link" calls
 * `navigator.clipboard.writeText`. The handler does have a fallback, so without
 * the grant the confirmation would still appear — but it would appear from the
 * rejection path, which is not the state a visitor reaches.
 *
 * See `gate.ts` for why nothing is injected into the page, why the FO steps are
 * revealed through the lab's own button rather than by stripping `hidden`, why
 * the lab's shipped defaults are asserted rather than assumed, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(600_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    await driveLinkedScenario(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(600_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    await driveLinkedScenario(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });
}
