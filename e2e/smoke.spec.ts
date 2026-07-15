import { expect, test, type Page } from '@playwright/test';

// Cross-browser functional smoke. Runs on Chromium, Firefox, WebKit and a mobile
// viewport (see playwright.config.ts) to prove portability rather than assume it.
// Deliberately NO axe here — the full accessibility scan stays Chromium-only for
// runtime cost; this suite asserts the teaching-critical behavior and the visual
// distinctness of the three verdict states.

const btn = (page: Page, label: string) => page.locator('#app button', { hasText: label });

function verdictText(page: Page, caller: 'safe' | 'broken') {
  return page.locator(`.caller-${caller} .indicator .indicator-text`).nth(1); // [0]=crypto result, [1]=verdict
}

test('valid ciphertext: SAFE accepts, BROKEN accepts (only by luck)', async ({ page }) => {
  await page.goto('.');
  await expect(verdictText(page, 'safe')).toHaveText('ACCEPT');
  await expect(verdictText(page, 'broken')).toHaveText('ACCEPT');
  await expect(page.locator('.caller-broken .caller-note')).toContainText(/no confirmation/i);
});

test('flipped bit: real crypto drives SAFE→REJECT and BROKEN→ALARM', async ({ page }) => {
  await page.goto('.');
  await btn(page, 'Flip a random bit').click();
  await expect(verdictText(page, 'safe')).toHaveText('REJECT');
  await expect(verdictText(page, 'broken')).toHaveText('ALARM');
  // Reveal the branch (steps are progressively hidden), then confirm the
  // re-encryption diverges.
  await btn(page, 'Reveal whole branch').click();
  await expect(page.locator('.compare-ne')).toBeVisible();
  // The consolidated announcer narrates the consequence.
  await expect(page.locator('[aria-live="polite"][aria-atomic="true"]')).toContainText(
    /implicit-rejection secret/i,
  );
});

test('corrupted length: Decaps is rejected pre-branch, BROKEN keys on resident bytes', async ({
  page,
}) => {
  await page.goto('.');
  await btn(page, 'Corrupt the length').click();
  await expect(verdictText(page, 'broken')).toHaveText('ALARM');
  // FO panel never reaches the branch.
  await expect(page.locator('#fo .callout-reject')).toBeVisible();
  // Buffer inspector reports the untouched buffer.
  await expect(page.locator('#buffer')).toContainText(/buffer NOT written|resident bytes/i);
});

test('a scenario permalink restores the mutation on load', async ({ page }) => {
  await page.goto('./#m=flip.512.3&r=previous');
  // The scenario is restored from the URL alone.
  await expect(page.locator('.mutation-status')).toContainText('byte 512');
  await expect(verdictText(page, 'broken')).toHaveText('ALARM');
  await btn(page, 'Reveal whole branch').click();
  await expect(page.locator('.compare-ne')).toBeVisible();
});

test('the three verdicts are visually and textually distinct (dark + light)', async ({ page }) => {
  await page.goto('.');
  await btn(page, 'Flip a random bit').click(); // now ACCEPT (provenance), REJECT (safe), ALARM (broken) all on screen

  async function colorsAndText() {
    const read = async (cls: string) => {
      const locator = page.locator(`.${cls} .indicator-text`).first();
      const color = await locator.evaluate((el) => getComputedStyle(el).color);
      const text = (await locator.textContent()) || '';
      return { color, text };
    };
    return {
      accept: await read('v-accept'),
      reject: await read('v-reject'),
      alarm: await read('v-alarm'),
    };
  }

  async function assertDistinct() {
    const { accept, reject, alarm } = await colorsAndText();
    // Colors are mutually distinct (never convey state by a shared color).
    expect(new Set([accept.color, reject.color, alarm.color]).size).toBe(3);
    // Text labels are distinct too (never color alone).
    expect(accept.text).not.toBe(reject.text);
    expect(reject.text).not.toBe(alarm.text);
    expect(accept.text).not.toBe(alarm.text);
  }

  await assertDistinct(); // dark
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await assertDistinct(); // light
});
