import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Reveal collapsed / progressively-hidden content so axe scans it. The FO panel
// hides not-yet-revealed steps with the `hidden` attribute for real users; here
// we un-hide them all so the whole branch is scanned.
async function reveal(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
    document.querySelectorAll<HTMLElement>('[hidden],[role="tabpanel"]').forEach((el) => {
      el.removeAttribute('hidden');
      el.style.display = '';
      el.classList.add('active', 'is-active', 'open', 'is-revealed');
    });
  });
  await page.waitForTimeout(200);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

// Scan a clean state (full valid FO branch) AND a tampered state (a flipped bit
// drives the REJECT / ALARM styling and the FO rejection branch) so both the
// success and failure palettes are checked.
async function scanBothStates(page: Page): Promise<void> {
  await reveal(page);
  await scan(page);
  await page.locator('#app button', { hasText: 'Flip a random bit' }).click();
  await reveal(page); // re-hide happens on re-render; reveal the FO branch again
  await scan(page);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await scanBothStates(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await scanBothStates(page);
});
