import { expect, test } from '@playwright/test';

for (const width of [1280, 320]) {
  test(`security-property matrix keeps premises and evidence together at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    const matrix = page.locator('#security-properties');
    await expect(matrix.getByRole('row')).toHaveCount(7);
    const timing = matrix.locator('[data-evidence-row="timing"]');
    await expect(timing).toContainText('Raspberry Pi 2 and Arm Cortex-M4');
    await expect(timing).toContainText('linked lab is a simulation');
    const comparison = matrix.locator('[data-evidence-row="comparison"]');
    await expect(comparison).toContainText('reused key');
    await expect(comparison).toContainText('partial binary recovery');
    await expect(comparison).toContainText('idealized reference model');
    await expect(comparison).toContainText('No deployed HPKE/KEMTLS oracle bridge');
    for (const link of await matrix.locator('tbody a').all()) {
      const href = await link.getAttribute('href');
      expect(href).toBeTruthy();
      if (href?.startsWith('#')) await expect(page.locator(href)).toHaveCount(1);
    }
    const scenarioBefore = await page.evaluate(() => location.hash);
    const focus = matrix.getByLabel('Focus on a security property');
    await focus.selectOption('identity');
    await expect(matrix.locator('tbody tr')).toHaveCount(1);
    await expect(matrix).toContainText('A matching tag alone does not establish a real-world identity');
    await expect(matrix.getByRole('status')).toContainText('Showing 1 of 6');
    await focus.selectOption('agreement');
    await expect(matrix.locator('[data-evidence-row="caller"]')).toBeVisible();
    await focus.selectOption('confidentiality');
    await expect(matrix.locator('tbody tr')).toHaveCount(4);
    await focus.selectOption('all');
    await expect(matrix.locator('tbody tr')).toHaveCount(6);
    expect(await page.evaluate(() => location.hash)).toBe(scenarioBefore);
    const scroll = matrix.getByRole('region');
    await scroll.focus();
    await expect(scroll).toBeFocused();
    if (width === 320) {
      const before = await scroll.evaluate(node => node.scrollLeft);
      await page.keyboard.press('ArrowRight');
      await expect.poll(() => scroll.evaluate(node => node.scrollLeft)).toBeGreaterThan(before);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
