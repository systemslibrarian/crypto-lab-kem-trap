import { expect, test } from '@playwright/test';

// Source: Das, ePrint 2026/1682, Table 1 and §§5–6.2 (pp.5–7).
// These assertions guard attribution and evidence scope, not attack reproduction.
for (const width of [1280, 380]) {
  test(`incomplete comparison distinguishes binary and model evidence at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await page.locator('#incomplete-comparison > summary').click();
    const note = page.locator('#incomplete-comparison');
    await expect(note).toBeVisible();
    await expect(note.locator('a[href="https://eprint.iacr.org/2026/1682"]')).toBeVisible();
    await expect(note).toContainText('2048 secret coefficients of ML-KEM-1024');
    await expect(note).toContainText('98.0% at 400 ciphertexts on the AVX2 backend');
    await expect(note).toContainText('98.5% at 600 on NEON');
    await expect(note).toContainText('about 1300 ciphertexts');
    await expect(note).toContainText("quoted from the preprint’s own abstract");
    await expect(note).toContainText('recovers all 2048 at about 1300 ciphertexts');
    await expect(note).toContainText('reused key and a constructed plaintext-checking oracle');
    await expect(note).toContainText('ciphertext counts are not query counts');
    await expect(note).toContainText('not as attack input');
    await expect(note).toContainText('does not show that any deployed protocol exposes the same oracle');
    await expect(note).toContainText('break of correct ML-KEM');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

  // These went because the PDF answers 403 and none of them is in the abstract.
  // Asserting their ABSENCE is what stops the old wording returning unnoticed.
  for (const gone of ['HPKE', 'KEMTLS', 'QEMU', 'Table 1', 'idealized']) {
    await expect(note).not.toContainText(gone);
  }
  });
}
