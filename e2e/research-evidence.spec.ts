import { expect, test } from '@playwright/test';

// Source: Das, ePrint 2026/1682, Table 1 and §§5–6.2 (pp.5–7).
// These assertions guard attribution and evidence scope, not attack reproduction.
// The paper was read in full on 2026-11-06, so each pointer below is checked
// against the page it sits on rather than against the abstract.
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
    await expect(note).toContainText('recovers 2047 of 2048 coefficients by 700 ciphertexts');
    await expect(note).toContainText('reused key and a constructed plaintext-checking oracle');
    await expect(note).toContainText('ciphertext counts are not query counts');
    await expect(note).toContainText('not as attack input');
    await expect(note).toContainText('does not show that any deployed protocol exposes the same oracle');
    await expect(note).toContainText('break of correct ML-KEM');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

    // The four qualifiers are restored, each scoped as the paper scopes it.
    // Asserting the SCOPE and not merely the word is the whole point: 'QEMU'
    // present somewhere would also pass if a future edit hung it on the native
    // AVX2 run, and 'idealized' would pass if it were hung on the hardware runs.
    for (const scoped of [
      'Table 1 on p. 5 carries both hardware figures',
      '98.0% at 400 ciphertexts on the AVX2 backend, which is native x86-64',
      '98.5% at 600 on NEON, which is ARM64 under QEMU emulation',
      '§5 on pp. 5–6 describes both runs',
      'compressed kyber-py reference model rather than on hardware',
      'idealized ±q/64 measurement noise',
      'marks those model counts optimistic',
      '§6.2 on p. 7 requires all 10^5–10^6 decapsulations',
      'HPKE static recipients and KEMTLS long-term keys are reachable when the key is long-lived',
      'less so under frequent rotation',
      'argued, not demonstrated, on pp. 3 and 7',
    ]) {
      await expect(note).toContainText(scoped);
    }
  });
}
