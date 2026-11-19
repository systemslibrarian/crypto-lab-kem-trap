import { expect, test } from '@playwright/test';

// Act 6 — "Keys that bind nothing" (MAL-BIND, Schmieg 2024).
//
// The honesty of this exhibit is a PAIR of claims that must travel together: the
// ML-KEM *primitive* is neither MAL-BIND-K-CT nor MAL-BIND-K-PK against a
// maliciously built decapsulation key (one secret, two ciphertexts / two public
// keys), AND the real @noble ML-KEM-768 mitigates the K-CT case because its
// decapsulate enforces the FIPS 203 §7.3 key check. Drop either half and the
// card either overclaims a break or hides one. The outcomes themselves are
// computed in src/kem/malformed.ts and guarded byte-for-byte in
// src/__tests__/malformed.test.ts; this spec guards that the page SHOWS them,
// with the framing intact, so corrected wording cannot silently return.

test('MAL-BIND-K-CT is shown as a real collision that the library still rejects', async ({ page }) => {
  await page.goto('.');
  const panel = page.locator('#malformed');
  await expect(panel).toBeVisible();

  // The break: one shared secret from two different ciphertexts, two public keys.
  await expect(panel.getByText('Same shared secret').first()).toBeVisible();
  await expect(panel.getByText('K₀ = K₁, byte for byte')).toBeVisible();
  await expect(panel.getByText('c₀ ≠ c₁')).toBeVisible();
  await expect(panel.getByText('ek₀ ≠ ek₁').first()).toBeVisible();

  // The mitigation, which keeps the card honest: the §7.3 check catches the
  // tampered key, and @noble enforces it, so real ML-KEM-768 is not vulnerable.
  await expect(panel.getByText('REJECTS the tampered key')).toBeVisible();
  await expect(panel.getByText(/throws on the tampered key.*not vulnerable to this one/)).toBeVisible();
});

test('MAL-BIND-K-PK is shown as a collision the hash check cannot see', async ({ page }) => {
  await page.goto('.');
  const panel = page.locator('#malformed');

  await expect(panel.getByText('K₀ = K₁', { exact: false }).first()).toBeVisible();
  await expect(panel.getByText(/implicit-rejection secret/)).toBeVisible();
  await expect(panel.getByText('J(z ‖ c), the FO rejection branch')).toBeVisible();
  // The hash check PASSES on both keys here — it is the wrong defence for K-PK.
  await expect(panel.getByText('PASSES — it cannot see this')).toBeVisible();
});

test('the encapsulation coin alone is shown to be the key', async ({ page }) => {
  await page.goto('.');
  const panel = page.locator('#malformed');

  await expect(panel.getByText('The coin IS the key')).toBeVisible();
  await expect(panel.getByText('identical — no ciphertext needed')).toBeVisible();
});

test('re-running an act keeps the outcome (fresh real keys, same verdict)', async ({ page }) => {
  await page.goto('.');
  const panel = page.locator('#malformed');
  await panel.getByRole('button', { name: 'Run with fresh keys' }).first().click();
  // A fresh pair of real ML-KEM-768 keys still collides to one secret.
  await expect(panel.getByText('K₀ = K₁, byte for byte')).toBeVisible();
  await expect(panel.getByText('REJECTS the tampered key')).toBeVisible();
});
