// Small byte helpers shared by the crypto layer, UI, and tests.

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Count differing bytes between two equal-length arrays (for the UI diff). */
export function byteDiffCount(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  let n = Math.abs(a.length - b.length);
  for (let i = 0; i < len; i++) if (a[i] !== b[i]) n++;
  return n;
}
