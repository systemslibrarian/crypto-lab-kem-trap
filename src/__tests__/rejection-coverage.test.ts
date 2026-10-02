import { describe, expect, it } from 'vitest';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { decapsulateTraced } from '../kem/fo-transform.ts';

// Detect a prefix-only re-encryption check: mutations include every byte and
// every compressed v coefficient, with fixed seeds and a valid positive control.
// These are rejection regressions, not a reproduction of ePrint 2026/2239.
for (const [name, kem, vBytes, dv] of [
  ['512', ml_kem512, 128, 4],
  ['768', ml_kem768, 128, 4],
  ['1024', ml_kem1024, 160, 5],
] as const) {
  describe(`ML-KEM-${name} complete ciphertext comparison`, () => {
    it('returns exactly J(z||c) for mutations across the whole ciphertext', () => {
      const seed = Uint8Array.from({ length: 64 }, (_, i) => i);
      const { publicKey, secretKey } = kem.keygen(seed);
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey, new Uint8Array(32).fill(42));
      expect(kem.decapsulate(cipherText, secretKey)).toEqual(sharedSecret);
      const z = secretKey.slice(-32);
      const bits = new Set<number>();
      for (let i = 0; i < cipherText.length; i++) bits.add(i * 8);
      for (let i = 0; i < 256; i++) bits.add((cipherText.length - vBytes) * 8 + i * dv);
      for (const bit of bits) {
        const changed = cipherText.slice();
        changed[Math.floor(bit / 8)] ^= 1 << (bit % 8);
        const expected = shake256(new Uint8Array([...z, ...changed]), { dkLen: 32 });
        expect(kem.decapsulate(changed, secretKey), `mutated bit ${bit}`).toEqual(expected);
        if (name === '768') {
          const traced = decapsulateTraced(changed, secretKey);
          expect(traced.implicitReject, `traced bit ${bit}`).toBe(true);
          expect(traced.sharedSecret).toEqual(expected);
        }
      }
    }, 120000);
  });
}
