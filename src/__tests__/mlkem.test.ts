import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  PARAMS,
  decapsulate,
  encapsulate,
  keygen,
  publicKeyFromSecret,
} from '../kem/mlkem.ts';
import { VECTORS } from '../kem/vectors.ts';
import { toHex, bytesEqual } from '../kem/util.ts';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

describe('ML-KEM-768 wrapper', () => {
  it('round-trips: Encaps then Decaps recovers the same 32-byte secret', () => {
    const kp = keygen();
    const e = encapsulate(kp.publicKey);
    const k = decapsulate(e.ciphertext, kp.secretKey);
    expect(toHex(k)).toBe(toHex(e.sharedSecret));
    expect(k.length).toBe(32);
  });

  it('produces FIPS 203 Table 3 lengths for ML-KEM-768', () => {
    const kp = keygen();
    const e = encapsulate(kp.publicKey);
    expect(kp.publicKey.length).toBe(PARAMS.publicKey); // 1184
    expect(kp.secretKey.length).toBe(PARAMS.secretKey); // 2400
    expect(e.ciphertext.length).toBe(PARAMS.ciphertext); // 1088
    expect(e.sharedSecret.length).toBe(PARAMS.sharedSecret); // 32
  });

  it('embeds the public key inside the secret key (ek recoverable from dk)', () => {
    const kp = keygen();
    expect(bytesEqual(publicKeyFromSecret(kp.secretKey), kp.publicKey)).toBe(true);
  });

  it('Decaps NEVER throws on a well-formed-but-wrong ciphertext (implicit rejection)', () => {
    const bob = keygen();
    const mallory = keygen();
    const e = encapsulate(bob.publicKey);
    // Wrong key still returns 32 bytes — silently — instead of an error.
    const wrong = decapsulate(e.ciphertext, mallory.secretKey);
    expect(wrong.length).toBe(32);
    expect(toHex(wrong)).not.toBe(toHex(e.sharedSecret));
  });

  it('a single flipped ciphertext bit yields a different secret, not an error', () => {
    const bob = keygen();
    const e = encapsulate(bob.publicKey);
    const tampered = e.ciphertext.slice();
    tampered[10] ^= 0x01;
    const k = decapsulate(tampered, bob.secretKey);
    expect(k.length).toBe(32);
    expect(toHex(k)).not.toBe(toHex(e.sharedSecret));
  });

  it('rejects malformed lengths loudly (the one place Decaps does throw)', () => {
    const bob = keygen();
    expect(() => decapsulate(new Uint8Array(1087), bob.secretKey)).toThrow();
    expect(() => decapsulate(new Uint8Array(PARAMS.ciphertext), new Uint8Array(2399))).toThrow();
  });

  describe('deterministic known-answer vectors (pinned to the ACVP-validated reference)', () => {
    for (const v of VECTORS) {
      it(`vector #${v.n}: seed/message reproduce pinned ek, dk, ct, and shared secret`, () => {
        const kp = ml_kem768.keygen(v.seed);
        expect(toHex(sha256(kp.publicKey))).toBe(v.ekSha256);
        expect(toHex(sha256(kp.secretKey))).toBe(v.dkSha256);
        const e = encapsulate(kp.publicKey, v.message);
        expect(toHex(sha256(e.ciphertext))).toBe(v.ctSha256);
        expect(toHex(e.sharedSecret)).toBe(v.sharedSecret);
        // Decaps of the pinned ciphertext returns the pinned secret.
        const k = decapsulate(e.ciphertext, kp.secretKey);
        expect(toHex(k)).toBe(v.sharedSecret);
      });
    }
  });
});
