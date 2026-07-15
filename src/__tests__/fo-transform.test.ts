import { describe, expect, it } from 'vitest';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { shake256 } from '@noble/hashes/sha3.js';
import {
  decapsulateTraced,
  implicitRejectSecret,
  kPkeDecrypt,
} from '../kem/fo-transform.ts';
import { decapsulate, encapsulate, keygen, PARAMS } from '../kem/mlkem.ts';
import { toHex, bytesEqual } from '../kem/util.ts';

// The transparent FO reconstruction is only trustworthy if it matches the
// reference exactly. These are the KATs that make the teaching layer honest.

describe('transparent FO transform vs. reference decapsulate', () => {
  it('kPkeDecrypt recovers the exact message the sender encapsulated', () => {
    const bob = keygen();
    for (let i = 0; i < 5; i++) {
      const m = crypto.getRandomValues(new Uint8Array(32));
      const e = encapsulate(bob.publicKey, m);
      const dkPke = bob.secretKey.subarray(0, PARAMS.dkPkeBytes);
      const recovered = kPkeDecrypt(e.ciphertext, dkPke);
      expect(toHex(recovered)).toBe(toHex(m));
    }
  });

  it('J(z‖c) matches the reference implicit-rejection secret on tampered input', () => {
    const bob = keygen();
    const e = encapsulate(bob.publicKey);
    const tampered = e.ciphertext.slice();
    tampered[100] ^= 0x80;
    const z = bob.secretKey.subarray(bob.secretKey.length - 32);
    const kBar = implicitRejectSecret(z, tampered);
    // On a mismatch the reference returns exactly J(z‖c); confirm byte-for-byte.
    expect(toHex(decapsulate(tampered, bob.secretKey))).toBe(toHex(kBar));
    // And confirm our J is literally SHAKE256(z‖c, 32).
    const expected = shake256(new Uint8Array([...z, ...tampered]), { dkLen: 32 });
    expect(toHex(kBar)).toBe(toHex(expected));
  });

  it('traced Decaps returns byte-identical secret to the reference — valid ciphertexts', () => {
    for (let i = 0; i < 20; i++) {
      const bob = keygen();
      const e = encapsulate(bob.publicKey);
      const trace = decapsulateTraced(e.ciphertext, bob.secretKey);
      expect(toHex(trace.sharedSecret)).toBe(toHex(decapsulate(e.ciphertext, bob.secretKey)));
      // Valid ciphertext: re-encryption reproduces c, branch does NOT reject.
      expect(trace.ciphertextsMatch).toBe(true);
      expect(trace.implicitReject).toBe(false);
      expect(bytesEqual(trace.sharedSecret, trace.kHat)).toBe(true);
      expect(bytesEqual(trace.sharedSecret, e.sharedSecret)).toBe(true);
    }
  });

  it('traced Decaps returns byte-identical secret to the reference — tampered ciphertexts', () => {
    let rejections = 0;
    for (let i = 0; i < 30; i++) {
      const bob = keygen();
      const e = encapsulate(bob.publicKey);
      const tampered = e.ciphertext.slice();
      tampered[i % tampered.length] ^= 1 << (i % 8);
      const trace = decapsulateTraced(tampered, bob.secretKey);
      // Whatever the branch, it must equal the reference.
      expect(toHex(trace.sharedSecret)).toBe(toHex(decapsulate(tampered, bob.secretKey)));
      if (trace.implicitReject) {
        rejections++;
        // On reject the returned secret is K̄, and re-encryption differs from c.
        expect(trace.ciphertextsMatch).toBe(false);
        expect(bytesEqual(trace.sharedSecret, trace.kBar)).toBe(true);
      }
    }
    // A flipped bit essentially always triggers implicit rejection.
    expect(rejections).toBeGreaterThan(25);
  });

  it('the two candidate secrets K̂ and K̄ are distinct on a rejected ciphertext', () => {
    const bob = keygen();
    const e = encapsulate(bob.publicKey);
    const tampered = e.ciphertext.slice();
    tampered[500] ^= 0x01;
    const trace = decapsulateTraced(tampered, bob.secretKey);
    expect(trace.implicitReject).toBe(true);
    expect(bytesEqual(trace.kHat, trace.kBar)).toBe(false);
  });

  it('cross-checks against a fully independent reconstruction path', () => {
    // Independent oracle: reference decaps must equal our trace for the same input.
    const bob = keygen();
    const m = crypto.getRandomValues(new Uint8Array(32));
    const { cipherText } = ml_kem768.encapsulate(bob.publicKey, m);
    const trace = decapsulateTraced(cipherText, bob.secretKey);
    expect(toHex(trace.mPrime)).toBe(toHex(m));
    expect(toHex(trace.reencrypted)).toBe(toHex(cipherText));
  });
});
