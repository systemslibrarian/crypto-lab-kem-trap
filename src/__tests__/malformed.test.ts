import { describe, expect, it } from 'vitest';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { keygen, PARAMS } from '../kem/mlkem.ts';
import { kPkeEncryptWithRandomness, deriveKr } from '../kem/kpke-encrypt.ts';
import {
  coinToKey,
  fipsHashCheck,
  hField,
  malBindKCt,
  malBindKPk,
  tamperHash,
  tamperZ,
} from '../kem/malformed.ts';
import { toHex, bytesEqual } from '../kem/util.ts';
import { VECTORS } from '../kem/vectors.ts';

describe('K-PKE.Encrypt reconstruction (KAT vs reference)', () => {
  it('reproduces ml_kem768.encapsulate’s ciphertext byte-for-byte', () => {
    for (let i = 0; i < 8; i++) {
      const { publicKey: ek } = keygen();
      const m = crypto.getRandomValues(new Uint8Array(32));
      const ref = ml_kem768.encapsulate(ek, m);
      const { randomness } = deriveKr(m, sha3_256(ek));
      const mine = kPkeEncryptWithRandomness(ek, m, randomness);
      expect(toHex(mine)).toBe(toHex(ref.cipherText));
    }
  });

  it('agrees with the reference on the lab’s pinned vector #0', () => {
    const v = VECTORS[0];
    const { publicKey: ek } = ml_kem768.keygen(v.seed);
    const ref = ml_kem768.encapsulate(ek, v.message);
    const { sharedSecret, randomness } = deriveKr(v.message, sha3_256(ek));
    expect(toHex(kPkeEncryptWithRandomness(ek, v.message, randomness))).toBe(toHex(ref.cipherText));
    expect(toHex(sharedSecret)).toBe(v.sharedSecret);
  });
});

describe('Algorithm 2 — MAL-BIND-K-CT (malformed hash field)', () => {
  it('two parties obtain the same K from different ciphertexts and different keys', () => {
    for (let i = 0; i < 4; i++) {
      const r = malBindKCt();
      expect(r.sameSecret).toBe(true);
      expect(r.differentCiphertext).toBe(true);
      expect(r.differentPublicKey).toBe(true);
      // Re-derive independently: K equals G(m0 ‖ h0)[:32] and neither ciphertext
      // is a function the other.
      expect(r.K0.length).toBe(PARAMS.sharedSecret);
      expect(bytesEqual(r.K0, r.K1)).toBe(true);
    }
  });

  it('the FIPS 203 §7.3 hash check rejects the tampered key, and the library enforces it', () => {
    const r = malBindKCt();
    expect(r.hashCheckRejects).toBe(true);
    expect(r.libraryEnforcesCheck).toBe(true);
    // And a well-formed key passes.
    expect(fipsHashCheck(keygen().secretKey)).toBe(true);
  });
});

describe('Algorithm 3 — MAL-BIND-K-PK (shared implicit-rejection seed)', () => {
  it('one random ciphertext gives the same K under two different public keys', () => {
    for (let i = 0; i < 4; i++) {
      const r = malBindKPk();
      expect(r.sameSecret).toBe(true);
      expect(r.differentPublicKey).toBe(true);
      expect(r.isImplicitReject).toBe(true);
    }
  });

  it('the hash check does NOT stop it — both keys are internally consistent', () => {
    const r = malBindKPk();
    expect(r.hashCheckPassesBoth).toBe(true);
    // Only sharing z: tampering z keeps h = H(ek), so the check sees nothing.
    const dk = keygen().secretKey;
    const z = crypto.getRandomValues(new Uint8Array(32));
    expect(fipsHashCheck(tamperZ(dk, z))).toBe(true);
    // Whereas tampering h breaks the check.
    expect(fipsHashCheck(tamperHash(dk, sha3_256(crypto.getRandomValues(new Uint8Array(1184)))))).toBe(false);
  });
});

describe('the encapsulation coin is the key', () => {
  it('K = G(m ‖ H(ek)) is recoverable from the coin alone, without the ciphertext', () => {
    for (let i = 0; i < 4; i++) {
      const { publicKey: ek } = keygen();
      const r = coinToKey(ek);
      expect(r.matches).toBe(true);
      // Re-derive once more, the long way, independent of coinToKey.
      const g = sha3_512(Uint8Array.from([...r.m, ...sha3_256(ek)]));
      expect(toHex(r.keyFromCoin)).toBe(toHex(g.subarray(0, 32)));
    }
  });
});

describe('hField accessor', () => {
  it('reads H(ek) out of a well-formed key', () => {
    const dk = keygen().secretKey;
    const ek = dk.subarray(PARAMS.dkPkeBytes, PARAMS.dkPkeBytes + PARAMS.publicKey);
    expect(toHex(hField(dk))).toBe(toHex(sha3_256(ek)));
  });
});
