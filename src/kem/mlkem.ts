// ML-KEM-768 — real post-quantum KEM, FIPS 203 (August 2024).
// https://csrc.nist.gov/pubs/fips/203/final
//
// This module is a thin, honest wrapper over @noble/post-quantum, whose ML-KEM
// implementation passes the NIST ACVP test suite. We do NOT re-implement the
// scheme here — the transparent, hand-rolled teaching layer (the FO branch that
// this lab exists to show) lives in fo-transform.ts and is KAT-checked against
// the reference `decapsulate` below.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import type { EncapsResult, MlKemKeyPair } from './types.ts';

// FIPS 203, Table 3 — ML-KEM-768 (Category 3) byte lengths.
export const PARAMS = {
  name: 'ML-KEM-768',
  category: 3,
  publicKey: 1184,
  secretKey: 2400,
  ciphertext: 1088,
  sharedSecret: 32,
  message: 32,
  seed: 64,
  // K-PKE structural sizes for K=3, du=10, dv=4 (used by the transparent decrypt).
  K: 3,
  du: 10,
  dv: 4,
  dkPkeBytes: 1152, // 384 * K
  c1Bytes: 960, // 32 * du * K
  c2Bytes: 128, // 32 * dv
} as const;

function assertLen(label: string, actual: number, expected: number): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected} bytes, got ${actual}`);
  }
}

/** KeyGen. With no seed the reference draws fresh randomness. */
export function keygen(seed?: Uint8Array): MlKemKeyPair {
  const pair = seed ? ml_kem768.keygen(seed) : ml_kem768.keygen();
  assertLen('public key', pair.publicKey.length, PARAMS.publicKey);
  assertLen('secret key', pair.secretKey.length, PARAMS.secretKey);
  return { publicKey: pair.publicKey, secretKey: pair.secretKey };
}

/**
 * Encaps. `message` is the 32-byte pre-secret; passing it fixes the randomness
 * (FIPS 203 Algorithm 17's deterministic hook) so the demo is reproducible and
 * so we can show that re-encrypting the SAME m reproduces the SAME c.
 */
export function encapsulate(publicKey: Uint8Array, message?: Uint8Array): EncapsResult {
  assertLen('public key', publicKey.length, PARAMS.publicKey);
  const m = message ?? crypto.getRandomValues(new Uint8Array(PARAMS.message));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, m);
  assertLen('ciphertext', cipherText.length, PARAMS.ciphertext);
  assertLen('shared secret', sharedSecret.length, PARAMS.sharedSecret);
  return { ciphertext: cipherText, sharedSecret, message: m };
}

/**
 * Decaps — the reference implementation. ALWAYS returns 32 bytes. Never throws
 * for a well-formed-but-wrong ciphertext: on a re-encryption mismatch it returns
 * the implicit-rejection secret K̄ = J(z||c) instead of signalling failure. That
 * silence is the entire subject of this lab.
 */
export function decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  assertLen('ciphertext', ciphertext.length, PARAMS.ciphertext);
  assertLen('secret key', secretKey.length, PARAMS.secretKey);
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

/** ek = the last-but-one field of dk; the public key is embedded in the secret key. */
export function publicKeyFromSecret(secretKey: Uint8Array): Uint8Array {
  assertLen('secret key', secretKey.length, PARAMS.secretKey);
  return ml_kem768.getPublicKey(secretKey);
}
