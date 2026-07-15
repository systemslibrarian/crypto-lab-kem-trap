// The headline mechanism, made inspectable.
//
// ML-KEM's Decapsulation is a Fujisaki–Okamoto (FO) transform (FIPS 203 §7.3,
// Algorithm 18). The library computes it and hands back 32 bytes. To *show* the
// branch — decrypt, re-encrypt, compare, and on mismatch return the pseudorandom
// implicit-rejection secret instead of erroring — we reconstruct the same
// computation here with every intermediate exposed.
//
// What is hand-rolled vs. borrowed, and why it is honest:
//   - K-PKE.Decrypt (m' recovery) is hand-rolled below from the reference's own
//     tested math surfaces (`__tests`: ByteDecode/Decompress/NTT/…). The library
//     does not export this subroutine, and it is exactly the inspectable internal
//     the lab teaches, so we build it in the open.
//   - Re-encryption + K̂ derivation reuse the real `ml_kem768.encapsulate(ek, m')`,
//     which IS G(m'‖H(ek)) followed by K-PKE.Encrypt — identical to what Decaps
//     does internally.
//   - K̄ = J(z‖c) is the real SHAKE256 call (FIPS 203's function J).
//
// This reconstruction is not trusted on faith: `fo-transform.test.ts` asserts it
// equals `ml_kem768.decapsulate` byte-for-byte across many valid and tampered
// ciphertexts. If it ever diverged, the build would fail.

import { __tests, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { PARAMS } from './mlkem.ts';
import type { DecapsTrace } from './types.ts';

const Q = 3329;
const N = 256;
const { ByteDecode_d, Decompress_d, Compress_d, ByteEncode_d, NTT, NTT_inv, MultiplyNTTs } =
  __tests as {
    ByteDecode_d: (b: Uint8Array, d: number) => Uint16Array;
    Decompress_d: (y: number, d: number) => number;
    Compress_d: (x: number, d: number) => number;
    ByteEncode_d: (f: Uint16Array, d: number) => Uint8Array;
    NTT: (f: Uint16Array) => Uint16Array;
    NTT_inv: (f: Uint16Array) => Uint16Array;
    MultiplyNTTs: (f: Uint16Array, g: Uint16Array) => Uint16Array;
  };

const mod = (x: number): number => {
  const r = x % Q;
  return r < 0 ? r + Q : r;
};

/**
 * K-PKE.Decrypt (FIPS 203 Algorithm 15), reconstructed transparently.
 * Recovers the 32-byte message m' that Decaps derives from a ciphertext — for
 * ANY ciphertext, well-formed or tampered. This is what makes it possible to
 * show the re-encryption diverging on an adversarial input.
 */
export function kPkeDecrypt(ciphertext: Uint8Array, dkPke: Uint8Array): Uint8Array {
  const { K, du, dv, c1Bytes } = PARAMS;
  const c1 = ciphertext.subarray(0, c1Bytes);
  const c2 = ciphertext.subarray(c1Bytes);

  // u ← Decompress_du(ByteDecode_du(c1)) — K noise-carrying polynomials.
  const u: Uint16Array[] = [];
  for (let i = 0; i < K; i++) {
    const chunk = c1.subarray(i * 32 * du, (i + 1) * 32 * du);
    const raw = ByteDecode_d(chunk, du);
    const poly = new Uint16Array(N);
    for (let j = 0; j < N; j++) poly[j] = Decompress_d(raw[j], du);
    u.push(poly);
  }

  // v ← Decompress_dv(ByteDecode_dv(c2)).
  const rawV = ByteDecode_d(c2, dv);
  const v = new Int32Array(N);
  for (let j = 0; j < N; j++) v[j] = Decompress_d(rawV[j], dv);

  // ŝ ← ByteDecode_12(dkPKE) — the secret vector, already in NTT domain.
  const acc = new Int32Array(N);
  for (let i = 0; i < K; i++) {
    const sHat = ByteDecode_d(dkPke.subarray(i * 384, (i + 1) * 384), 12);
    const prod = MultiplyNTTs(sHat, NTT(u[i])); // ŝ_i ◦ NTT(u_i)
    for (let j = 0; j < N; j++) acc[j] = mod(acc[j] + prod[j]);
  }
  const inv = NTT_inv(Uint16Array.from(acc, mod));

  // w ← v − NTT⁻¹(ŝᵀ ◦ NTT(u)); m' ← ByteEncode_1(Compress_1(w)).
  const w = new Uint16Array(N);
  for (let j = 0; j < N; j++) w[j] = mod(v[j] - inv[j]);
  const compressed = Uint16Array.from(w, (x) => Compress_d(x, 1));
  return ByteEncode_d(compressed, 1);
}

/** J(z ‖ c) — FIPS 203's function J is SHAKE256 with a 32-byte output. */
export function implicitRejectSecret(z: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const input = new Uint8Array(z.length + ciphertext.length);
  input.set(z, 0);
  input.set(ciphertext, z.length);
  return shake256(input, { dkLen: 32 });
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Decapsulate with the full FO branch exposed. The returned `sharedSecret` is
 * byte-identical to `mlkem.decapsulate` (KAT-enforced); every other field exists
 * only to let the UI animate the mechanism.
 */
export function decapsulateTraced(ciphertext: Uint8Array, secretKey: Uint8Array): DecapsTrace {
  const { dkPkeBytes, publicKey: ekLen } = PARAMS;
  const dkPke = secretKey.subarray(0, dkPkeBytes);
  const ek = secretKey.subarray(dkPkeBytes, dkPkeBytes + ekLen);
  const z = secretKey.subarray(secretKey.length - 32);

  const mPrime = kPkeDecrypt(ciphertext, dkPke);

  // Re-encrypt m' under the real encapsulation: this is G(m'‖H(ek)) then
  // K-PKE.Encrypt, giving both the candidate ciphertext c' and the "real" key K̂.
  const re = ml_kem768.encapsulate(ek, mPrime);
  const reencrypted: Uint8Array = re.cipherText;
  const kHat: Uint8Array = re.sharedSecret;

  const kBar = implicitRejectSecret(z, ciphertext);
  const ciphertextsMatch = bytesEqual(reencrypted, ciphertext);

  return {
    ciphertext,
    mPrime,
    reencrypted,
    kHat,
    kBar,
    ciphertextsMatch,
    implicitReject: !ciphertextsMatch,
    sharedSecret: ciphertextsMatch ? kHat : kBar,
  };
}
