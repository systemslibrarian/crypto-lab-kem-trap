// K-PKE.Encrypt (FIPS 203 Algorithm 14), reconstructed transparently so the lab
// can encrypt under an ATTACKER-CHOSEN randomness r. The library's
// `ml_kem768.encapsulate(ek, m)` derives its own r = G(m ‖ H(ek)) internally and
// gives no hook to override it — but the malformed-key attacks (src/kem/malformed.ts)
// and the faithful FO trace (src/kem/fo-transform.ts, which must re-encrypt with
// the randomness Decaps derives from the key's STORED hash, not a recomputed one)
// both need exactly that hook.
//
// It is built from the reference's own tested math surfaces (`__tests`:
// ByteDecode/Compress/NTT/SampleNTT/SamplePolyCBD/…) and @noble/hashes, mirroring
// @noble's own `encryptCore` step for step. It is not trusted on faith:
// kpke-encrypt.test.ts asserts it reproduces `ml_kem768.encapsulate(ek, m).cipherText`
// byte-for-byte across many keys, which is the strongest possible check.
import { __tests } from '@noble/post-quantum/ml-kem.js';
import { sha3_256, sha3_512, shake256 } from '@noble/hashes/sha3.js';
import { PARAMS } from './mlkem.ts';

const N = 256;
const Q = 3329;
const { K, du, dv } = PARAMS;
const ETA1 = 2; // ML-KEM-768, FIPS 203 Table 2
const ETA2 = 2;

const { ByteDecode_d, ByteEncode_d, Compress_d, Decompress_d, NTT, NTT_inv, MultiplyNTTs, SampleNTT, SamplePolyCBD } =
  __tests as {
    ByteDecode_d: (b: Uint8Array, d: number) => Uint16Array;
    ByteEncode_d: (f: Uint16Array, d: number) => Uint8Array;
    Compress_d: (x: number, d: number) => number;
    Decompress_d: (y: number, d: number) => number;
    NTT: (f: Uint16Array) => Uint16Array;
    NTT_inv: (f: Uint16Array) => Uint16Array;
    MultiplyNTTs: (f: Uint16Array, g: Uint16Array) => Uint16Array;
    SampleNTT: (seed34: Uint8Array) => Uint16Array;
    SamplePolyCBD: (bytes: Uint8Array, eta: number) => Uint16Array;
  };

const mod = (a: number): number => ((a % Q) + Q) % Q;
const polyAdd = (a: Uint16Array, b: Uint16Array): Uint16Array => {
  const r = new Uint16Array(N);
  for (let i = 0; i < N; i++) r[i] = mod(a[i]! + b[i]!);
  return r;
};

/** FIPS 203 function G = SHA3-512, returning its 64-byte output. */
export function G(input: Uint8Array): Uint8Array {
  return sha3_512(input);
}
/** FIPS 203 function H = SHA3-256. */
export function H(input: Uint8Array): Uint8Array {
  return sha3_256(input);
}
/** FIPS 203 function J = SHAKE256 with a 32-byte output. */
export function J(input: Uint8Array): Uint8Array {
  return shake256(input, { dkLen: 32 });
}

/** (K, r) = G(m ‖ h): the shared secret and the encryption randomness Encaps/Decaps derive. */
export function deriveKr(m: Uint8Array, h: Uint8Array): { sharedSecret: Uint8Array; randomness: Uint8Array } {
  const g = G(Uint8Array.from([...m, ...h]));
  return { sharedSecret: g.subarray(0, 32), randomness: g.subarray(32, 64) };
}

/** PRF_eta(seed, nonce) = SHAKE256(seed ‖ nonce, 64·eta bytes). */
function prf(len: number, seed: Uint8Array, nonce: number): Uint8Array {
  return shake256.create({ dkLen: len }).update(seed).update(new Uint8Array([nonce])).digest();
}
const cbd = (seed: Uint8Array, nonce: number, eta: number): Uint16Array => SamplePolyCBD(prf(64 * eta, seed, nonce), eta);
const matrixEntry = (rho: Uint8Array, i: number, j: number): Uint16Array => {
  const b = new Uint8Array(34);
  b.set(rho);
  b[32] = i;
  b[33] = j;
  return SampleNTT(b);
};

/**
 * K-PKE.Encrypt(ek, m, r) — FIPS 203 Algorithm 14, with the randomness `r`
 * supplied by the caller rather than derived. Returns the 1088-byte ciphertext.
 */
export function kPkeEncryptWithRandomness(ek: Uint8Array, msg: Uint8Array, r: Uint8Array): Uint8Array {
  const tHat: Uint16Array[] = [];
  for (let i = 0; i < K; i++) tHat.push(ByteDecode_d(ek.subarray(384 * i, 384 * (i + 1)), 12));
  const rho = ek.subarray(384 * K, 384 * K + 32);

  const rHat: Uint16Array[] = [];
  for (let i = 0; i < K; i++) rHat.push(NTT(cbd(r, i, ETA1)));

  const u: Uint16Array[] = [];
  for (let i = 0; i < K; i++) {
    let acc = new Uint16Array(N);
    for (let j = 0; j < K; j++) acc = polyAdd(acc, MultiplyNTTs(matrixEntry(rho, i, j), rHat[j]!));
    u.push(polyAdd(NTT_inv(acc), cbd(r, K + i, ETA2)));
  }

  let t2 = new Uint16Array(N);
  for (let i = 0; i < K; i++) t2 = polyAdd(t2, MultiplyNTTs(tHat[i]!, rHat[i]!));
  const mPoly = Uint16Array.from(ByteDecode_d(msg, 1), (y) => Decompress_d(y, 1));
  const v = polyAdd(polyAdd(NTT_inv(t2), cbd(r, 2 * K, ETA2)), mPoly);

  const out = new Uint8Array(32 * du * K + 32 * dv);
  let off = 0;
  for (let i = 0; i < K; i++) {
    const b = ByteEncode_d(Uint16Array.from(u[i]!, (z) => Compress_d(z, du)), du);
    out.set(b, off);
    off += b.length;
  }
  out.set(ByteEncode_d(Uint16Array.from(v, (z) => Compress_d(z, dv)), dv), off);
  return out;
}
