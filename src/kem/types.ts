// Shared types for the KEM Trap lab.
//
// The lab's whole thesis lives in the separation of two ideas that callers
// routinely collapse into one:
//   - the CRYPTOGRAPHIC RESULT  — what Decaps literally returned (always 32 bytes)
//   - the SECURITY VERDICT      — whether the system should trust those bytes
// These are modelled as distinct fields everywhere and never merged.

export interface MlKemKeyPair {
  publicKey: Uint8Array; // ek — 1184 bytes for ML-KEM-768
  secretKey: Uint8Array; // dk — 2400 bytes (dkPKE || ek || H(ek) || z)
}

export interface EncapsResult {
  ciphertext: Uint8Array; // c — 1088 bytes
  sharedSecret: Uint8Array; // K — 32 bytes (the sender's copy)
  message: Uint8Array; // m — 32-byte pre-secret the sender drew (kept for teaching)
}

// The intermediate values inside a single Decapsulation, surfaced so the UI can
// SHOW the Fujisaki–Okamoto branch rather than assert it. Reconstructed
// transparently in fo-transform.ts and KAT-checked against the reference.
export interface DecapsTrace {
  ciphertext: Uint8Array; // c — the ciphertext handed to Decaps
  mPrime: Uint8Array; // m' — K-PKE.Decrypt(dkPKE, c)
  reencrypted: Uint8Array; // c' — K-PKE.Encrypt(ek, m', G(m'||h))
  kHat: Uint8Array; // K̂ — the "real" secret, valid only if c' == c
  kBar: Uint8Array; // K̄ = J(z || c) — the implicit-rejection secret
  ciphertextsMatch: boolean; // c == c' ?
  implicitReject: boolean; // did the branch return K̄ instead of K̂?
  sharedSecret: Uint8Array; // the 32 bytes Decaps actually returns
}

// Whether a shared secret is the one both parties intended, or a per-key
// pseudorandom value from implicit rejection. Decaps CANNOT report this — it is
// derived here only for the teaching UI, by comparing against the sender.
export type SecretKind = 'agreed' | 'implicit-reject';

// The security verdict is deliberately three-valued. Note ALARM is NOT the same
// as REJECT: REJECT is the system correctly refusing bad input; ALARM is the
// system having ACCEPTED something it should not have — a forged-but-accepted
// outcome. Color tracks this, never the raw crypto return value.
export type Verdict = 'accept' | 'reject' | 'alarm';
