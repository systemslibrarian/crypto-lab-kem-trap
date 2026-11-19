// Keys that bind nothing — ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK.
//
// Sophie Schmieg, "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor
// MAL-BIND-K-PK" (3 April 2024). A binding KEM would guarantee that a shared
// secret determines the ciphertext (K-CT) and the public key (K-PK) that
// produced it. ML-KEM guarantees neither against a MALICIOUSLY constructed
// decapsulation key, and the two attacks below exhibit each failure on the real
// ML-KEM-768.
//
// Companion: Tehrani, Buchanan and Lemoudden, "On the Secrecy of the
// Encapsulation Coin in ML-KEM" — K = G(m ‖ H(ek)) is fixed before the
// ciphertext exists, so the coin m alone recovers the key.
//
// Everything here runs the real @noble/post-quantum ML-KEM-768. The malformed
// keys are built by editing the documented byte fields of a real decapsulation
// key; the attack ciphertexts are real K-PKE encryptions (kpke-encrypt.ts, KAT
// against the reference).
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { keygen, PARAMS } from './mlkem.ts';
import { decapsulateTraced } from './fo-transform.ts';
import { H, J, deriveKr, kPkeEncryptWithRandomness } from './kpke-encrypt.ts';
import { bytesEqual } from './util.ts';

// FIPS 203 decapsulation-key layout: dk = dkPKE ‖ ek ‖ H(ek) ‖ z.
const EK_OFFSET = PARAMS.dkPkeBytes; // 1152
const H_OFFSET = PARAMS.dkPkeBytes + PARAMS.publicKey; // 1152 + 1184 = 2336
const Z_OFFSET = H_OFFSET + 32; // 2368

/** The ek embedded in a decapsulation key. */
export function ekField(dk: Uint8Array): Uint8Array {
  return dk.subarray(EK_OFFSET, EK_OFFSET + PARAMS.publicKey);
}
/** The stored hash field h = H(ek) of a well-formed key. */
export function hField(dk: Uint8Array): Uint8Array {
  return dk.subarray(H_OFFSET, H_OFFSET + 32);
}
/** The implicit-rejection seed z. */
export function zField(dk: Uint8Array): Uint8Array {
  return dk.subarray(Z_OFFSET, Z_OFFSET + 32);
}

/** A copy of dk with its stored hash field replaced by `h`. */
export function tamperHash(dk: Uint8Array, h: Uint8Array): Uint8Array {
  const out = dk.slice();
  out.set(h.subarray(0, 32), H_OFFSET);
  return out;
}
/** A copy of dk with its implicit-rejection seed replaced by `z`. */
export function tamperZ(dk: Uint8Array, z: Uint8Array): Uint8Array {
  const out = dk.slice();
  out.set(z.subarray(0, 32), Z_OFFSET);
  return out;
}

/**
 * FIPS 203 §7.3 "Decapsulation input check", item 3 (Hash check), eq. (7.2):
 * recompute H(ek) from the key's own ek field and compare with the stored h.
 * Returns true when the key is internally consistent.
 */
export function fipsHashCheck(dk: Uint8Array): boolean {
  return bytesEqual(H(ekField(dk)), hField(dk));
}

export interface MalBindKCt {
  ek0: Uint8Array;
  ek1: Uint8Array;
  /** Party 0's honest ciphertext under ek0. */
  c0: Uint8Array;
  /** The crafted ciphertext party 1 decapsulates under its tampered key. */
  c1: Uint8Array;
  K0: Uint8Array;
  K1: Uint8Array;
  /** The two shared secrets are equal … */
  sameSecret: boolean;
  /** … from different ciphertexts … */
  differentCiphertext: boolean;
  /** … and different public keys. */
  differentPublicKey: boolean;
  /** FIPS 203 §7.3 hash check on the tampered key: it rejects it. */
  hashCheckRejects: boolean;
  /**
   * @noble's `decapsulate` ENFORCES the §7.3 check, so it throws on the tampered
   * key — the attack only lands on a decaps that skips the check, which is why
   * the lab's transparent FO (decapsulateTraced) is what runs it here.
   */
  libraryEnforcesCheck: boolean;
}

/**
 * Algorithm 2 (MAL-BIND-K-CT). Party 1's decapsulation key carries h0 = H(ek0)
 * in place of its own H(ek1). Party 0 encapsulates m0 to its own ek0, getting
 * K0 = G(m0 ‖ h0). Party 1 decapsulates a DIFFERENT ciphertext c1 = Encrypt(ek1,
 * m0, G(m0 ‖ h0)) under its tampered key, and because decaps uses the STORED h0
 * it derives the same K0. Same secret, different ciphertext, different key.
 *
 * The decaps here is the lab's transparent FO (`decapsulateTraced`), which
 * follows Algorithm 18 WITHOUT the §7.3 input check — exactly the implementation
 * the attack needs. @noble's own `decapsulate` adds the check and rejects the
 * key, which is the mitigation this act then demonstrates.
 */
export function malBindKCt(): MalBindKCt {
  const p0 = keygen();
  const p1 = keygen();
  const h0 = H(p0.publicKey);
  const dk1 = tamperHash(p1.secretKey, h0);

  const m0 = crypto.getRandomValues(new Uint8Array(32));
  // Party 0, honest encapsulation to its own key: K0 = G(m0 ‖ H(ek0)) = G(m0 ‖ h0).
  const enc0 = ml_kem768.encapsulate(p0.publicKey, m0);
  const c0 = enc0.cipherText;
  const K0 = enc0.sharedSecret;

  // The crafted ciphertext: Encrypt(ek1, m0, r) with r = G(m0 ‖ h0)'s randomness half.
  const { randomness } = deriveKr(m0, h0);
  const c1 = kPkeEncryptWithRandomness(p1.publicKey, m0, randomness);

  // Decapsulate under the tampered key with a decaps that skips the §7.3 check.
  const K1 = decapsulateTraced(c1, dk1).sharedSecret;

  // Confirm @noble's checked decaps refuses the tampered key.
  let libraryEnforcesCheck = false;
  try {
    ml_kem768.decapsulate(c1, dk1);
  } catch {
    libraryEnforcesCheck = true;
  }

  return {
    ek0: p0.publicKey,
    ek1: p1.publicKey,
    c0,
    c1,
    K0,
    K1,
    sameSecret: bytesEqual(K0, K1),
    differentCiphertext: !bytesEqual(c0, c1),
    differentPublicKey: !bytesEqual(p0.publicKey, p1.publicKey),
    hashCheckRejects: !fipsHashCheck(dk1),
    libraryEnforcesCheck,
  };
}

export interface MalBindKPk {
  ek0: Uint8Array;
  ek1: Uint8Array;
  /** The one random ciphertext both parties decapsulate. */
  c: Uint8Array;
  z: Uint8Array;
  K0: Uint8Array;
  K1: Uint8Array;
  sameSecret: boolean;
  differentPublicKey: boolean;
  /** Both tampered keys still pass the FIPS 203 hash check — it does not stop this. */
  hashCheckPassesBoth: boolean;
  /** The shared secret is the implicit-rejection value J(z ‖ c). */
  isImplicitReject: boolean;
}

/**
 * Algorithm 3 (MAL-BIND-K-PK). Two decapsulation keys are given the SAME
 * implicit-rejection seed z but are otherwise honest (each h still equals its
 * own H(ek), so the FIPS 203 hash check passes on both). A single random
 * ciphertext c fails re-encryption under both, so both decapsulate to the
 * implicit-rejection secret J(z ‖ c) — the same key, under different public
 * keys, and the hash check cannot see it because z never involves the public
 * key. What stops it: binding the public key into the shared secret at the
 * protocol level.
 */
export function malBindKPk(): MalBindKPk {
  const p0 = keygen();
  const p1 = keygen();
  const z = crypto.getRandomValues(new Uint8Array(32));
  const dk0 = tamperZ(p0.secretKey, z);
  const dk1 = tamperZ(p1.secretKey, z);

  // A random ciphertext: with overwhelming probability it fails re-encryption
  // under both keys, so both take the implicit-rejection branch.
  const c = crypto.getRandomValues(new Uint8Array(PARAMS.ciphertext));
  const K0 = ml_kem768.decapsulate(c, dk0);
  const K1 = ml_kem768.decapsulate(c, dk1);
  const kBar = J(Uint8Array.from([...z, ...c]));

  return {
    ek0: p0.publicKey,
    ek1: p1.publicKey,
    c,
    z,
    K0,
    K1,
    sameSecret: bytesEqual(K0, K1),
    differentPublicKey: !bytesEqual(p0.publicKey, p1.publicKey),
    hashCheckPassesBoth: fipsHashCheck(dk0) && fipsHashCheck(dk1),
    isImplicitReject: bytesEqual(K0, kBar),
  };
}

export interface CoinToKey {
  m: Uint8Array;
  ek: Uint8Array;
  /** K = G(m ‖ H(ek))[:32], computed from the coin and the public key — no ciphertext. */
  keyFromCoin: Uint8Array;
  /** The shared secret the real encapsulation produces for the same (ek, m). */
  keyFromEncaps: Uint8Array;
  /** They are equal: whoever learns m has the key. */
  matches: boolean;
}

/**
 * The encapsulation coin IS the key. K = G(m ‖ H(ek)) is fixed before the
 * ciphertext exists (Tehrani, Buchanan and Lemoudden), so anyone who learns the
 * 32-byte coin m recovers the shared secret from the public key alone. The same
 * shape — a parameter-controlled, externally invisible predictability — is the
 * Dual_EC_DRBG lesson the corrupted-oracle lab draws out.
 */
export function coinToKey(ek: Uint8Array, m?: Uint8Array): CoinToKey {
  const coin = m ?? crypto.getRandomValues(new Uint8Array(32));
  const keyFromCoin = deriveKr(coin, H(ek)).sharedSecret;
  const keyFromEncaps = ml_kem768.encapsulate(ek, coin).sharedSecret;
  return { m: coin, ek, keyFromCoin, keyFromEncaps, matches: bytesEqual(keyFromCoin, keyFromEncaps) };
}
