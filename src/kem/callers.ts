// The callers — where every security property of a KEM actually lives.
//
// ML-KEM-768 Decaps is correct and IND-CCA2 secure. It still returns 32 bytes
// for a tampered ciphertext (the implicit-rejection secret K̄), by design. So the
// only thing standing between "I received 32 bytes" and "I share the intended
// secret with the intended party" is the code that CALLS Decaps. This module
// models two such callers against the real primitive:
//
//   SAFE   — treats Decaps uniformly, then runs an authenticated confirmation
//            step (an HMAC over the transcript, keyed from the shared secret).
//            A wrong secret produces a wrong tag; the protocol rejects, and it
//            rejects the SAME way for every bad ciphertext (no oracle).
//   BROKEN — models a real FFI fail-open: it reads Decaps's return code into a
//            variable and never branches on it, then derives a session key from
//            the output buffer regardless. On a malformed ciphertext the buffer
//            is never written and the session proceeds on whatever was resident.
//
// All crypto here is real: ML-KEM via @noble/post-quantum, HMAC-SHA256 and HKDF
// via @noble/hashes.

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { decapsulate, encapsulate, PARAMS } from './mlkem.ts';
import type { EncapsResult, MlKemKeyPair, SecretKind, Verdict } from './types.ts';

const enc = new TextEncoder();
const CONFIRM_LABEL = enc.encode('kem-trap/confirm-v1');
const SESSION_LABEL = enc.encode('kem-trap/session-v1');

/** Session key = HKDF-SHA256(sharedSecret, info=transcript). Real KDF. */
export function deriveSessionKey(sharedSecret: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, undefined, concat(SESSION_LABEL, ciphertext), 32);
}

/** Confirmation tag Alice sends: HMAC-SHA256(sessionKey, label‖c). Real MAC. */
export function confirmationTag(sessionKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return hmac(sha256, sessionKey, concat(CONFIRM_LABEL, ciphertext));
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** The sender's half of a handshake: encapsulate, derive, and MAC the transcript. */
export interface SenderHello {
  ciphertext: Uint8Array;
  sessionKey: Uint8Array;
  confirmTag: Uint8Array;
  sharedSecret: Uint8Array;
}

export function senderHello(recipientPublicKey: Uint8Array, message?: Uint8Array): SenderHello {
  const e: EncapsResult = encapsulate(recipientPublicKey, message);
  const sessionKey = deriveSessionKey(e.sharedSecret, e.ciphertext);
  return {
    ciphertext: e.ciphertext,
    sessionKey,
    confirmTag: confirmationTag(sessionKey, e.ciphertext),
    sharedSecret: e.sharedSecret,
  };
}

// ── The receiver's outcome, with the two indicators kept strictly separate ──
//
// `cryptoResult` describes what Decaps literally did (it returned 32 bytes; on a
// bad ciphertext it implicitly rejected). `verdict` describes what the SYSTEM
// concluded. They can disagree — a BROKEN caller can report a green crypto
// result while the verdict is ALARM.
export interface ReceiverOutcome {
  caller: 'safe' | 'broken';
  cryptoResult: {
    returnCode: number; // liboqs-style rc: 0 = success, nonzero = input rejected
    bytesReturned: number; // Decaps always yields 32 on success, else buffer size
    secretKind: SecretKind; // agreed vs implicit-reject (a TEACHING label; Decaps can't tell)
  };
  verdict: Verdict;
  sessionEstablished: boolean;
  // What an external observer learns from this caller's response (the oracle surface).
  externalResponse: { text: string; length: number };
  // The bytes the session actually keyed on (may be stale/garbage for BROKEN).
  sessionKeyedOn: Uint8Array;
  note: string;
}

// A liboqs-style Decaps at the FFI boundary. Returns rc and writes into a
// caller-provided buffer. Models the two real behaviors:
//   - length-correct ciphertext  → rc 0, buffer fully written with Decaps output
//     (this is TRUE even for a bit-flipped ciphertext: implicit rejection is not
//     an error, so rc stays 0 and the buffer holds the pseudorandom K̄).
//   - wrong-length ciphertext     → rc nonzero, buffer left UNTOUCHED.
export interface FfiBuffer {
  bytes: Uint8Array; // 32-byte output buffer, pre-populated with resident data
  wasWritten: boolean;
}

export function oqsDecaps(
  buffer: FfiBuffer,
  ciphertext: Uint8Array,
  secretKey: MlKemKeyPair['secretKey'],
): number {
  if (ciphertext.length !== PARAMS.ciphertext) {
    // liboqs validates the ciphertext length and returns OQS_ERROR (-1) without
    // touching the output buffer. This is the trap the BROKEN caller ignores.
    return -1;
  }
  buffer.bytes.set(decapsulate(ciphertext, secretKey));
  buffer.wasWritten = true;
  return 0;
}

/**
 * SAFE caller. Uniform handling of Decaps, then an authenticated confirmation.
 * The KEM's implicit rejection is respected: a wrong secret yields a wrong MAC,
 * caught at the confirmation step, and every failure looks identical from
 * outside (no distinguishing string, length, or code).
 */
export function safeReceiver(
  hello: Pick<SenderHello, 'confirmTag'>,
  ciphertext: Uint8Array,
  secretKey: MlKemKeyPair['secretKey'],
  senderSecret: Uint8Array,
): ReceiverOutcome {
  const UNIFORM = { text: 'handshake failed', length: 'handshake failed'.length };

  if (ciphertext.length !== PARAMS.ciphertext) {
    // Length guard, then the same uniform rejection as any other failure.
    return {
      caller: 'safe',
      cryptoResult: { returnCode: -1, bytesReturned: 0, secretKind: 'implicit-reject' },
      verdict: 'reject',
      sessionEstablished: false,
      externalResponse: UNIFORM,
      sessionKeyedOn: new Uint8Array(0),
      note: 'Malformed ciphertext rejected before use; response identical to every other failure.',
    };
  }

  const ss = decapsulate(ciphertext, secretKey);
  const sessionKey = deriveSessionKey(ss, ciphertext);
  const recomputed = confirmationTag(sessionKey, ciphertext);
  const macOk = ctEqual(recomputed, hello.confirmTag);
  const secretKind: SecretKind = ctEqual(ss, senderSecret) ? 'agreed' : 'implicit-reject';

  return {
    caller: 'safe',
    cryptoResult: { returnCode: 0, bytesReturned: 32, secretKind },
    verdict: macOk ? 'accept' : 'reject',
    sessionEstablished: macOk,
    externalResponse: macOk
      ? { text: 'session established', length: 'session established'.length }
      : UNIFORM,
    sessionKeyedOn: ss,
    note: macOk
      ? 'Shared secret confirmed by the authenticated transcript MAC.'
      : 'Wrong secret caught by the confirmation MAC — rejected uniformly, no oracle leaked.',
  };
}

/**
 * BROKEN caller — the scoped centerpiece. Models this FFI code verbatim:
 *
 *   uint8_t ss[32];                       // caller-allocated, uninitialized
 *   int rc = OQS_KEM_decaps(kem, ss, ct, sk);
 *   // rc checked into a variable, never branched on
 *   derive_session_key(ss);               // consumed regardless
 *
 * It performs NO confirmation step, so it cannot notice a wrong secret, and it
 * ignores rc, so on a malformed ciphertext it keys the session on whatever bytes
 * were resident in `ss`.
 */
export function brokenReceiver(
  buffer: FfiBuffer,
  ciphertext: Uint8Array,
  secretKey: MlKemKeyPair['secretKey'],
  senderSecret: Uint8Array,
): ReceiverOutcome {
  const rc = oqsDecaps(buffer, ciphertext, secretKey); // rc captured…
  // …and never branched on. The session proceeds on buffer.bytes no matter what.
  const ss = buffer.bytes;
  const sessionKeyedOn = ss.slice();
  const secretKind: SecretKind = ctEqual(ss, senderSecret) ? 'agreed' : 'implicit-reject';

  // The crypto RESULT is honestly reported (rc, byte count). The VERDICT is a
  // separate judgement about system integrity: any session that proceeds on a
  // secret the peer does not share is an ALARM, even though "Decaps returned 32
  // bytes" is literally true.
  const agreed = secretKind === 'agreed' && buffer.wasWritten;
  const verdict: Verdict = agreed ? 'accept' : 'alarm';

  return {
    caller: 'broken',
    cryptoResult: { returnCode: rc, bytesReturned: 32, secretKind },
    verdict,
    sessionEstablished: true, // it ALWAYS proceeds — that is the bug
    externalResponse: { text: 'session established', length: 'session established'.length },
    sessionKeyedOn,
    note: agreed
      ? 'Correct only by luck of a valid ciphertext — no confirmation was ever performed.'
      : buffer.wasWritten
        ? 'Keyed on the implicit-rejection secret K̄; peer holds a different key. Session is a ghost.'
        : `rc=${rc} ignored: buffer never written, session keyed on resident bytes.`,
  };
}

// ── Oracle surface ──────────────────────────────────────────────────────────
//
// An attacker submits chosen ciphertexts and reads only the caller's external
// response. If that response distinguishes "re-encryption matched" from "did
// not", it is a plaintext-checking / decapsulation oracle. This models the
// SURFACE only — it does NOT run any key-recovery attack (that is a non-goal;
// see kyberslash). The precise consequence of such an oracle against ML-KEM is
// recovery of the decapsulation (private) key — a confidentiality key. ML-KEM
// provides no peer authentication, so there is no "authentication key" to lose.

export interface OracleResponse {
  distinguishable: boolean;
  validText: string;
  invalidText: string;
}

/** SAFE caller's oracle profile: identical response for valid and invalid. */
export function safeOracleProfile(): OracleResponse {
  return { distinguishable: false, validText: 'handshake failed', invalidText: 'handshake failed' };
}

/** BROKEN-verbose caller's oracle profile: leaks the FO comparison result. */
export function verboseOracleProfile(): OracleResponse {
  return {
    distinguishable: true,
    validText: 'session established',
    invalidText: 'decapsulation failed: re-encryption mismatch',
  };
}

// ── Provenance ──────────────────────────────────────────────────────────────
//
// A KEM shared secret proves nothing about WHO you share it with. Encapsulate to
// Bob; Bob's Decaps yields the agreed secret, but Carol's Decaps of the SAME
// ciphertext also yields 32 well-formed bytes (implicit rejection). A caller that
// equates "32 bytes arrived" with "secret established with the intended party"
// is fooled about provenance. Authenticating the transcript (a confirmation MAC
// or a key-committing step — see commit-gate) is what binds secret to identity.

export interface ProvenanceResult {
  bobSecret: Uint8Array; // agreed with the sender
  carolSecret: Uint8Array; // 32 bytes, but NOT agreed with anyone
  bobIsAgreed: boolean;
  carolIsAgreed: boolean;
  bobBytes: number;
  carolBytes: number;
}

export function provenanceCheck(
  bob: MlKemKeyPair,
  carol: MlKemKeyPair,
  message?: Uint8Array,
): ProvenanceResult {
  const hello = senderHello(bob.publicKey, message);
  const bobSecret = decapsulate(hello.ciphertext, bob.secretKey);
  const carolSecret = decapsulate(hello.ciphertext, carol.secretKey);
  return {
    bobSecret,
    carolSecret,
    bobIsAgreed: ctEqual(bobSecret, hello.sharedSecret),
    carolIsAgreed: ctEqual(carolSecret, hello.sharedSecret),
    bobBytes: bobSecret.length,
    carolBytes: carolSecret.length,
  };
}
