import { describe, expect, it } from 'vitest';
import {
  brokenReceiver,
  provenanceCheck,
  safeOracleProfile,
  safeReceiver,
  senderHello,
  verboseOracleProfile,
  type FfiBuffer,
} from '../kem/callers.ts';
import { keygen, PARAMS } from '../kem/mlkem.ts';
import { bytesEqual, toHex } from '../kem/util.ts';

function residentBuffer(fill = 0xde): FfiBuffer {
  return { bytes: new Uint8Array(32).fill(fill), wasWritten: false };
}

describe('SAFE caller — implicit rejection respected, confirmation enforced', () => {
  it('accepts a valid handshake (crypto result and verdict both positive)', () => {
    const bob = keygen();
    const hello = senderHello(bob.publicKey);
    const r = safeReceiver(hello, hello.ciphertext, bob.secretKey, hello.sharedSecret);
    expect(r.verdict).toBe('accept');
    expect(r.sessionEstablished).toBe(true);
    expect(r.cryptoResult.secretKind).toBe('agreed');
  });

  it('rejects a tampered ciphertext at the confirmation MAC — crypto returned 32 bytes, verdict REJECT', () => {
    const bob = keygen();
    const hello = senderHello(bob.publicKey);
    const tampered = hello.ciphertext.slice();
    tampered[7] ^= 0x01;
    const r = safeReceiver(hello, tampered, bob.secretKey, hello.sharedSecret);
    expect(r.cryptoResult.returnCode).toBe(0); // Decaps "succeeded"
    expect(r.cryptoResult.bytesReturned).toBe(32);
    expect(r.cryptoResult.secretKind).toBe('implicit-reject');
    expect(r.verdict).toBe('reject'); // system correctly refuses — NOT an alarm
    expect(r.sessionEstablished).toBe(false);
  });

  it('gives a uniform external response for malformed and well-formed-wrong inputs (no oracle)', () => {
    const bob = keygen();
    const hello = senderHello(bob.publicKey);
    const flipped = hello.ciphertext.slice();
    flipped[3] ^= 0x10;
    const short = new Uint8Array(PARAMS.ciphertext - 1);
    const rFlipped = safeReceiver(hello, flipped, bob.secretKey, hello.sharedSecret);
    const rShort = safeReceiver(hello, short, bob.secretKey, hello.sharedSecret);
    expect(rFlipped.externalResponse).toEqual(rShort.externalResponse);
    expect(rFlipped.verdict).toBe('reject');
    expect(rShort.verdict).toBe('reject');
  });
});

describe('BROKEN caller — the fail-open FFI trap', () => {
  it('keys the session on RESIDENT bytes when Decaps rejects the input (rc ignored)', () => {
    const bob = keygen();
    const hello = senderHello(bob.publicKey);
    const resident = residentBuffer(0xab);
    const before = resident.bytes.slice();
    // Malformed (wrong length): oqsDecaps returns rc != 0 and never writes the buffer.
    const short = new Uint8Array(PARAMS.ciphertext - 8);
    const r = brokenReceiver(resident, short, bob.secretKey, hello.sharedSecret);
    expect(r.cryptoResult.returnCode).toBe(-1); // honestly reported…
    expect(r.sessionEstablished).toBe(true); // …but session proceeds anyway
    expect(r.verdict).toBe('alarm'); // forged/garbage acceptance = ALARM, never green
    expect(resident.wasWritten).toBe(false);
    expect(bytesEqual(r.sessionKeyedOn, before)).toBe(true); // stale resident bytes
  });

  it('accepts the implicit-rejection secret on a bit-flip (no confirmation step)', () => {
    const bob = keygen();
    const hello = senderHello(bob.publicKey);
    const buf = residentBuffer();
    const tampered = hello.ciphertext.slice();
    tampered[42] ^= 0x04;
    const r = brokenReceiver(buf, tampered, bob.secretKey, hello.sharedSecret);
    expect(r.cryptoResult.returnCode).toBe(0); // rc success — Decaps implicit-rejected
    expect(r.cryptoResult.secretKind).toBe('implicit-reject');
    expect(r.verdict).toBe('alarm'); // keyed on K̄ the peer does not share
    expect(r.sessionEstablished).toBe(true);
  });

  it('is correct only by luck on a valid ciphertext (still no confirmation performed)', () => {
    const bob = keygen();
    const hello = senderHello(bob.publicKey);
    const buf = residentBuffer();
    const r = brokenReceiver(buf, hello.ciphertext, bob.secretKey, hello.sharedSecret);
    expect(r.verdict).toBe('accept');
    expect(r.cryptoResult.secretKind).toBe('agreed');
    expect(r.note).toMatch(/no confirmation/i);
  });

  it('models a previous call\'s secret still resident in the buffer', () => {
    const alice = keygen();
    const prev = senderHello(alice.publicKey);
    const prevSecret = prev.sharedSecret;
    // Buffer still holds the previous session's shared secret.
    const buf: FfiBuffer = { bytes: prevSecret.slice(), wasWritten: false };
    const bob = keygen();
    const short = new Uint8Array(PARAMS.ciphertext - 1);
    const r = brokenReceiver(buf, short, bob.secretKey, prev.sharedSecret);
    expect(bytesEqual(r.sessionKeyedOn, prevSecret)).toBe(true);
    expect(r.verdict).not.toBe('reject'); // it never rejects — that is the flaw
  });
});

describe('oracle surface', () => {
  it('SAFE caller is indistinguishable for valid vs invalid; verbose caller is an oracle', () => {
    const safe = safeOracleProfile();
    const verbose = verboseOracleProfile();
    expect(safe.distinguishable).toBe(false);
    expect(safe.validText).toBe(safe.invalidText);
    expect(verbose.distinguishable).toBe(true);
    expect(verbose.validText).not.toBe(verbose.invalidText);
  });
});

describe('provenance — "32 bytes arrived" is not "secret with the intended party"', () => {
  it('the unintended recipient also gets 32 well-formed bytes, but they are NOT agreed', () => {
    const bob = keygen();
    const carol = keygen();
    const p = provenanceCheck(bob, carol);
    expect(p.bobBytes).toBe(32);
    expect(p.carolBytes).toBe(32); // Carol receives 32 bytes too
    expect(p.bobIsAgreed).toBe(true);
    expect(p.carolIsAgreed).toBe(false); // …but shares nothing with the sender
    expect(toHex(p.bobSecret)).not.toBe(toHex(p.carolSecret));
  });

  it('the confirmation MAC binds provenance: verifies for Bob, fails for Carol', () => {
    const bob = keygen();
    const carol = keygen();
    const p = provenanceCheck(bob, carol);
    expect(p.bobConfirms).toBe(true); // the fix works for the intended party…
    expect(p.carolConfirms).toBe(false); // …and only the intended party
  });
});
