import { describe, expect, it } from 'vitest';
import { byteDiffCount, bytesEqual, toHex } from '../kem/util.ts';

// The byte helpers are small, but the rest of the suite reads its assertions
// through them — `toHex(a)).toBe(toHex(b))` is how most KATs here compare
// buffers, and `bytesEqual` decides whether a handshake is judged agreed. A
// helper that quietly says "equal" for two different buffers would turn real
// failures green, so they get their own direct tests rather than being trusted
// implicitly by the callers that use them.

describe('toHex — lowercase, zero-padded, one byte to two digits', () => {
  it('pads bytes below 0x10 to two digits instead of emitting one', () => {
    // The padStart is the whole point: without it 0x0a would render as "a"
    // and a 32-byte secret could print as fewer than 64 characters.
    expect(toHex(new Uint8Array([0x00, 0x01, 0x0f, 0x10]))).toBe('00010f10');
  });

  it('renders the full byte range in lowercase and preserves order', () => {
    expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef');
    expect(toHex(new Uint8Array([0xff, 0x00]))).toBe('ff00');
  });

  it('emits exactly two characters per byte', () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    expect(toHex(bytes)).toHaveLength(64);
  });

  it('maps the empty buffer to the empty string', () => {
    expect(toHex(new Uint8Array(0))).toBe('');
  });
});

// `bytesEqual` accumulates the XOR of every byte instead of returning early on
// the first mismatch. These assert the *result* only — a timing assertion in a
// JIT'd browser runtime measures the engine, not the code.
describe('bytesEqual — content comparison without an early content exit', () => {
  it('is true for distinct buffers holding the same bytes', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(a).not.toBe(b);
    expect(bytesEqual(a, b)).toBe(true);
  });

  it('is false when equal-length buffers differ, wherever the difference sits', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    expect(bytesEqual(a, new Uint8Array([9, 2, 3, 4]))).toBe(false); // first byte
    expect(bytesEqual(a, new Uint8Array([1, 2, 3, 9]))).toBe(false); // last byte
  });

  it('is false for a one-bit difference, not just a whole-byte one', () => {
    const a = crypto.getRandomValues(new Uint8Array(32));
    const b = a.slice();
    b[17] ^= 0x01;
    expect(bytesEqual(a, b)).toBe(false);
  });

  it('is false on a length mismatch, including when one is a prefix of the other', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    expect(bytesEqual(a, a.subarray(0, 3))).toBe(false); // b is a prefix of a
    expect(bytesEqual(a.subarray(0, 3), a)).toBe(false); // and the reverse
    expect(bytesEqual(a, new Uint8Array(0))).toBe(false);
  });

  it('is true for two empty buffers', () => {
    expect(bytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

// The UI reports "N of 1088 bytes differ" from this. It must count *bytes*,
// not bits and not positions-scanned, or the lab teaches the wrong lesson
// about how far a tampered ciphertext is from the original.
describe('byteDiffCount — how many bytes differ, for the UI diff readout', () => {
  it('is 0 for identical buffers', () => {
    const a = crypto.getRandomValues(new Uint8Array(64));
    expect(byteDiffCount(a, a.slice())).toBe(0);
  });

  it('counts differing positions in equal-length buffers', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 9, 3, 9, 5]);
    expect(byteDiffCount(a, b)).toBe(2);
  });

  it('counts a whole byte once however many bits inside it flipped', () => {
    const a = new Uint8Array(16); // all zero
    const b = a.slice();
    b[3] = 0xff; // eight flipped bits, one differing byte
    expect(byteDiffCount(a, b)).toBe(1);
  });

  it('counts every byte when nothing matches', () => {
    const a = new Uint8Array(32).fill(0x00);
    const b = new Uint8Array(32).fill(0xff);
    expect(byteDiffCount(a, b)).toBe(32);
  });

  it('is symmetric in its arguments', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 7, 7, 4]);
    expect(byteDiffCount(a, b)).toBe(byteDiffCount(b, a));
  });

  it('adds the length delta to the differences found in the shared prefix', () => {
    // 4 missing bytes, plus 1 mismatch inside the 3 bytes they share.
    const a = new Uint8Array([1, 2, 3, 4, 5, 6, 7]);
    const b = new Uint8Array([1, 9, 3]);
    expect(byteDiffCount(a, b)).toBe(5);
    expect(byteDiffCount(b, a)).toBe(5);
  });

  it('reports a pure truncation as exactly the number of bytes dropped', () => {
    const a = crypto.getRandomValues(new Uint8Array(32));
    expect(byteDiffCount(a, a.subarray(0, 30))).toBe(2);
  });

  it('is 0 for two empty buffers, and the full length when only one is empty', () => {
    expect(byteDiffCount(new Uint8Array(0), new Uint8Array(0))).toBe(0);
    expect(byteDiffCount(new Uint8Array(5), new Uint8Array(0))).toBe(5);
  });
});
