import { describe, expect, it } from 'vitest';
import { compareCiphertexts } from '../ui/comparison-model.ts';

describe('illustrative incomplete FO comparison', () => {
  const original = Uint8Array.from([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);

  it('accepts an ignored-tail mutation only when comparison is incomplete', () => {
    const changed = Uint8Array.from(original);
    changed[7] ^= 1;
    expect(compareCiphertexts(original, changed, 7)).toEqual({ fullMatch: false, partialMatch: true });
    expect(compareCiphertexts(original, changed, 8)).toEqual({ fullMatch: false, partialMatch: false });
  });

  it('rejects a mutation in the checked prefix under both comparisons', () => {
    const changed = Uint8Array.from(original);
    changed[0] ^= 1;
    expect(compareCiphertexts(original, changed, 7)).toEqual({ fullMatch: false, partialMatch: false });
  });

  it('rejects mismatched lengths and invalid comparison bounds', () => {
    expect(() => compareCiphertexts(original, original.subarray(0, 7), 7)).toThrow(RangeError);
    expect(() => compareCiphertexts(original, original, 9)).toThrow(RangeError);
  });
});
