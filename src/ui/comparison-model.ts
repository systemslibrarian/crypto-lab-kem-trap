/** A byte-level illustration of a truncated FO comparison, not ML-KEM decapsulation. */
export function compareCiphertexts(
  expected: Uint8Array,
  received: Uint8Array,
  checkedBytes: number,
): { fullMatch: boolean; partialMatch: boolean } {
  if (expected.length !== received.length || expected.length === 0) {
    throw new RangeError('comparison requires nonempty, equal-length ciphertexts');
  }
  if (!Number.isInteger(checkedBytes) || checkedBytes < 1 || checkedBytes > expected.length) {
    throw new RangeError('checkedBytes must be within the ciphertext');
  }
  let fullDifference = 0;
  let checkedDifference = 0;
  for (let i = 0; i < expected.length; i++) {
    const difference = expected[i] ^ received[i];
    fullDifference |= difference;
    if (i < checkedBytes) checkedDifference |= difference;
  }
  return { fullMatch: fullDifference === 0, partialMatch: checkedDifference === 0 };
}
