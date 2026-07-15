// Deterministic known-answer vectors for ML-KEM-768.
//
// FIPS 203 KeyGen and Encaps are randomized, but expose deterministic hooks
// (Algorithms 16/17): a 64-byte KeyGen seed and a 32-byte Encaps message fix all
// randomness. Feeding fixed seeds/messages to the reference implementation
// (@noble/post-quantum, which passes the NIST ACVP ML-KEM test suite) yields
// fixed outputs. These are pinned below and checked in mlkem.test.ts.
//
// Large artifacts (ek/dk/ct) are pinned by SHA-256 digest for a compact,
// readable file; the 32-byte shared secret is pinned in full. A regression in
// the KEM pipeline — ours or an upstream change — breaks these vectors.

export interface KemTrapVector {
  n: number;
  seed: Uint8Array; // 64-byte KeyGen seed
  message: Uint8Array; // 32-byte Encaps message (pre-secret)
  ekSha256: string;
  dkSha256: string;
  ctSha256: string;
  sharedSecret: string; // full 32-byte hex — Encaps output == Decaps output
}

function seed(n: number): Uint8Array {
  const s = new Uint8Array(64);
  s[0] = n;
  s[63] = 0xa5;
  return s;
}

function message(n: number): Uint8Array {
  const m = new Uint8Array(32);
  m[0] = n;
  m[31] = 0x5a;
  return m;
}

export const VECTORS: KemTrapVector[] = [
  {
    n: 0,
    seed: seed(0),
    message: message(0),
    ekSha256: 'f95c185fe5b2335d2fc938dd889c6425944acd74376b6952bf1130f720f6ba99',
    dkSha256: '37564d6a716abb401ffaba375a4997490e9e45ef2d6390166cf1d99ad9e08ca4',
    ctSha256: 'e8194220a05e591f885a18d365d8342f98c1ea740b04962c586f86ba4e105154',
    sharedSecret: 'bba04dca20825beda420dfa5058ff6a53e035cc2ec255b516512f7188aae3df4',
  },
  {
    n: 1,
    seed: seed(1),
    message: message(1),
    ekSha256: 'ba89b39b372c8ede9c2d360d5ed6d6c1309a47f592c90170d7462771be37a7ad',
    dkSha256: '2655a694f5dc8b5a8fe05b1a8e755a409c2777b970224a1893610b5bf9114e42',
    ctSha256: '7a1a7c25ff2155cf482e59884625979f2d3237811b5be42c2077ce9bdff2dbad',
    sharedSecret: 'ae71d55cf6e6c6daae7f6cc757578332e8f89f86750f2a880b48d23774cf8455',
  },
  {
    n: 2,
    seed: seed(2),
    message: message(2),
    ekSha256: 'e77b0d96fef8baf407d118b0d875204079fd660756ceb1d848031caae2e02b2d',
    dkSha256: 'a3f49352a0bf23e7e80efe565e01ed9b5e0bc60ce20c7e4b7f423793b7d43b21',
    ctSha256: 'a7ffc6efb1ea00e88f59b0b34557d2247bffa6b1a6007fba261578bbb2bad402',
    sharedSecret: 'c2d3bfafaa2007d3b600854430f719a67b4e986d8ea3a50c825a3d41aa27f4ba',
  },
];
