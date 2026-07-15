# crypto-lab-kem-trap

**KEM Trap** — a browser demo of ML-KEM-768 decapsulation failure semantics: how a correctly-implemented, ACVP-validated KEM still gets destroyed by the code that calls it.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-kem-trap/

## What It Is

A KEM (key-encapsulation mechanism) lets two parties agree on a shared secret: one side encapsulates a fresh secret under the other's public key, the other decapsulates it. **ML-KEM-768** is the post-quantum KEM standardized in **FIPS 203** (Category 3, `1184`-byte public key / `2400`-byte secret key / `1088`-byte ciphertext / `32`-byte secret).

The subject of this lab is the one thing FIPS 203 §7.3 makes non-negotiable: **Decapsulation never fails loudly.** It runs a Fujisaki–Okamoto (FO) transform — decrypt, re-encrypt, compare — and on a mismatch it does **not** raise an error. It returns `J(z‖c)`, a per-key pseudorandom secret derived from the implicit-rejection key `z`. Either way, the caller receives exactly 32 clean bytes. That is a deliberate security property (it closes a class of chosen-ciphertext attacks), and it means **every remaining security decision belongs to the caller.** If the caller treats "I received 32 bytes" as "I share the intended secret with the intended party," the KEM's guarantees are already gone.

**Security model:** the ML-KEM operations are real (`@noble/post-quantum`, which passes the NIST ACVP ML-KEM test suite) and run entirely in your browser. The two "callers" — SAFE and BROKEN — are deliberately minimal models built to expose one failure each. **Not production crypto — a teaching demo.** No backend; all key material is per-session in memory and never persisted.

### What's real vs. simulated

- **Real:** ML-KEM-768 KeyGen / Encaps / Decaps; the FO transform's implicit-rejection branch, reconstructed transparently from the reference's own tested math surfaces (`K-PKE.Decrypt` hand-rolled, re-encryption via the real `encapsulate`, `J(z‖c)` via real SHAKE256) and **KAT-checked byte-for-byte against the reference `decapsulate`**; the confirmation MAC (HMAC-SHA256) and session KDF (HKDF-SHA256).
- **Simulated (a labelled model):** the FFI boundary — a caller-allocated output buffer, a liboqs-style return code, and a "resident bytes" buffer. This is a faithful model of a real C fail-open shape, not an emulated Rust/WASM FFI.

### What it does **NOT** prove

- It does **not** run a key-recovery attack. It exposes the oracle *surface*; it does not exploit it.
- It does **not** demonstrate the lattice math (LWE/NTT) inside `K-PKE.Decrypt` — that's [kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/).
- It does **not** cover Kyber's plaintext-checking oracle attack or KyberSlash timing recovery — those are named and linked, not executed ([kyberslash](https://systemslibrarian.github.io/crypto-lab-kyberslash/)).
- It is **not** a general memory-zeroization lab. The one memory lesson is the fail-open output buffer.

## Exhibits

1. **The Fujisaki–Okamoto branch** — step through a real Decapsulation: receive `c` → decrypt to `m'` → re-encrypt to `c'` → compare → branch to `K̂` (agreed) or `K̄ = J(z‖c)` (implicit rejection). Every intermediate is shown, not asserted; both candidate secrets are displayed and the returned one is highlighted.
2. **Same ciphertext, two callers** — SAFE vs. BROKEN side by side. The **cryptographic result** ("Decaps returned 32 bytes") and the **security verdict** (ACCEPT / REJECT / ALARM) are rendered as *separate* indicators and never merged. A forged-but-accepted outcome renders as ALARM, not green.
3. **The fail-open output buffer** — the scoped centerpiece, modeled on a real FFI shape: `rc` captured but never branched on, `derive_session_key(ss)` run regardless. Watch the 32-byte buffer hold stack garbage or a previous call's secret, then watch the session key on it when Decaps rejects a malformed ciphertext and leaves the buffer untouched.
4. **The oracle a chatty caller hands out** — the SAFE caller answers every failure identically; a verbose broken caller answers differently for valid vs. invalid ciphertexts. That one-bit-per-query difference is a plaintext-checking oracle. Flip a bit and watch the verbose answer flip.
5. **Provenance** — one ciphertext to Bob; Bob gets the agreed secret, Carol (the wrong recipient) also gets 32 well-formed bytes. "32 bytes arrived" is not "a secret with the intended party."

**Break-it-yourself:** the tamper controls (flip a bit, corrupt the length, regenerate keys) drive every panel against the real primitive and the real verifier. The learner *causes* the failure; nothing here is a canned animation.

## When to Use It

- Teaching why KEM misuse-resistance lives in the calling protocol, not the primitive.
- Reviewing FFI boundaries (liboqs, `OQS_KEM_decaps`) where a return code is dropped or a KEM secret is consumed without a confirmation step.
- **Do NOT** use it as a KEM implementation, a security proof, or evidence about any specific product. It is a minimal teaching model.

## Live Demo

At the [live demo](https://systemslibrarian.github.io/crypto-lab-kem-trap/) you can flip a single ciphertext bit and watch the FO check fail while Decaps stays silent; corrupt the ciphertext length and watch the BROKEN caller key a session on resident buffer bytes; toggle a stale buffer between stack garbage and a previous call's secret; and see the oracle surface flip in real time. Works on mobile (panels stack < 640px) and in both light and dark themes.

## What Can Go Wrong

- **Dropped return code:** `rc` is checked into a variable but never branched on; a malformed ciphertext leaves the output buffer untouched and the session proceeds on whatever was resident.
- **No confirmation step:** the caller equates "Decaps returned 32 bytes" with "we share the intended key." A bit-flipped ciphertext yields the implicit-rejection secret `K̄`; without an authenticated confirmation MAC, the caller cannot notice the peer holds a different value.
- **A distinguishable failure response:** a caller that reveals *why* decapsulation failed (error string, length, or timing) becomes a plaintext-checking / decapsulation oracle. **Precise consequence:** such an oracle enables published chosen-ciphertext attacks that recover the ML-KEM **decapsulation (private) key** — a *confidentiality* key. A KEM authenticates nobody, so there is no separate "authentication key" at risk here.
- **Provenance confusion:** treating shared-secret bytes as proof of *who* you're talking to. The bytes carry no identity; binding the secret to the transcript (a confirmation MAC or a key-committing step) is what ties it to a party.

## Real-World Usage

ML-KEM is being deployed now in hybrid TLS 1.3 key exchange, SSH, and messaging. NIST **SP 800-227** (secure use of KEMs) exists precisely because the primitive's guarantees are conditional on correct caller behavior: confirm the shared secret through an authenticated step, handle Decaps uniformly, and never build a distinguishable failure path. The FFI shape modeled here mirrors real integrations against liboqs's `OQS_KEM_decaps`.

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-kem-trap/
npm run build      # production build to dist/
npm run preview    # serve the production build
```

## Related Demos

- [kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — the lattice math (LWE, NTT) inside ML-KEM.
- [kyberslash](https://systemslibrarian.github.io/crypto-lab-kyberslash/) — the KyberSlash timing side channel and plaintext-checking oracle attacks this lab only names.
- [commit-gate](https://systemslibrarian.github.io/crypto-lab-commit-gate/) — commitment binding, the key-commitment idea behind provenance.

## Build & Verify

- **24 unit tests** (Vitest) across three files, run in CI before deploy:
  - `src/__tests__/mlkem.test.ts` — round-trips, FIPS 203 lengths, implicit-rejection (never throws on a wrong-but-well-formed ciphertext), and **3 deterministic known-answer vectors** pinned to the ACVP-validated reference (`src/kem/vectors.ts`).
  - `src/__tests__/fo-transform.test.ts` — the transparent FO reconstruction checked **byte-for-byte against the reference `decapsulate`** across valid and tampered ciphertexts, plus `m'` recovery and `J(z‖c)` = SHAKE256(z‖c) verification.
  - `src/__tests__/callers.test.ts` — SAFE uniform rejection + confirmation, BROKEN fail-open on stale buffers, the oracle distinguisher, and provenance.
- **Accessibility gate:** `@axe-core/playwright` scans the production build for zero WCAG 2.1 A/AA violations in **both** themes (`e2e/a11y.spec.ts`). The GitHub Pages deploy is blocked on any regression.

```bash
npm test                       # 24 unit tests + KATs
npm run build && npm run test:a11y   # a11y gate, both themes
```

## Performance

All operations are a single ML-KEM-768 KeyGen/Encaps/Decaps (sub-millisecond each) plus small hashes; every panel re-renders synchronously on interaction with no perceptible delay.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
