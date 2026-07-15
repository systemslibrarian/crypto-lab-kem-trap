import './style.css';
import { buildLab } from './ui/lab.ts';
import { el } from './ui/dom.ts';

const app = document.getElementById('app');
if (!app) throw new Error('missing #app mount point');

// The standardized hero: short-name <h1> + spec subtitle + one-sentence
// description on the left; the "Why it matters" box to the side.
const hero = el('header', { class: 'cl-hero' }, [
  el('div', { class: 'cl-hero-main' }, [
    el('h1', { class: 'cl-hero-title', text: 'KEM Trap' }),
    el('p', { class: 'cl-hero-sub', text: 'Decapsulation failure semantics · FIPS 203 · NIST SP 800-227' }),
    el('p', {
      class: 'cl-hero-desc',
      text: 'Runs real ML-KEM-768 decapsulation on ciphertexts you tamper with, then shows a correctly-implemented KEM destroyed by the code that calls it.',
    }),
  ]),
  el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
    el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
    el('p', {
      class: 'cl-hero-why-text',
      text: 'Post-quantum KEMs are shipping into TLS, SSH, and messaging now. Decaps returns 32 bytes for any ciphertext by design, so a single mishandled return value turns an unbreakable primitive into a silently broken system.',
    }),
  ]),
]);

// Plain-language on-ramp — no math, before any hex or control (the §2 intro card).
const intro = el('section', { class: 'intro', 'aria-label': 'What this is' }, [
  el('h2', { class: 'intro-title', text: 'What is this?' }),
  el('p', {
    class: 'intro-text',
    text:
      'A KEM (key-encapsulation mechanism) is how two parties agree on a shared secret key. One side scrambles a fresh secret under the other’s public key; the other side unscrambles it. ML-KEM-768 is the post-quantum KEM NIST standardized in FIPS 203.',
  }),
  el('p', {
    class: 'intro-text',
    text:
      'Here is the trap. The unscramble step — Decapsulation — never says “this ciphertext is bad.” By design it returns 32 random-looking bytes for ANY ciphertext, even a corrupted one. That is a security feature (it stops a whole class of attacks). But it means the KEM has quietly handed every remaining security decision to the program that called it. If that program assumes “I got 32 bytes” means “we share the right key,” the guarantees are already gone.',
  }),
  el('p', {
    class: 'intro-text intro-text-dim',
    text:
      'Not production crypto — a teaching demo. The ML-KEM operations are real (@noble/post-quantum, FIPS 203, ACVP-validated) and run in your browser; the “callers” are deliberately minimal models built to expose one failure each.',
  }),
]);

app.append(hero, intro);
buildLab(app);
