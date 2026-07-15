// The interactive lab. Every panel runs against the real ML-KEM-768 primitive
// and the real verifier; the learner's actions (flipping a bit, corrupting the
// length, choosing what sits in a stale buffer) cause the genuine crypto to
// produce a genuinely wrong outcome. Nothing here is a canned animation.

import {
  brokenReceiver,
  provenanceCheck,
  safeReceiver,
  senderHello,
  verboseOracleProfile,
  type FfiBuffer,
  type SenderHello,
} from '../kem/callers.ts';
import { decapsulateTraced } from '../kem/fo-transform.ts';
import { keygen, PARAMS } from '../kem/mlkem.ts';
import type { MlKemKeyPair } from '../kem/types.ts';
import { byteDiffCount } from '../kem/util.ts';
import {
  button,
  byteView,
  clear,
  cryptoResultBadge,
  el,
  panel,
  scopeNote,
  verdictBadge,
} from './dom.ts';

type Mutation =
  | { kind: 'none' }
  | { kind: 'bitflip'; index: number; bit: number }
  | { kind: 'truncate'; drop: number };

interface LabState {
  bob: MlKemKeyPair;
  carol: MlKemKeyPair;
  message: Uint8Array;
  hello: SenderHello;
  mutation: Mutation;
  residentKind: 'garbage' | 'previous';
  previousSecret: Uint8Array;
}

const subscribers: Array<() => void> = [];
function notify(): void {
  for (const fn of subscribers) fn();
}

function freshState(): LabState {
  const bob = keygen();
  const carol = keygen();
  const message = crypto.getRandomValues(new Uint8Array(PARAMS.message));
  const prev = senderHello(keygen().publicKey); // a "previous" session's secret
  return {
    bob,
    carol,
    message,
    hello: senderHello(bob.publicKey, message),
    mutation: { kind: 'none' },
    residentKind: 'garbage',
    previousSecret: prev.sharedSecret,
  };
}

let state = freshState();

function currentCiphertext(): Uint8Array {
  const base = state.hello.ciphertext;
  switch (state.mutation.kind) {
    case 'none':
      return base;
    case 'bitflip': {
      const c = base.slice();
      c[state.mutation.index] ^= 1 << state.mutation.bit;
      return c;
    }
    case 'truncate':
      return base.slice(0, base.length - state.mutation.drop);
  }
}

function isWellFormed(c: Uint8Array): boolean {
  return c.length === PARAMS.ciphertext;
}

function mutationLabel(): string {
  switch (state.mutation.kind) {
    case 'none':
      return 'valid ciphertext (untouched)';
    case 'bitflip':
      return `1 bit flipped at byte ${state.mutation.index}`;
    case 'truncate':
      return `length corrupted (${state.mutation.drop} bytes dropped → ${PARAMS.ciphertext - state.mutation.drop} of ${PARAMS.ciphertext})`;
  }
}

// ── Shared mutation controls: the break-it-yourself surface ──────────────────
function mutationControls(): HTMLElement {
  const status = el('p', {
    class: 'mutation-status',
    role: 'status',
    'aria-live': 'polite',
  });
  const paint = () => {
    status.textContent = `Current ciphertext: ${mutationLabel()}.`;
  };
  subscribers.push(paint);
  paint();

  const flip = button('Flip a random bit', () => {
    state.mutation = {
      kind: 'bitflip',
      index: Math.floor(Math.random() * PARAMS.ciphertext),
      bit: Math.floor(Math.random() * 8),
    };
    notify();
  }, 'btn-accent');
  const corrupt = button('Corrupt the length', () => {
    state.mutation = { kind: 'truncate', drop: 1 };
    notify();
  });
  const reset = button('Reset to a valid ciphertext', () => {
    state.mutation = { kind: 'none' };
    notify();
  });
  const regen = button('Generate fresh keys', () => {
    state = freshState();
    notify();
  });

  return el('div', { class: 'controls', role: 'group', 'aria-label': 'Tamper with the ciphertext' }, [
    el('div', { class: 'control-row' }, [flip, corrupt, reset, regen]),
    status,
  ]);
}

// ── Panel 1: headline mechanism — the FO branch, shown step by step ──────────
function foPanel(): HTMLElement {
  const p = panel(
    'fo',
    '1 · The Fujisaki–Okamoto branch (the headline mechanism)',
    'Decapsulation does not check a MAC and return “fail”. It decrypts your ciphertext, re-encrypts what it got, and compares. If they differ it does not error — it returns J(z‖c), a per-key pseudorandom secret. Watch the branch decide.',
  );

  const stepWrap = el('div', { class: 'fo-steps' });
  const stepControls = el('div', { class: 'control-row' });
  const body = el('div');
  p.append(stepControls, body, stepWrap);

  let highlight = 0;
  const render = () => {
    clear(body);
    clear(stepWrap);
    const c = currentCiphertext();

    if (!isWellFormed(c)) {
      body.append(
        el('div', { class: 'callout callout-reject' }, [
          el('span', { class: 'callout-icon', 'aria-hidden': 'true', text: '⊘' }),
          el('p', {
            text: `This ciphertext is ${c.length} bytes, not ${PARAMS.ciphertext}. Decaps rejects it at the length check (rc≠0) before the FO branch ever runs. The interesting failure now lives at the caller — see Panel 3.`,
          }),
        ]),
      );
      return;
    }

    const trace = decapsulateTraced(c, state.bob.secretKey);
    const cDiff = byteDiffCount(c, state.hello.ciphertext);
    const steps: Array<{ t: string; body: HTMLElement }> = [
      {
        t: `Receive c${cDiff ? ` — ${cDiff} byte(s) differ from the original` : ''}`,
        body: byteView('ciphertext c (first 32 of 1088 bytes)', c, {
          diffAgainst: state.hello.ciphertext,
          limit: 32,
        }),
      },
      {
        t: 'Decrypt: m′ = K-PKE.Decrypt(dkPKE, c)',
        body: byteView('recovered message m′ (32 bytes)', trace.mPrime, {
          diffAgainst: state.message,
        }),
      },
      {
        t: `Re-encrypt: c′ = K-PKE.Encrypt(ek, m′, G(m′‖H(ek)))`,
        body: byteView('re-encryption c′ (first 32 bytes)', trace.reencrypted, {
          diffAgainst: c,
          limit: 32,
        }),
      },
      {
        t: trace.ciphertextsMatch ? 'Compare: c′ == c  ✓' : 'Compare: c′ ≠ c  ✗',
        body: el('p', {
          class: trace.ciphertextsMatch ? 'compare compare-eq' : 'compare compare-ne',
          text: trace.ciphertextsMatch
            ? 'The re-encryption reproduces the ciphertext exactly. The FO check passes.'
            : `The re-encryption does not match (${byteDiffCount(c, trace.reencrypted)} of ${PARAMS.ciphertext} bytes differ). The FO check fails — but Decaps still will not error.`,
        }),
      },
      {
        t: trace.implicitReject ? 'Branch: return K̄ = J(z‖c) (implicit rejection)' : 'Branch: return K̂ (the real secret)',
        body: el('div', { class: 'branch' }, [
          candidate('K̂  (real secret)', trace.kHat, !trace.implicitReject),
          candidate('K̄ = J(z‖c)  (implicit-rejection secret)', trace.kBar, trace.implicitReject),
        ]),
      },
      {
        t: 'Return: exactly 32 bytes — either way',
        body: el('div', {}, [
          byteView('shared secret Decaps returns', trace.sharedSecret),
          el('p', {
            class: 'note',
            text: trace.implicitReject
              ? 'No exception. No error code from the branch. The caller receives 32 clean bytes that look exactly like a real secret — but the peer holds a different value.'
              : 'A genuine agreed secret. Indistinguishable, at this interface, from the rejection case above.',
          }),
        ]),
      },
    ];

    const list = el('ol', { class: 'step-list' });
    steps.forEach((s, i) => {
      const li = el('li', {
        class: `step ${i === highlight ? 'is-active' : ''} ${i < highlight ? 'is-done' : ''}`,
      }, [el('h3', { class: 'step-title', text: s.t }), s.body]);
      list.append(li);
    });
    stepWrap.append(list);
  };

  const rebuildControls = () => {
    clear(stepControls);
    stepControls.append(
      button('Step through the branch', () => {
        highlight = (highlight + 1) % 7;
        render();
      }, 'btn-accent'),
      button('Show whole branch', () => {
        highlight = 6;
        render();
      }),
    );
  };
  rebuildControls();

  subscribers.push(() => {
    highlight = 0;
    render();
  });
  render();
  p.append(
    scopeNote(
      'the lattice math behind K-PKE.Decrypt (LWE, the NTT) — this lab shows the FO wrapper around it; the lattice internals are in the kyber-vault demo, linked below.',
    ),
  );
  return p;
}

function candidate(label: string, bytes: Uint8Array, chosen: boolean): HTMLElement {
  return el('div', { class: `candidate ${chosen ? 'is-chosen' : 'is-dropped'}` }, [
    el('span', { class: 'candidate-tag' }, [
      el('span', { class: 'candidate-mark', 'aria-hidden': 'true', text: chosen ? '▶' : '·' }),
      el('span', { text: chosen ? `${label} — RETURNED` : `${label} — discarded` }),
    ]),
    byteView(label, bytes, { limit: 16 }),
  ]);
}

// ── Panel 2: one ciphertext, two callers, side by side ───────────────────────
function callersPanel(): HTMLElement {
  const p = panel(
    'callers',
    '2 · Same ciphertext, two callers',
    'The KEM does its job identically for both. The only difference is the code around it. Notice the two indicators never merge: “Decaps returned 32 bytes” is a fact; the verdict is a separate judgement about whether the system should have trusted them.',
  );

  const grid = el('div', { class: 'caller-grid' });
  p.append(grid);

  const render = () => {
    clear(grid);
    grid.append(callerCard('safe'), callerCard('broken'));
  };

  const callerCard = (which: 'safe' | 'broken'): HTMLElement => {
    const c = currentCiphertext();
    const resident =
      state.residentKind === 'previous' ? state.previousSecret.slice() : new Uint8Array(32).fill(0xde);
    const buffer: FfiBuffer = { bytes: resident, wasWritten: false };
    const outcome =
      which === 'safe'
        ? safeReceiver(state.hello, c, state.bob.secretKey, state.hello.sharedSecret)
        : brokenReceiver(buffer, c, state.bob.secretKey, state.hello.sharedSecret);

    const title = which === 'safe' ? 'SAFE caller' : 'BROKEN caller (fail-open)';
    const sub =
      which === 'safe'
        ? 'uniform handling + authenticated confirmation MAC'
        : 'ignores rc, no confirmation — proceeds regardless';

    const card = el('div', { class: `caller-card caller-${which} verdict-${outcome.verdict}` }, [
      el('h3', { class: 'caller-name', text: title }),
      el('p', { class: 'caller-sub', text: sub }),
      cryptoResultBadge(outcome.cryptoResult),
      verdictBadge(outcome.verdict, outcome.sessionEstablished ? 'session established' : 'no session'),
      el('p', { class: 'caller-note', text: outcome.note }),
    ]);
    if (outcome.sessionKeyedOn.length) {
      card.append(byteView('session keyed on (first 16 bytes)', outcome.sessionKeyedOn, { limit: 16 }));
    }
    return card;
  };

  subscribers.push(render);
  render();
  return p;
}

// ── Panel 3: the fail-open output buffer — the scoped centerpiece ────────────
const FFI_CODE = `uint8_t ss[32];                       // caller-allocated, uninitialized
int rc = OQS_KEM_decaps(kem, ss, ct, sk);
// rc checked into a variable, never branched on
derive_session_key(ss);               // consumed regardless`;

function bufferPanel(): HTMLElement {
  const p = panel(
    'buffer',
    '3 · The fail-open output buffer',
    'The one memory lesson in this lab. A real FFI shape: a caller-allocated 32-byte buffer, a return code captured but never branched on, and a session key derived from the buffer no matter what. When Decaps rejects a malformed ciphertext it leaves the buffer untouched — so the session keys on whatever was resident.',
  );

  const codeEl = el('pre', {
    class: 'code',
    role: 'region',
    'aria-label': 'The fail-open C caller',
    tabindex: '0',
  }, [el('code', { text: FFI_CODE })]);

  const residentToggle = el('div', { class: 'control-row', role: 'group', 'aria-label': 'What is resident in the buffer' }, [
    el('span', { class: 'toggle-label', text: 'Buffer starts holding:' }),
    button('Uninitialized stack garbage', () => {
      state.residentKind = 'garbage';
      notify();
    }),
    button("A previous call's shared secret", () => {
      state.residentKind = 'previous';
      notify();
    }),
  ]);

  const out = el('div', { class: 'buffer-out' });
  p.append(codeEl, residentToggle, out);

  const render = () => {
    clear(out);
    const c = currentCiphertext();
    const resident =
      state.residentKind === 'previous' ? state.previousSecret.slice() : new Uint8Array(32).fill(0xde);
    const before = resident.slice();
    const buffer: FfiBuffer = { bytes: resident, wasWritten: false };
    const outcome = brokenReceiver(buffer, c, state.bob.secretKey, state.hello.sharedSecret);

    const wrote = buffer.wasWritten;
    out.append(
      el('ol', { class: 'buffer-steps' }, [
        step('①  Allocate ss[32]', byteView(`resident bytes (${state.residentKind === 'previous' ? "previous call's secret" : 'stack garbage'})`, before, { limit: 32 })),
        step(
          `②  rc = OQS_KEM_decaps(...) → rc = ${outcome.cryptoResult.returnCode}${wrote ? ' (buffer written)' : ' (buffer NOT written)'}`,
          byteView('ss after the call', buffer.bytes, { diffAgainst: before, limit: 32 }),
        ),
        step(
          '③  derive_session_key(ss) — runs regardless of rc',
          el('div', {}, [
            byteView('bytes the session actually keyed on', outcome.sessionKeyedOn, { limit: 32 }),
            el('div', { class: 'buffer-verdicts' }, [
              cryptoResultBadge(outcome.cryptoResult),
              verdictBadge(outcome.verdict, wrote ? undefined : 'keyed on resident bytes'),
            ]),
            el('p', { class: 'note', text: outcome.note }),
          ]),
        ),
      ]),
    );
  };

  subscribers.push(render);
  render();
  p.append(
    scopeNote(
      'a general memory-zeroization tour. The single lesson is this output buffer at the KEM boundary; secret-wiping elsewhere is out of scope.',
    ),
  );
  return p;
}

function step(title: string, body: HTMLElement): HTMLElement {
  return el('li', { class: 'buffer-step' }, [el('h3', { class: 'step-title', text: title }), body]);
}

// ── Panel 4: the oracle surface ──────────────────────────────────────────────
function oraclePanel(): HTMLElement {
  const p = panel(
    'oracle',
    '4 · The oracle a chatty caller hands out',
    'A caller must not reveal WHY a decapsulation failed. The SAFE caller answers every failure identically. A “verbose” broken caller answers differently for valid vs. invalid ciphertexts — that one-bit-per-query difference is a plaintext-checking oracle. Flip a bit above and watch the verbose answer flip.',
  );

  const out = el('div', { class: 'oracle-out' });
  p.append(out);

  const render = () => {
    clear(out);
    const c = currentCiphertext();
    const wellFormed = isWellFormed(c);
    const rejected = wellFormed ? decapsulateTraced(c, state.bob.secretKey).implicitReject : true;
    const verbose = verboseOracleProfile();

    const safeAnswer = 'handshake failed';
    const verboseAnswer = rejected ? verbose.invalidText : verbose.validText;

    out.append(
      el('div', { class: 'oracle-grid' }, [
        oracleCol('SAFE caller', 'handshake failed', 'handshake failed', false, safeAnswer),
        oracleCol('Verbose broken caller', verbose.validText, verbose.invalidText, true, verboseAnswer),
      ]),
      el('p', {
        class: 'oracle-live',
        role: 'status',
        'aria-live': 'polite',
        text: `Your current ciphertext is ${rejected ? 'INVALID' : 'valid'}. SAFE says “${safeAnswer}”. Verbose says “${verboseAnswer}”.`,
      }),
    );
  };

  subscribers.push(render);
  render();

  p.append(
    el('div', { class: 'callout callout-precise' }, [
      el('span', { class: 'callout-icon', 'aria-hidden': 'true', text: 'ℹ' }),
      el('p', {
        html:
          'Precise consequence: such an oracle enables published chosen-ciphertext attacks that recover the ML-KEM <strong>decapsulation (private) key</strong> — a confidentiality key. A KEM authenticates <em>nobody</em>, so there is no separate “authentication key” to lose here. This lab exposes the surface; it does <strong>not</strong> run the recovery — see the kyberslash demo below.',
      }),
    ]),
    scopeNote(
      'a working key-recovery or timing attack. The Kyber plaintext-checking oracle and KyberSlash timing recovery are named and linked, not executed here.',
    ),
  );
  return p;
}

function oracleCol(
  name: string,
  validText: string,
  invalidText: string,
  distinguishable: boolean,
  live: string,
): HTMLElement {
  return el('div', { class: `oracle-col ${distinguishable ? 'is-oracle' : 'is-uniform'}` }, [
    el('h3', { class: 'oracle-name', text: name }),
    el('table', { class: 'oracle-table' }, [
      el('tbody', {}, [
        el('tr', {}, [el('th', { scope: 'row', text: 'valid ct →' }), el('td', { text: `“${validText}”` })]),
        el('tr', {}, [el('th', { scope: 'row', text: 'invalid ct →' }), el('td', { text: `“${invalidText}”` })]),
      ]),
    ]),
    el('p', {
      class: distinguishable ? 'oracle-flag oracle-flag-bad' : 'oracle-flag oracle-flag-ok',
    }, [
      el('span', { class: 'oracle-flag-icon', 'aria-hidden': 'true', text: distinguishable ? '✗' : '✓' }),
      document.createTextNode(distinguishable ? ' Responses differ → 1-bit oracle' : ' Responses identical → no signal'),
    ]),
    el('p', { class: 'oracle-current', text: `Now: “${live}”` }),
  ]);
}

// ── Panel 5: provenance ──────────────────────────────────────────────────────
function provenancePanel(): HTMLElement {
  const p = panel(
    'provenance',
    '5 · “32 bytes arrived” is not “a secret with the intended party”',
    'One ciphertext, encapsulated to Bob. Bob decapsulates it and gets the agreed secret. Carol — the wrong recipient — decapsulates the SAME ciphertext and also gets 32 well-formed bytes. A caller that treats “I got 32 bytes” as “we share a secret” cannot tell these apart.',
  );

  const out = el('div', { class: 'prov-out' });
  p.append(out);

  const render = () => {
    clear(out);
    const r = provenanceCheck(state.bob, state.carol, state.message);
    out.append(
      el('div', { class: 'prov-grid' }, [
        provCard('Bob (intended recipient)', r.bobSecret, r.bobIsAgreed, r.bobBytes),
        provCard('Carol (wrong recipient)', r.carolSecret, r.carolIsAgreed, r.carolBytes),
      ]),
    );
  };

  subscribers.push(render);
  render();

  p.append(
    el('p', {
      class: 'note',
      html:
        'The bytes carry no proof of provenance. Binding the secret to the transcript (a confirmation MAC, or a key-committing step) is what ties it to an identity — see the commit-gate demo on key commitment, linked below.',
    }),
    scopeNote('a full authenticated key exchange. Provenance here is one lesson; building the handshake around it is a separate demo.'),
  );
  return p;
}

function provCard(name: string, secret: Uint8Array, agreed: boolean, bytes: number): HTMLElement {
  return el('div', { class: `prov-card ${agreed ? 'prov-agreed' : 'prov-ghost'}` }, [
    el('h3', { class: 'prov-name', text: name }),
    el('div', { class: 'prov-fact' }, [
      el('span', { class: 'prov-fact-label', text: 'Bytes received' }),
      el('span', { class: 'prov-fact-val', text: String(bytes) }),
    ]),
    el('div', { class: `indicator ${agreed ? 'v-accept' : 'v-alarm'}`, role: 'status' }, [
      el('span', { class: 'indicator-kicker', text: 'Provenance' }),
      el('span', { class: 'indicator-body' }, [
        el('span', { class: 'indicator-icon', 'aria-hidden': 'true', text: agreed ? '✓' : '✗' }),
        el('span', { class: 'indicator-text', text: agreed ? 'AGREED with sender' : 'NOT agreed — a ghost secret' }),
      ]),
    ]),
    byteView(`${name} secret (first 16 bytes)`, secret, { limit: 16 }),
  ]);
}

export function buildLab(root: HTMLElement): void {
  root.append(
    el('section', { class: 'controls-panel', 'aria-label': 'Tamper controls' }, [
      el('h2', { class: 'panel-title', text: 'Break it yourself' }),
      el('p', {
        class: 'panel-lead',
        text: 'These controls drive every panel below against the real ML-KEM-768 primitive and the real verifier. Flip a bit and watch honest crypto produce a dishonest outcome downstream.',
      }),
      mutationControls(),
    ]),
    foPanel(),
    callersPanel(),
    bufferPanel(),
    oraclePanel(),
    provenancePanel(),
  );
}
