// Tiny DOM helpers. No framework — the point of the lab is transparency, and a
// handful of typed helpers keeps the panel code readable without one.

import type { SecretKind, Verdict } from '../kem/types.ts';
import { toHex } from '../kem/util.ts';

type Attrs = Record<string, string | number | boolean | ((e: Event) => void)>;
type Child = Node | string;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'function') node.addEventListener(k.replace(/^on/, '').toLowerCase(), v as EventListener);
    else if (k === 'class') node.className = String(v);
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'html') node.innerHTML = String(v);
    else if (v === true) node.setAttribute(k, '');
    else if (v !== false) node.setAttribute(k, String(v));
  }
  for (const c of children) node.append(c);
  return node;
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** A titled panel <section> with a heading and optional lead paragraph. */
export function panel(id: string, title: string, lead?: string): HTMLElement {
  const section = el('section', { class: 'panel', id, 'aria-labelledby': `${id}-h` }, [
    el('h2', { id: `${id}-h`, class: 'panel-title', text: title }),
  ]);
  if (lead) section.append(el('p', { class: 'panel-lead', text: lead }));
  return section;
}

/**
 * A scrollable byte view. Meets the a11y rule for overflow regions: focusable,
 * role="region" (labelled), so keyboard users can reach and read it. Bytes that
 * differ from `diffAgainst` are marked with text + icon + color (never color
 * alone). `limit` truncates very long buffers with an explicit "…(+N more)".
 */
export function byteView(
  label: string,
  bytes: Uint8Array,
  opts: { diffAgainst?: Uint8Array; limit?: number } = {},
): HTMLElement {
  const limit = opts.limit ?? bytes.length;
  const region = el('div', {
    class: 'bytes',
    role: 'region',
    'aria-label': label,
    tabindex: '0',
  });
  const shown = Math.min(limit, bytes.length);
  for (let i = 0; i < shown; i++) {
    const b = bytes[i];
    const differs = opts.diffAgainst ? opts.diffAgainst[i] !== b : false;
    const cell = el('span', {
      class: differs ? 'byte byte-diff' : 'byte',
      title: `byte ${i} = 0x${b.toString(16).padStart(2, '0')}${differs ? ' (changed)' : ''}`,
    }, [b.toString(16).padStart(2, '0')]);
    if (differs) cell.append(el('span', { class: 'vh', text: ' changed' }));
    region.append(cell);
  }
  if (bytes.length > shown) {
    region.append(el('span', { class: 'byte byte-more', text: `…(+${bytes.length - shown} more)` }));
  }
  return el('div', { class: 'byte-block' }, [
    el('span', { class: 'byte-label', text: label }),
    region,
  ]);
}

export function hexLine(bytes: Uint8Array): string {
  return toHex(bytes);
}

const VERDICT_META: Record<Verdict, { icon: string; text: string; cls: string }> = {
  accept: { icon: '✓', text: 'ACCEPT', cls: 'v-accept' },
  reject: { icon: '⊘', text: 'REJECT', cls: 'v-reject' },
  alarm: { icon: '✗', text: 'ALARM', cls: 'v-alarm' },
};

/**
 * The SECURITY VERDICT indicator. Color tracks system integrity, never the raw
 * return value: ALARM (accepted something it should not have) is red even though
 * the crypto call "succeeded". Always icon + text + color.
 */
export function verdictBadge(verdict: Verdict, detail?: string): HTMLElement {
  const m = VERDICT_META[verdict];
  return el('div', { class: `indicator ${m.cls}`, role: 'status', 'aria-live': 'polite' }, [
    el('span', { class: 'indicator-kicker', text: 'Security verdict' }),
    el('span', { class: 'indicator-body' }, [
      el('span', { class: 'indicator-icon', 'aria-hidden': 'true', text: m.icon }),
      el('span', { class: 'indicator-text', text: m.text }),
    ]),
    detail ? el('span', { class: 'indicator-detail', text: detail }) : document.createComment(''),
  ]);
}

/**
 * The CRYPTOGRAPHIC RESULT indicator — deliberately separate from the verdict.
 * It reports what Decaps literally did, in neutral styling, so the reader can see
 * "Signature/Decaps: succeeded" sitting next to a red "Verdict: ALARM".
 */
export function cryptoResultBadge(opts: {
  returnCode: number;
  bytesReturned: number;
  secretKind: SecretKind;
}): HTMLElement {
  const succeeded = opts.returnCode === 0;
  const kindText =
    opts.secretKind === 'agreed' ? 'agreed secret' : 'implicit-rejection secret (K̄)';
  return el('div', { class: 'indicator v-neutral', role: 'status', 'aria-live': 'polite' }, [
    el('span', { class: 'indicator-kicker', text: 'Cryptographic result' }),
    el('span', { class: 'indicator-body' }, [
      el('span', { class: 'indicator-icon', 'aria-hidden': 'true', text: succeeded ? '↩' : '⚠' }),
      el('span', {
        class: 'indicator-text',
        text: succeeded ? `Decaps rc=0 · ${opts.bytesReturned} bytes` : `Decaps rc=${opts.returnCode} · buffer untouched`,
      }),
    ]),
    el('span', { class: 'indicator-detail', text: succeeded ? `Returned the ${kindText}. Decaps cannot tell you which.` : 'Input rejected before any secret was written.' }),
  ]);
}

/** A small "what this isn't" scope note. */
export function scopeNote(text: string): HTMLElement {
  return el('p', { class: 'scope-note' }, [
    el('span', { class: 'scope-note-tag', text: 'What this isn’t' }),
    document.createTextNode(' ' + text),
  ]);
}

export function button(label: string, onClick: (e: Event) => void, extraClass = ''): HTMLButtonElement {
  return el('button', { type: 'button', class: `btn ${extraClass}`.trim(), onClick }, [label]);
}
