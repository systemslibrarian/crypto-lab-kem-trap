import { clear, el, panel } from './dom.ts';

type Focus = 'all' | 'confidentiality' | 'agreement' | 'identity';
interface EvidenceRow {
  id: string;
  scenario: string;
  focus: Exclude<Focus, 'all'>;
  property: string;
  access: string;
  evidence: string;
  limit: string;
  source: string;
  href: string;
  demo?: string;
}

const FIPS = 'https://doi.org/10.6028/NIST.FIPS.203';
const GUIDANCE = 'https://doi.org/10.6028/NIST.SP.800-227';

// A reading map, not security ratings. Keep source evidence separate from what
// this browser executes; no row asserts that a deployed endpoint is vulnerable.
const rows: EvidenceRow[] = [
  {
    id: 'standard', scenario: 'Correct ML-KEM algorithm', focus: 'confidentiality',
    property: 'Shared-secret confidentiality under chosen-ciphertext attack (IND-CCA).',
    access: 'The security game permits decapsulation queries except the challenge ciphertext; it does not grant arbitrary leakage from the implementation.',
    evidence: 'Standard and security model. This lab runs real ML-KEM-768 operations and known-answer checks.',
    limit: 'Round trips and test vectors do not prove IND-CCA security or certify a device. Kyber research versions and final ML-KEM must be distinguished.',
    source: 'FIPS 203 §3; SP 800-227 §2.3 and §5.1.3', href: GUIDANCE, demo: '#fo',
  },
  {
    id: 'caller', scenario: 'Caller accepts any 32-byte result', focus: 'agreement',
    property: 'Agreement on the intended session secret.',
    access: 'An attacker tampers with the ciphertext; a broken caller skips confirmation or ignores an input-error return code and uses resident buffer bytes.',
    evidence: 'Executed here: real decapsulation plus deliberately broken caller and FFI models.',
    limit: 'False session acceptance is not private-key recovery. The FFI wrapper is a teaching model, not a tested liboqs integration.',
    source: 'SP 800-227 §3.3 and §4.4', href: GUIDANCE, demo: '#callers',
  },
  {
    id: 'identity', scenario: 'A confirmation tag verifies', focus: 'identity',
    property: 'Key confirmation versus peer authentication.',
    access: 'A peer can produce a valid tag using the established secret. Naming that peer also needs a trusted identity-to-public-key binding and a suitable protocol.',
    evidence: 'Executed here: Bob/Carol confirmation comparison. Guidance supplies the separate identity requirement.',
    limit: 'A matching tag alone does not establish a real-world identity, mutual authentication, replay protection or forward secrecy.',
    source: 'SP 800-227 §4.2, §4.4 and §5.2.2', href: GUIDANCE, demo: '#provenance',
  },
  {
    id: 'oracle', scenario: 'A caller reveals rejection information', focus: 'confidentiality',
    property: 'Confidentiality threatened by an additional oracle.',
    access: 'Chosen ciphertexts and an observable, useful distinction correlated with secret processing; key reuse and query budget depend on the attack.',
    evidence: 'Executed here: response text/length distinctions. Timing is a branch model, not a measurement; no key-recovery attack runs here.',
    limit: 'A visible distinction is not a completed recovery. Show that the particular attack can use the signal before transferring a paper result to a protocol.',
    source: 'SP 800-227 §3.3', href: GUIDANCE, demo: '#oracle',
  },
  {
    id: 'comparison', scenario: 'An implementation skips part of the FO comparison', focus: 'confidentiality',
    property: 'The implementation no longer performs the full ciphertext check.',
    access: 'A faulty comparison, a reused key and the paper’s constructed plaintext-checking oracle. Ciphertexts and total decapsulation queries are different budgets.',
    evidence: 'Here: an eight-byte illustration only. The cited paper reports partial binary recovery; its full recovery is in an idealized reference model. See the detailed research note above.',
    limit: 'The binary results are not full hardware key recovery. No deployed HPKE/KEMTLS oracle bridge or break of correct ML-KEM is demonstrated here.',
    source: 'Das, ePrint 2026/1682, Table 1 and §§5–6.2', href: 'https://eprint.iacr.org/2026/1682', demo: '#incomplete-comparison',
  },
  {
    id: 'timing', scenario: 'KyberSlash timing leakage', focus: 'confidentiality',
    property: 'Private-key confidentiality in affected Kyber implementations.',
    access: 'Chosen-ciphertext decapsulation with exploitable secret-dependent division timings on an affected implementation and platform.',
    evidence: 'Published implementation/hardware experiments: Raspberry Pi 2 and Arm Cortex-M4. This page does not reproduce them; the linked lab is a simulation.',
    limit: 'A browser simulation is not a physical measurement or proof that this ML-KEM library, every CPU or a deployed remote service is vulnerable.',
    source: 'KyberSlash, ePrint 2024/1049', href: 'https://eprint.iacr.org/2024/1049', demo: 'https://systemslibrarian.github.io/crypto-lab-kyberslash/',
  },
];

export function securityMatrix(): HTMLElement {
  const section = panel('security-properties', '6 · Kyber / ML-KEM security-property matrix',
    'Start with the property, then ask what the attacker can observe and what was actually demonstrated. These rows are evidence categories, not security scores.');
  const summary = el('p', { class: 'note', role: 'status', 'aria-live': 'polite' });
  const body = el('tbody');
  const select = el('select', { id: 'security-focus' }, [
    ...[['all', 'All properties'], ['confidentiality', 'Confidentiality'], ['agreement', 'Key agreement'], ['identity', 'Peer authentication']].map(([value, text]) => el('option', { value, text })),
  ]);
  const render = () => {
    clear(body);
    const shown = rows.filter(row => select.value === 'all' || row.focus === select.value);
    for (const row of shown) {
      const links = [el('a', { href: row.href, text: row.source })];
      if (row.demo) links.push(el('a', { href: row.demo, text: 'Explore this example' }));
      body.append(el('tr', { 'data-evidence-row': row.id }, [
        el('th', { scope: 'row', text: row.scenario }),
        el('td', { text: row.property }),
        el('td', { text: row.access }),
        el('td', {}, [el('p', { text: row.evidence }), el('div', { class: 'matrix-links' }, links)]),
        el('td', { text: row.limit }),
      ]));
    }
    summary.textContent = `Showing ${shown.length} of ${rows.length} scenarios. Filtering changes this reading map, not the attack controls or their results.`;
  };
  select.addEventListener('change', render);
  section.append(
    el('label', { for: 'security-focus', class: 'matrix-label', text: 'Focus on a security property' }), select, summary,
    el('div', { class: 'matrix-scroll', role: 'region', tabindex: '0', 'aria-label': 'Security-property matrix; scroll horizontally to read all columns' }, [
      el('table', { class: 'security-matrix' }, [
        el('caption', { text: 'Property × attacker access × evidence × limit' }),
        el('thead', {}, [el('tr', {}, ['Scenario', 'Property at issue', 'Required access or premise', 'Evidence and source', 'What does not follow'].map(text => el('th', { scope: 'col', text })))]),
        body,
      ]),
    ]),
    el('p', { class: 'note', text: 'Evidence does not automatically transfer between an algorithm, a simulated fault, an affected binary and a deployed protocol. The full-comparison and oracle lessons already above remain the experiments; this table connects their limits.' }),
    el('a', { href: FIPS, text: 'ML-KEM algorithm specification: FIPS 203' }),
  );
  render();
  return section;
}
