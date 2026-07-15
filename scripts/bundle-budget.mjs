// Fail the build if the shipped JavaScript grows past its budget. Protects the
// small-bundle win rather than just achieving it once. Runs after `vite build`.
import { readdirSync, readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';

// Envelope, in kB (gzipped). Keep in sync with the README's Performance section.
const BUDGET_JS_GZIP_KB = 28;

const assetsDir = join('dist', 'assets');
let files;
try {
  files = readdirSync(assetsDir).filter((f) => f.endsWith('.js'));
} catch {
  console.error(`bundle-budget: ${assetsDir} not found — run \`npm run build\` first.`);
  process.exit(1);
}

let totalGzip = 0;
for (const f of files) {
  const raw = readFileSync(join(assetsDir, f));
  totalGzip += gzipSync(raw).length;
}
const kb = totalGzip / 1024;
const pretty = kb.toFixed(2);

if (kb > BUDGET_JS_GZIP_KB) {
  console.error(
    `bundle-budget: FAIL — JS is ${pretty} kB gzip, over the ${BUDGET_JS_GZIP_KB} kB budget.`,
  );
  process.exit(1);
}
console.log(`bundle-budget: OK — JS is ${pretty} kB gzip (budget ${BUDGET_JS_GZIP_KB} kB).`);
