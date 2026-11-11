import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
const root = new URL('../', import.meta.url);
execFileSync(process.execPath, [fileURLToPath(new URL('typescript/ids/scripts/build.mjs', root))], { stdio: 'inherit' });
for (const name of ['agent-delegation.d.ts', 'types.d.ts']) {
  const bytes = readFileSync(new URL('typescript/ids/dist/' + name, root));
  const dest = new URL('docs/agent-delegation/' + name, root);
  if (process.argv.includes('--write')) writeFileSync(dest, bytes);
  else if (!readFileSync(dest).equals(bytes)) throw Error('Agent consume contract drift: ' + name);
}
const paths = ['docs/agent-delegation/agent-delegation.d.ts', 'docs/agent-delegation/types.d.ts', 'vectors/agent-delegation/v1.json'];
const manifest = JSON.stringify({ version: 1, files: Object.fromEntries(paths.map(p => [p, createHash('sha256').update(readFileSync(new URL(p, root))).digest('hex')])) }, null, 2) + '\n';
const dest = new URL('docs/agent-delegation/manifest.json', root);
if (process.argv.includes('--write')) writeFileSync(dest, manifest);
else if (readFileSync(dest, 'utf8') !== manifest) throw Error('Agent consume manifest drift');
