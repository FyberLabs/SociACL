import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
const result = await build({ entryPoints: [fileURLToPath(new URL('../src/index.js',import.meta.url))],
  bundle: true, platform: 'browser', format: 'esm', target: 'es2022', write: false, metafile: true });
for (const [name,input] of Object.entries(result.metafile.inputs)) {
  for (const ref of input.imports) if (ref.path.startsWith('node:')) throw Error(`Node dependency: ${name} -> ${ref.path}`);
}
if (result.outputFiles.some(f=>/\b(?:from|import)\s*[(]?\s*['"]node:/.test(f.text))) throw Error('Node import in browser bundle');
console.log(`Browser bundle verified (${result.outputFiles[0].contents.length} bytes)`);
