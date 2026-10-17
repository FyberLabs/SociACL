import { copyFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
const root = new URL('../', import.meta.url);
const dist = new URL('dist/', root);
rmSync(dist, { recursive: true, force: true });
execFileSync(process.execPath, [fileURLToPath(new URL('node_modules/typescript/bin/tsc', root)),
  '--strict', '--allowJs', '--checkJs', '--declaration', '--emitDeclarationOnly', '--noEmit', 'false',
  '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext',
  '--outDir', 'dist', ...readdirSync(new URL('src/',root)).filter(f=>f.endsWith('.js')).map(f=>'src/'+f)],
  { cwd: fileURLToPath(root), stdio: 'inherit' });
mkdirSync(dist, { recursive: true });
for (const name of readdirSync(new URL('src/',root)).filter(f=>f.endsWith('.js') || f.endsWith('.d.ts'))) {
  copyFileSync(new URL('src/'+name,root),new URL(name,dist));
}
