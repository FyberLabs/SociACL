import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const temp=mkdtempSync(join(tmpdir(),'sociacl-ids-consumer-'));
try {
  execFileSync('npm',['run','build'],{cwd:root,stdio:'inherit'});
  const packed=JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',temp],{cwd:root,encoding:'utf8'}));
  const consumer=join(temp,'consumer'); cpSync(join(root,'examples/consumer'),consumer,{recursive:true});
  execFileSync('npm',['install','--offline','--ignore-scripts','--no-audit','--no-fund',join(temp,packed[0].filename)],{cwd:consumer,stdio:'inherit'});
  execFileSync(process.execPath,[join(root,'node_modules/typescript/bin/tsc'),'--strict','--noEmit','--target','ES2022','--module','NodeNext','--moduleResolution','NodeNext','main.ts'],{cwd:consumer,stdio:'inherit'});
  execFileSync(process.execPath,['main.ts'],{cwd:consumer,stdio:'inherit'});
} finally { rmSync(temp,{recursive:true,force:true}); }
