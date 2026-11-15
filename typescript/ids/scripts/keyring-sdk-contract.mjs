// Packed export/type/bundle and SDK unit/contract validation. CI only.
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Keyring SDK contract requires CI');
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync,copyFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
const root=fileURLToPath(new URL('../',import.meta.url));
const repository=fileURLToPath(new URL('../../../',import.meta.url));
const sdk=resolve(process.env.SEA_DEVICE_LINK_SDK);
const temp=mkdtempSync(join(tmpdir(),'sociacl-keyring-sdk-'));
try{
 const packs=[];
 for(const cwd of [root,sdk]){
  const packed=JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',temp],{cwd,encoding:'utf8'}));
  packs.push(join(temp,packed[0].filename));
 }
 writeFileSync(join(temp,'package.json'),JSON.stringify({private:true,type:'module'}));
 execFileSync('npm',['install','--ignore-scripts','--no-audit','--no-fund',...packs],{cwd:temp,stdio:'inherit'});
 const types=`import {importKeyring,exportKeyring,validateKeyring,closeKeyring,openKeyringContent,type KeyringState} from 'sociacl-ids/keyring';
import type {IdentityAdapter} from 'sea-device-link';
export function validator(state:KeyringState):IdentityAdapter['validateKeyring'] {return async (bytes,identity)=>validateKeyring(bytes,identity,state);}
export {importKeyring,exportKeyring,closeKeyring,openKeyringContent};`;
 writeFileSync(join(temp,'consumer.ts'),types);
 execFileSync(process.execPath,[join(root,'node_modules/typescript/bin/tsc'),'--strict','--noEmit','--target','ES2022','--module','NodeNext','--moduleResolution','NodeNext','consumer.ts'],{cwd:temp,stdio:'inherit'});
 const bundled=await build({entryPoints:[join(temp,'consumer.ts')],bundle:true,platform:'browser',format:'esm',write:false,metafile:true});
 for(const [name,input] of Object.entries(bundled.metafile.inputs))for(const ref of input.imports)if(ref.path.startsWith('node:'))throw Error('Node runtime import: '+name);
 if(bundled.outputFiles.some(f=>/\brequire\(|\bBuffer\b|node:crypto/.test(f.text)))throw Error('Node runtime in browser keyring');
 copyFileSync(join(root,'test/keyring-sdk-contract.mjs'),join(temp,'contract.mjs'));
 execFileSync(process.execPath,['contract.mjs'],{cwd:temp,stdio:'inherit',env:{...process.env,
 KEYRING_VECTOR:join(repository,'vectors/encrypted-discovery/browser-keyring.json'),KEYRING_RECORDS:join(repository,'vectors/ids/records.json'),KEYRING_WRAP:join(repository,'vectors/encrypted-discovery/account-keyring.json')}});
}finally{rmSync(temp,{recursive:true,force:true});}
