// CI-only actual Chromium recovery and cross-entry opaque-handle contract.
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Recovery browser contract requires CI');
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {chromium} from 'playwright';
const read=async name=>JSON.parse(await readFile(new URL('../../../vectors/'+name,import.meta.url),'utf8'));
const ring=await read('encrypted-discovery/account-keyring.json'),records=await read('ids/records.json'),legacy=await read('encrypted-discovery/recovery-legacy-strength.json');
const bundled=await build({stdin:{contents:"export {openRecoveryKeyring,sealRecoveryKeyring} from './dist/recovery.js';export {exportKeyring,closeKeyring} from './dist/keyring.js';export {historyState} from './dist/index.js';",resolveDir:fileURLToPath(new URL('../',import.meta.url))},bundle:true,platform:'browser',format:'esm',write:false,metafile:true});
for(const input of Object.values(bundled.metafile.inputs))for(const ref of input.imports)if(ref.path.startsWith('node:'))throw Error('Node import in recovery');
const server=createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/recovery.js'?'text/javascript':'text/html');res.end(req.url==='/recovery.js'?bundled.outputFiles[0].text:'<!doctype html><title>Recovery contract</title>');});
let browser;
try{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));browser=await chromium.launch({headless:true});const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}`);
 const result=await page.evaluate(async({ring,records,legacy})=>{
  const m=await import('/recovery.js'),g=ring.genesis,expected={principal:g.principal,pub:g.signingPub,epub:g.epub,rotationSeq:0};
  const state=()=>({rotations:[],context:{...records.context,links:new Map(records.context.links),revocations:[],pinnedIss:new Set(records.context.pinnedIss),genesisEpubBindings:[ring.genesisBinding],history:(p,at,until)=>records.context.authenticatedAccounts.includes(p)?{ok:true,value:m.historyState(p,[],at,until)}:{ok:false,reason:'missing-history'}}});
  const bytes=new Uint8Array(legacy.envelopeHex.match(/../g).map(h=>parseInt(h,16))),e={principal:g.principal,signingPub:g.signingPub,epub:g.epub,rotationSeq:0,bytes};
  const pass=new TextEncoder().encode(legacy.passphraseUtf8),handle=await m.openRecoveryKeyring(pass,e,expected,state);
  const encoded=m.exportKeyring(handle,state);const size=encoded.length;encoded.fill(0);
  let weak=false;try{await m.sealRecoveryKeyring(handle,pass,state);}catch(e){weak=e.message==='recovery-weak-passphrase';}
  const freshPass=new TextEncoder().encode('Otters juggle violet satellites beyond Jupiter 739!');
  const sealed=await m.sealRecoveryKeyring(handle,freshPass,state);const reopened=await m.openRecoveryKeyring(freshPass,sealed,expected,state);m.closeKeyring(reopened);freshPass.fill(0);m.closeKeyring(handle);
  let closed=false,tampered=false;try{m.exportKeyring(handle,state);}catch{closed=true;}
  bytes[bytes.length-1]^=1;try{await m.openRecoveryKeyring(pass,e,expected,state);}catch{tampered=true;}pass.fill(0);
  return {opened:size>0,closed,tampered,weak};
 },{ring,records,legacy});
 assert.deepEqual(result,{opened:true,closed:true,tampered:true,weak:true});console.log('Chromium recovery: legacy passphrase, shared keyring handle, close and tamper refusal passed');
}finally{await browser?.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
