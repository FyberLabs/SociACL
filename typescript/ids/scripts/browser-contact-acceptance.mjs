// Real Chromium + IndexedDB acceptance contract using public, synthetic SEA keys.
// Central scheduled CI only; no hosted accounts, service calls or login fixtures.
if(process.env.GITHUB_ACTIONS!=='true'||process.env.GITHUB_EVENT_NAME!=='schedule'||process.env.NIGHTLY_SUITE!=='sociacl-browser')throw Error('Requires central nightly CI');
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {chromium} from 'playwright';
const fixture=JSON.parse(await readFile(new URL('../../../vectors/encrypted-discovery/account-keyring.json',import.meta.url)));
const records=JSON.parse(await readFile(new URL('../../../vectors/ids/records.json',import.meta.url)));
const {outputFiles}=await build({stdin:{contents:"export {openFirstContactStore} from './first-contact-store.js'; export {acceptFirstContactRequest} from '../../contract/first-contact-accept-browser.ts'; export {sealFirstContactRequestBrowser} from '../../contract/first-contact-browser.ts'; export {pollFirstContact} from '../../contract/first-contact-poll.ts'; export {firstContactRequestBytes} from '../../contract/first-contact.ts'; export {openContactLaneGrant,deriveContactLane} from '../../contract/contact-lane-browser.ts'; export {signWithKeyring,historyState} from './index.js';",resolveDir:fileURLToPath(new URL('../src/',import.meta.url)),loader:'js'},nodePaths:[fileURLToPath(new URL('../node_modules/',import.meta.url))],bundle:true,platform:'browser',format:'esm',write:false});
const profile=await mkdtemp(join(tmpdir(),'sociacl-contact-acceptance-'));
const server=createServer((req,res)=>{res.setHeader('cache-control','no-store');if(req.url==='/api.js'){res.setHeader('content-type','text/javascript');res.end(outputFiles[0].text);}else if(req.url==='/'){res.setHeader('content-type','text/html');res.end('<!doctype html><title>Isolated browser acceptance</title>');}else{res.statusCode=404;res.end();}});
let context;
try{
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 const origin=`http://127.0.0.1:${server.address().port}`;
 async function launch(){context=await chromium.launchPersistentContext(profile,{headless:true});await context.route('**/*',route=>route.request().url().startsWith(origin+'/')?route.continue():route.abort());const page=await context.newPage();await page.goto(origin);return page;}
 const page=await launch();
 const accepted=await page.evaluate(async ({fixture,source})=>{
  const api=await import('/api.js'),sender=fixture.genesis,owner=fixture.mint;
  const known=new Set([sender.signingPub,owner.signingPub]);
  const ctx={...source,links:new Map(source.links),pinnedIss:new Set(source.pinnedIss),revocations:[],genesisEpubBindings:[fixture.genesisBinding],
   history:(p,at,until)=>known.has(p)?{ok:true,value:api.historyState(p,[],at,until)}:{ok:false,reason:'missing-history'}};
  const state=()=>({rotations:[],context:ctx});
  const issuer=()=>({...state(),issuer:{principal:owner.signingPub,signingPriv:owner.signingPriv,contactSecretHex:owner.contactLaneSecret,rotationSeq:0,baseLaneIds:[owner.laneId],contactSecrets:[owner.contactLaneSecret]}});
  const store=await api.openFirstContactStore({name:'two-identities',owner:owner.signingPub,create:true,now:()=>ctx.now});
  try{
   const d=await store.activate({encryptionEpub:owner.epub,expiresAt:ctx.now+600,maxLifetimeSeconds:300,maxMessageBytes:1024});
   const request={v:1,channelId:d.channelId,descriptorRevision:d.revision,sender:sender.signingPub,replyEpub:sender.epub,nonce:'ab'.repeat(32),issuedAt:ctx.now,expiresAt:ctx.now+300,message:'Public synthetic contact request'};
   const scalar=Uint8Array.from(atob(sender.signingPriv.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
   const signature=api.signWithKeyring(scalar,api.firstContactRequestBytes(request),sender.signingPub);scalar.fill(0);if(!signature.ok)throw Error('Fixture signature failed');
   const ciphertext=await api.sealFirstContactRequestBrowser({...request,sig:signature.value},d);
   const id=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',ciphertext)),x=>x.toString(16).padStart(2,'0')).join('');
   const sourceRows=async()=>[{id,ciphertext}];
   const admitted=await api.pollFirstContact(store,sourceRows,owner.epriv,state);
   if(admitted.length!==1||(await store.outbox()).length)throw Error('Receive accepted a contact');
   const pending=admitted[0];
   const grant=await api.acceptFirstContactRequest(store,pending.replayKey,pending.requestId,owner.epriv,state,issuer);
   const opened=await api.openContactLaneGrant(sender.signingPub,sender.epriv,grant,owner.signingPub,state);
   if(opened.laneId!==api.deriveContactLane(owner.contactLaneSecret,owner.signingPub,sender.signingPub))throw Error('Lane mismatch');
   const outbox=await store.outbox();if(outbox.length!==1||outbox[0].grant.ciphertextHex!==grant.ciphertextHex)throw Error('Missing committed outbox');
   let duplicate=false;try{await api.acceptFirstContactRequest(store,pending.replayKey,pending.requestId,owner.epriv,state,issuer);}catch{duplicate=true;}
   if(!duplicate||(await api.pollFirstContact(store,sourceRows,owner.epriv,state)).length)throw Error('Duplicate accepted');
   return {ciphertextHex:grant.ciphertextHex,replayKey:pending.replayKey,requestId:pending.requestId};
  }finally{store.close();}
 },{fixture,source:records.context});
 await context.close();context=undefined;
 const reopened=await launch();
 const retained=await reopened.evaluate(async ({owner,time})=>{const api=await import('/api.js');const store=await api.openFirstContactStore({name:'two-identities',owner,now:()=>time});try{const rows=await store.outbox();if(rows.length!==1)throw Error('Lost outbox');const row=rows[0];return{ciphertextHex:row.grant.ciphertextHex,replayKey:row.replayKey,requestId:row.requestId};}finally{store.close();}},{owner:fixture.mint.signingPub,time:records.context.now});
 assert.deepEqual(retained,accepted);
 console.log('Two-identity Chromium acceptance: explicit decision, confidential grant, duplicate refusal and retained outbox passed');
}finally{
 const results=await Promise.allSettled([context?.close(),new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()))]);
 await rm(profile,{recursive:true,force:true});
 if(results.some(result=>result.status==='rejected'))throw Error('Acceptance fixture cleanup failed');
}
