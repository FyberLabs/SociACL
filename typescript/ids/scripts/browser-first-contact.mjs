// Real browser persistence checks belong exclusively to the central scheduled batch.
if (process.env.GITHUB_ACTIONS !== 'true' || process.env.GITHUB_EVENT_NAME !== 'schedule' ||
    process.env.NIGHTLY_SUITE !== 'sociacl-browser') throw Error('Requires central nightly CI');
const { default: assert } = await import('node:assert/strict');
const { mkdtemp,readFile,rm } = await import('node:fs/promises');
const { tmpdir } = await import('node:os');
const { join } = await import('node:path');
const { createServer } = await import('node:http');
const { fileURLToPath } = await import('node:url');
const { build } = await import('esbuild');
const { chromium } = await import('playwright');
const v=JSON.parse(await readFile(new URL('../../../vectors/first-contact/v1.json',import.meta.url)));
const config={owner:v.request.sender,name:'first-contact',time:v.request.issuedAt+20};
const policy={encryptionEpub:v.request.replyEpub,expiresAt:config.time+600,maxLifetimeSeconds:300,maxMessageBytes:1024};
const {outputFiles}=await build({stdin:{contents:"export {openFirstContactStore} from './first-contact-store.js'; export {openFirstContactFloor} from './first-contact-floor.js'; export {pollFirstContact} from '../../contract/first-contact-poll.ts'; export {sealFirstContactRequestBrowser} from '../../contract/first-contact-browser.ts'; export {firstContactRequestBytes} from '../../contract/first-contact.ts'; export {signWithKeyring,historyState} from './index.js';",resolveDir:fileURLToPath(new URL('../src/',import.meta.url)),loader:'js'},nodePaths:[fileURLToPath(new URL('../node_modules/',import.meta.url))],bundle:true,platform:'browser',format:'esm',write:false});
const server=createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/store.js'?'text/javascript':'text/html');res.end(req.url==='/store.js'?outputFiles[0].text:'<!doctype html><title>First-contact persistence</title>');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const url=`http://127.0.0.1:${server.address().port}`, profile=await mkdtemp(join(tmpdir(),'sociacl-contact-browser-'));
let context;
async function page(create=false){
  const page=await context.newPage();await page.goto(url);
  await page.evaluate(async ({config,create})=>{
    const {openFirstContactStore,openFirstContactFloor}=await import('/store.js');
    window.floor=await openFirstContactFloor({...config,name:'descriptor-floors',anchor:{revision:1,digest:'ab'.repeat(32)},create,now:()=>config.time});
    window.store=await openFirstContactStore({...config,create,now:()=>config.time});
  },{config,create});return page;
}
try{
  context=await chromium.launchPersistentContext(profile,{headless:true});
  const a=await page(true),b=await page();
  const observations=await Promise.all([a,b].map((p,i)=>p.evaluate(async i=>{try{await window.floor.observe({revision:2,digest:(i?'cd':'ef').repeat(32)},()=>{});return true;}catch{return false;}},i)));
  assert.equal(observations.filter(Boolean).length,1);
  const savedFloor=await a.evaluate(()=>window.floor.read());
  const d=await a.evaluate(p=>window.store.activate(p),policy);
  const input={d,key:'12'.repeat(32),id:'34'.repeat(32),time:config.time};
  const reserve=page=>page.evaluate(({d,key,id,time})=>window.store.reserve(d,{replayKey:key,requestId:id,
    replayUntil:d.expiresAt,expiresAt:time+100,envelope:new Uint8Array(94)}),input);
  assert.deepEqual((await Promise.all([reserve(a),reserve(b)])).sort(),[false,true]);
  assert.deepEqual(await a.evaluate(()=>window.store.outbox()),[]);
  await a.evaluate(({d,key,id})=>window.store.decide(d,key,id,{status:'rejected'}),input);
  const packet=await a.evaluate(async ({v,d,time})=>{
    const api=await import('/store.js');
    const request={...v.request,channelId:d.channelId,descriptorRevision:d.revision,issuedAt:time,expiresAt:time+100};
    const key=new Uint8Array(32);key[31]=1;
    const signed=api.signWithKeyring(key,api.firstContactRequestBytes(request),request.sender);
    if(!signed.ok)throw Error(signed.reason);
    const ciphertext=await api.sealFirstContactRequestBrowser({...request,sig:signed.value},d);
    const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',ciphertext));
    return {ciphertext:Array.from(ciphertext),id:Array.from(digest,b=>b.toString(16).padStart(2,'0')).join('')};
  },{v,d,time:config.time});
  const poll=p=>p.evaluate(async ({packet,time})=>{
    const api=await import('/store.js');
    const key=new Uint8Array(32);key[31]=2;
    const epriv=btoa(String.fromCharCode(...key)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    const state={now:time,jwks:{keys:[]},links:new Map(),revocations:[],pinnedIss:new Set(),
      policy:{allowedDomains:[],allowedUris:[],allowedChainIds:[],clockSkewSeconds:0},
      history:(p,at,until)=>({ok:true,value:api.historyState(p,[],at,until)})};
    return (await api.pollFirstContact(window.store,async()=>[{...packet,ciphertext:new Uint8Array(packet.ciphertext)}],epriv,()=>({rotations:[],context:state}))).length;
  },{packet,time:config.time});
  assert.deepEqual((await Promise.all([poll(a),poll(b)])).sort(),[0,1]);
  assert.deepEqual(await a.evaluate(()=>window.store.outbox()),[]);
  await a.evaluate(async d=>{const [row]=await window.store.pending();await window.store.decide(d,row.replayKey,row.requestId,{status:'rejected'});},d);
  await context.close();context=undefined;
  context=await chromium.launchPersistentContext(profile,{headless:true});
  const reopened=await page();
  assert.deepEqual(await reopened.evaluate(()=>window.floor.read()),savedFloor);
  assert.equal(await reopened.evaluate(async()=>{try{await window.floor.observe({revision:1,digest:'ab'.repeat(32)},()=>{});return true;}catch{return false;}}),false);
  assert.equal(await reserve(reopened),false);
  assert.equal(await poll(reopened),0);
  assert.deepEqual(await reopened.evaluate(()=>window.store.pending()),[]);
  const next=await reopened.evaluate(p=>window.store.activate(p),policy);
  assert.notEqual(next.channelId,d.channelId);assert.equal(next.revision,d.revision+1);
  assert.equal(await reopened.evaluate(async ({d,key,id,time})=>{
    try{await window.store.reserve(d,{replayKey:key,requestId:id,replayUntil:d.expiresAt,expiresAt:time+100,envelope:new Uint8Array(94)});return true;}catch{return false;}
  },input),false);
  console.log('First-contact Chromium: concurrent replay, rejection, process restart and descriptor rotation passed');
}finally{await context?.close();await new Promise(resolve=>server.close(resolve));await rm(profile,{recursive:true,force:true});}
