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
const {outputFiles}=await build({stdin:{contents:"export {openFirstContactStore} from './first-contact-store.js'; export {openFirstContactFloor} from './first-contact-floor.js';",resolveDir:fileURLToPath(new URL('../src/',import.meta.url)),loader:'js'},bundle:true,platform:'browser',format:'esm',write:false});
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
  await context.close();context=undefined;
  context=await chromium.launchPersistentContext(profile,{headless:true});
  const reopened=await page();
  assert.deepEqual(await reopened.evaluate(()=>window.floor.read()),savedFloor);
  assert.equal(await reopened.evaluate(async()=>{try{await window.floor.observe({revision:1,digest:'ab'.repeat(32)},()=>{});return true;}catch{return false;}}),false);
  assert.equal(await reserve(reopened),false);
  assert.deepEqual(await reopened.evaluate(()=>window.store.pending()),[]);
  const next=await reopened.evaluate(p=>window.store.activate(p),policy);
  assert.notEqual(next.channelId,d.channelId);assert.equal(next.revision,d.revision+1);
  assert.equal(await reopened.evaluate(async ({d,key,id,time})=>{
    try{await window.store.reserve(d,{replayKey:key,requestId:id,replayUntil:d.expiresAt,expiresAt:time+100,envelope:new Uint8Array(94)});return true;}catch{return false;}
  },input),false);
  console.log('First-contact Chromium: concurrent replay, rejection, process restart and descriptor rotation passed');
}finally{await context?.close();await new Promise(resolve=>server.close(resolve));await rm(profile,{recursive:true,force:true});}
