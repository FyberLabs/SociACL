// Public fixture keys only; real Chromium persistence/concurrency acceptance.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename } from 'node:path';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium } from 'playwright';
import { p256 } from '@noble/curves/nist.js';
const f = JSON.parse(await readFile(new URL('../../../vectors/ids/witness-checkpoint.json', import.meta.url)));
const lifecycle = JSON.parse(await readFile(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url)));
const initial = lifecycle.accept.find(c=>c.name==='bootstrap-at-floor').input.steps[0].envelope;
function sign(doc,scalar,kind) {
  const payload=Buffer.from(JSON.stringify(doc)),signature=p256.sign(Buffer.concat([Buffer.from(`sociacl-witness-${kind}-v1\n`),payload]),
    Buffer.from(scalar.toString(16).padStart(64,'0'),'hex'),{lowS:true});
  return JSON.stringify({type:`sociacl-witness-${kind}-envelope-v1`,payload:payload.toString('base64url'),signature:Buffer.from(signature).toString('base64url')});
}
function response(request,state=f.accept[0].canonical.state) {
  const doc={...f.accept[0].canonical,state,challenge:request.challenge};
  return [sign(doc,18,'checkpoint'),sign({type:'sociacl-witness-policy-v1',audience:doc.audience,revision:state.revision,
    issuedAt:doc.issuedAt,expiresAt:doc.expiresAt,jwks:state.jwks},17,'policy')];
}
const { outputFiles }=await build({entryPoints:['checkpoint-store.js','indexeddb.js'].map(n=>fileURLToPath(new URL('../src/'+n,import.meta.url))),
  bundle:true,platform:'browser',format:'esm',outdir:'unused',write:false});
const scripts=new Map(outputFiles.map(f=>['/'+basename(f.path),f.text]));
const server=createServer((req,res)=>{res.setHeader('Content-Type',scripts.has(req.url)?'text/javascript':'text/html');res.end(scripts.get(req.url)??'<!doctype html><title>Checkpoint store</title>');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const url=`http://127.0.0.1:${server.address().port}`,profile=await mkdtemp(join(tmpdir(),'sociacl-checkpoint-'));
let context;
async function page(initialize=false) {
  const p=await context.newPage();await p.goto(url);
  await p.evaluate(async ({config,initial,initialize})=>{
    window.time={wall:config.now,mono:1000};
    window.options={...config,minimumRevision:7,name:'acceptance',now:()=>window.time.wall,monotonic:()=>window.time.mono};
    if(initialize){const {openWitnessPolicyStore}=await import('/indexeddb.js');const old=await openWitnessPolicyStore(window.options);await old.bootstrap(initial);old.close();}
    const {openWitnessCheckpointStore}=await import('/checkpoint-store.js');
    window.store=await openWitnessCheckpointStore(window.options);
  },{config:f.context,initial,initialize});return p;
}
try {
  context=await chromium.launchPersistentContext(profile,{headless:true});
  const a=await page(true),b=await page();
  await a.evaluate(async()=>{window.request=await window.store.beginRefresh();});
  const request=await a.evaluate(()=>window.request);
  await a.evaluate(reply=>window.store.install(window.request,...reply),response(request));
  assert.equal((await a.evaluate(()=>window.store.readFresh())).revision,8);
  assert.equal(await b.evaluate(async()=>{try{await window.store.readFresh();return true;}catch{return false;}}),false);
  // Open a competitor in the same page to enqueue ordered transactions, while
  // separate page b checks that only durable state (not the lease) is shared.
  const reqs=await a.evaluate(async()=>{const {openWitnessCheckpointStore}=await import('/checkpoint-store.js');window.other=await openWitnessCheckpointStore(window.options);
    window.ra=await window.store.beginRefresh();window.rb=await window.other.beginRefresh();return [window.ra,window.rb];});
  const newer={...f.accept[0].canonical.state,revision:9};
  assert.deepEqual(await a.evaluate(async replies=>(await Promise.allSettled([window.store.install(window.ra,...replies[0]),window.other.install(window.rb,...replies[1])])).map(x=>x.status),
    [response(reqs[0],newer),response(reqs[1])]),['fulfilled','rejected']);
  assert.deepEqual(await b.evaluate(()=>window.store.readInstalled()),newer);
  await context.close();context=undefined;
  context=await chromium.launchPersistentContext(profile,{headless:true});
  const restarted=await page();
  assert.deepEqual(await restarted.evaluate(()=>window.store.readInstalled()),newer);
  assert.equal(await restarted.evaluate(async()=>{try{await window.store.readFresh();return true;}catch{return false;}}),false);
  const next=await restarted.evaluate(async()=>{window.r=await window.store.beginRefresh();return window.r;});
  await restarted.evaluate(reply=>window.store.install(window.r,...reply),response(next,newer));
  assert.equal(await restarted.evaluate(async()=>{window.time.mono+=60000;try{await window.store.readFresh();return true;}catch{return false;}}),false);
  assert.deepEqual(await restarted.evaluate(()=>window.store.readInstalled()),newer);
  console.log('Chromium checkpoint store: schema upgrade, serialized refresh, cross-page reads, full-process restart and monotonic lease expiry passed');
} finally {await context?.close();await new Promise(resolve=>server.close(resolve));await rm(profile,{recursive:true,force:true});}
