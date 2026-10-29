import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { IDBFactory, IDBObjectStore, IDBDatabase } from 'fake-indexeddb';
import { p256 } from '@noble/curves/nist.js';
import { openWitnessPolicyStore } from '../src/indexeddb.js';
import { openWitnessCheckpointStore } from '../src/checkpoint-store.js';

const f = JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-checkpoint.json', import.meta.url)));
const lifecycle = JSON.parse(readFileSync(new URL('../../../vectors/ids/witness-lifecycle.json', import.meta.url)));
const initial = lifecycle.accept.find(c => c.name === 'bootstrap-at-floor').input.steps[0].envelope;
const canonical = f.accept[0].canonical;
function sign(doc, scalar, kind) {
  const payload = Buffer.from(JSON.stringify(doc));
  const signature = p256.sign(Buffer.concat([Buffer.from(`sociacl-witness-${kind}-v1\n`),payload]),
    Buffer.from(scalar.toString(16).padStart(64,'0'),'hex'), {lowS:true});
  return JSON.stringify({type:`sociacl-witness-${kind}-envelope-v1`,payload:payload.toString('base64url'),signature:Buffer.from(signature).toString('base64url')});
}
function response(request, changes = {}) {
  const doc = {...canonical, challenge:request.challenge, ...changes};
  return [sign(doc,18,'checkpoint'), sign({type:'sociacl-witness-policy-v1',audience:doc.audience,
    revision:doc.state.revision, issuedAt:doc.issuedAt, expiresAt:doc.expiresAt, jwks:doc.state.jwks},17,'policy')];
}
async function setup(overrides = {}, empty = false) {
  const time = {wall:f.context.now,mono:1000};
  const options = {...f.context, name:'checkpoint',minimumRevision:7, indexedDB:new IDBFactory(),now:()=>time.wall,monotonic:()=>time.mono,...overrides};
  if (!empty) {
    const old = await openWitnessPolicyStore({...options,minimumRevision:7});
    await old.bootstrap(initial); old.close();
  }
  return {options,time,store:await openWitnessCheckpointStore(options)};
}
async function raw(options, edit) {
  const db = await new Promise((resolve,reject) => {const r=options.indexedDB.open(options.name,2);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
  try { await new Promise((resolve,reject) => {
    const tx=db.transaction('witness-policy','readwrite'), s=tx.objectStore('witness-policy'), r=s.get('installed');
    r.onsuccess=()=>edit(s,r.result);tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);
  }); } finally {db.close();}
}
async function installed(store, changes) {const request=await store.beginRefresh();return store.install(request,...response(request,changes));}

test('upgrade preserves old evidence, installs complete history and requires a new lease after reopen', async () => {
  const {store,options}=await setup();
  assert.equal((await store.readInstalled()).revision,7);
  await assert.rejects(store.readFresh());
  const state=await installed(store);
  assert.deepEqual(state,canonical.state);
  assert.deepEqual(await store.readFresh(),state);
  store.close();
  const reopened=await openWitnessCheckpointStore(options);
  try {assert.deepEqual(await reopened.readInstalled(),state);await assert.rejects(reopened.readFresh());}
  finally {reopened.close();}
  await assert.rejects(openWitnessPolicyStore(options)); // schema v2 excludes old writers
});

test('one-use request cannot be cloned, reused, restored or used by another connection', async () => {
  const {store,options}=await setup(), other=await openWitnessCheckpointStore(options);
  const request=await store.beginRefresh(), reply=response(request);
  try {
    await assert.rejects(store.install({...request},...reply));
    await assert.rejects(other.install(request,...reply));
    await store.install(request,...reply);
    await assert.rejects(store.install(request,...reply));
    store.close();
    const reopened=await openWitnessCheckpointStore(options);
    try {await assert.rejects(reopened.install(request,...reply));await assert.rejects(reopened.readFresh());}
    finally {reopened.close();}
  } finally {store.close();other.close();}
});

test('fresh request uses unpredictable 32-byte challenges and supersedes earlier requests', async () => {
  const {store}=await setup();
  try {
    const a=await store.beginRefresh(),b=await store.beginRefresh();
    assert.equal(Buffer.from(a.challenge,'base64url').length,32);assert.notEqual(a.challenge,b.challenge);
    assert.ok(Object.isFrozen(b));assert.equal(b.operation,'refresh');
    await assert.rejects(store.install(a,...response(a)));
    await assert.rejects(store.install(b,...response(a))); // wrong outstanding challenge
    await assert.rejects(store.install(b,...response(b))); // failure consumes it too
    await assert.rejects(store.readFresh());
  } finally {store.close();}
});

test('failed refresh invalidates prior positive-use lease without erasing installed history', async () => {
  const {store}=await setup();
  try {
    const state=await installed(store), request=await store.beginRefresh();
    await assert.rejects(store.readFresh());
    await assert.rejects(store.install(request,'{}','{}'));
    assert.deepEqual(await store.readInstalled(),state);await assert.rejects(store.readFresh());
  } finally {store.close();}
});

for(const attack of ['revision','omission','widening','resurrection']) test(`signed ${attack} cannot weaken existing history`, async () => {
  const {store}=await setup();
  try {
    const state=await installed(store), next=structuredClone(state);next.revision++;
    if(attack==='revision')next.revision=7;
    if(attack==='omission')next.history.shift();
    if(attack==='widening')next.history[0].jwk.notAfter++;
    if(attack==='resurrection'){next.history[0].removed=false;next.jwks.keys.push(next.history[0].jwk);}
    const request=await store.beginRefresh();
    await assert.rejects(store.install(request,...response(request,{state:next})));
    assert.deepEqual(await store.readInstalled(),state);await assert.rejects(store.readFresh());
  } finally {store.close();}
});

for (const kind of ['wall-expiry','mono-expiry','wall-backward','mono-backward','bad-clock']) test(`${kind} invalidates current trust`,async()=>{
  const {store,time}=await setup();
  try {
    const state=await installed(store);
    if(kind==='wall-expiry')time.wall=canonical.expiresAt;
    if(kind==='mono-expiry')time.mono+=60000;
    if(kind==='wall-backward')time.wall--;
    if(kind==='mono-backward')time.mono--;
    if(kind==='bad-clock')time.mono=NaN;
    await assert.rejects(store.readFresh());assert.deepEqual(await store.readInstalled(),state);
    time.wall=f.context.now;time.mono=1000;
    await assert.rejects(store.readFresh());
  } finally {store.close();}
});

test('download time counts toward the monotonic lease even if UTC stalls',async()=>{
  const {store,time}=await setup();
  try {const request=await store.beginRefresh();time.mono+=60000;await assert.rejects(store.install(request,...response(request)));assert.equal((await store.readInstalled()).revision,7);}
  finally {store.close();}
});

test('concurrent winner is re-read under the write lock and invalidates another handle lease',async()=>{
  const {store,options}=await setup(),other=await openWitnessCheckpointStore(options);
  try {
    await installed(store);
    const a=await store.beginRefresh(),b=await other.beginRefresh();
    const newer=structuredClone(canonical.state);newer.revision=9;
    const outcomes=await Promise.allSettled([store.install(a,...response(a,{state:newer})),other.install(b,...response(b))]);
    assert.deepEqual(outcomes.map(x=>x.status),['fulfilled','rejected']);
    assert.equal((await other.readInstalled()).revision,9);
    await assert.rejects(other.readFresh());
    const later=await other.beginRefresh();await other.install(later,...response(later,{state:newer}));
    await assert.rejects(store.readFresh()); // superseded evidence, even at identical revision
  } finally {store.close();other.close();}
});

test('missing state never bootstraps; no recovery or reset method is exposed',async()=>{
  const {store}=await setup({},true);
  try {await assert.rejects(store.readInstalled());await assert.rejects(store.beginRefresh());await assert.rejects(store.readFresh());assert.equal(store.bootstrap,undefined);assert.equal(store.restore,undefined);}
  finally {store.close();}
});

for(const corruption of ['delete','state','signature','time','extra'])test(`saved ${corruption} cannot silently recover`,async()=>{
  const {store,options}=await setup();
  try {
    await installed(store);
    await raw(options,(s,row)=>{
      if(corruption==='delete'){s.delete('installed');return;}
      if(corruption==='state')row.state='{}';if(corruption==='signature')row.checkpoint='{}';
      if(corruption==='time')row.acceptedAt+=100000;if(corruption==='extra')row.extra=true;
      s.put(row,'installed');
    });
    await assert.rejects(store.readInstalled());await assert.rejects(store.readFresh());await assert.rejects(store.beginRefresh());
  }finally{store.close();}
});

for(const change of [{rootEpoch:2},{client:'other'},{audience:'other'}])test(`configuration change ${JSON.stringify(change)} does not migrate trust`,async()=>{
  const {store,options}=await setup();await installed(store);store.close();
  const other=await openWitnessCheckpointStore({...options,...change});
  try{await assert.rejects(other.readInstalled());await assert.rejects(other.beginRefresh());}finally{other.close();}
});

for(const failure of ['quota','abort','expiry-before-commit','expiry-after-commit','cancel-after-commit'])test(`${failure} preserves atomicity and never grants a lease`,async()=>{
  const {store,time}=await setup(), before=await store.readInstalled(),request=await store.beginRefresh();
  const original=IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put=function(...args){
    if(failure==='quota')throw new DOMException('full','QuotaExceededError');
    const r=original.apply(this,args);
    if(failure==='abort')r.addEventListener('success',()=>this.transaction.abort());
    if(failure==='expiry-before-commit')r.addEventListener('success',()=>{time.wall=canonical.expiresAt;});
    if(failure==='expiry-after-commit')this.transaction.addEventListener('complete',()=>{time.wall=canonical.expiresAt;});
    if(failure==='cancel-after-commit')this.transaction.addEventListener('complete',()=>store.cancel());
    return r;
  };
  try{await assert.rejects(store.install(request,...response(request)));}
  finally{IDBObjectStore.prototype.put=original;}
  try{
    const row=await store.readInstalled();
    assert.deepEqual(row,failure.endsWith('after-commit')?canonical.state:before);
    await assert.rejects(store.readFresh());await assert.rejects(store.install(request,...response(request)));
  }finally{store.close();}
});

test('strict durability is required and no best-effort fallback writes a row',async()=>{
  const {store}=await setup(),request=await store.beginRefresh(),original=IDBDatabase.prototype.transaction;
  IDBDatabase.prototype.transaction=function(names,mode){return original.call(this,names,mode);};
  try{await assert.rejects(store.install(request,...response(request)),/durability/);}finally{IDBDatabase.prototype.transaction=original;}
  assert.equal((await store.readInstalled()).revision,7);store.close();
});

test('raised floor permits authenticated renewal but forbids old reads',async()=>{
  const {store}=await setup({minimumRevision:8});
  try{await assert.rejects(store.readInstalled());assert.equal((await installed(store)).revision,8);}
  finally{store.close();}
});

test('cancelled or closed requests cannot finish or restore a lease',async()=>{
  const {store}=await setup();const a=await store.beginRefresh();store.cancel();
  await assert.rejects(store.install(a,...response(a)));const b=await store.beginRefresh();store.close();
  await assert.rejects(store.install(b,...response(b)));await assert.rejects(store.readFresh());await assert.rejects(store.beginRefresh());
});

for (const clock of ['wall', 'monotonic']) test(`earlier policy expiry bounds ${clock} freshness`, async () => {
  const {store,time}=await setup();
  try {
    const request=await store.beginRefresh(), [checkpoint]=response(request);
    const policy=sign({type:'sociacl-witness-policy-v1',audience:canonical.audience,
      revision:canonical.state.revision,issuedAt:time.wall,expiresAt:time.wall+5,jwks:canonical.state.jwks},17,'policy');
    await store.install(request,checkpoint,policy);
    await store.readFresh();
    if(clock==='wall') time.wall+=5; else time.mono+=5000;
    await assert.rejects(store.readFresh());
    assert.equal((await store.readInstalled()).revision,canonical.state.revision);
  } finally {store.close();}
});
