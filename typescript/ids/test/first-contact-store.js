import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { IDBFactory, IDBObjectStore } from 'fake-indexeddb';
import { openFirstContactStore } from '../src/first-contact-store.js';
const v = JSON.parse(readFileSync(new URL('../../../vectors/first-contact/v1.json', import.meta.url)));
const now = v.request.issuedAt + 20;
const policy = { encryptionEpub: v.request.replyEpub, expiresAt: now + 600, maxLifetimeSeconds: 300, maxMessageBytes: 1024 };
const options = () => ({ name: 'contacts', owner:v.request.sender, now:()=>now, create:true, indexedDB:new IDBFactory() });
const row = d => ({ replayKey:'12'.repeat(32),requestId:'34'.repeat(32),replayUntil:d.expiresAt,
  expiresAt:now+100,envelope:new Uint8Array(94) });
const grant = {status:'accepted',ciphertextHex:'ab'.repeat(100),rotationSeq:0};

test('first-contact replay survives connections, rejection and the shorter request expiry', async () => {
  const o=options(); let a=await openFirstContactStore(o); const d=await a.activate(policy);
  const r=row(d); assert.equal(await a.reserve(d,r),true);
  assert.deepEqual(await a.outbox(),[]); // Receipt creates no grant.
  assert.equal((await a.pending()).length,1);
  await a.decide(d,r.replayKey,r.requestId,{status:'rejected'});
  a.close(); a=await openFirstContactStore({...o,create:false,now:()=>now+101});
  assert.equal(await a.reserve(d,{...r,expiresAt:now+200,requestId:'56'.repeat(32)}),false);
  assert.deepEqual(await a.pending(),[]); assert.deepEqual(await a.outbox(),[]); a.close();
});

test('competing tabs reserve and decide once; outbox is durable', async () => {
  const o=options(), a=await openFirstContactStore(o), b=await openFirstContactStore(o);
  const d=await a.activate(policy), r=row(d);
  assert.deepEqual((await Promise.all([a.reserve(d,r),b.reserve(d,r)])).sort(),[false,true]);
  const outcomes=await Promise.allSettled([a.decide(d,r.replayKey,r.requestId,grant),b.decide(d,r.replayKey,r.requestId,{status:'rejected'})]);
  assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);
  const saved=await a.outbox(); assert.equal(saved.length,1); assert.deepEqual(saved[0].grant,{ciphertextHex:grant.ciphertextHex,rotationSeq:0});
  a.close(); b.close(); const reopened=await openFirstContactStore({...o,create:false});
  assert.deepEqual(await reopened.outbox(),saved); reopened.close();
});

test('rotation and disable invalidate old descriptors and pending decisions', async () => {
  const a=await openFirstContactStore(options()), d=await a.activate(policy), r=row(d);
  await a.reserve(d,r); await a.disable();
  await assert.rejects(a.reserve(d,r)); await assert.rejects(a.decide(d,r.replayKey,r.requestId,grant));
  const next=await a.activate(policy); assert.equal(next.revision,d.revision+1); assert.notEqual(next.channelId,d.channelId);
  await assert.rejects(a.reserve(d,r)); assert.deepEqual(await a.pending(),[]); a.close();
});

test('missing storage, clock rollback, full store and commit failure fail closed', async () => {
  const o=options(); await assert.rejects(openFirstContactStore({...o,create:false}));
  const a=await openFirstContactStore(o),d=await a.activate(policy),r=row(d);
  // Inject a put failure after the mutation has computed success, before commit.
  const original=IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put=function(){throw new DOMException('quota','QuotaExceededError');};
  try { await assert.rejects(a.reserve(d,r)); } finally { IDBObjectStore.prototype.put=original; }
  assert.deepEqual(await a.pending(),[]);
  assert.equal(await a.reserve(d,r),true);
  IDBObjectStore.prototype.put=function(){throw new DOMException('quota','QuotaExceededError');};
  try { await assert.rejects(a.decide(d,r.replayKey,r.requestId,grant)); } finally { IDBObjectStore.prototype.put=original; }
  assert.deepEqual(await a.outbox(),[]); assert.equal((await a.pending()).length,1);
  const rollback=await openFirstContactStore({...o,now:()=>now-1}); await assert.rejects(rollback.pending()); rollback.close();
  for(let i=1;i<256;i++) await a.reserve(d,{...r,replayKey:i.toString(16).padStart(64,'0')});
  await assert.rejects(a.reserve(d,{...r,replayKey:'ff'.repeat(32)})); a.close();
});

test('stored reservation projects ciphertext fields and refuses expiry and wrong request decisions', async()=>{
  const a=await openFirstContactStore(options()),d=await a.activate(policy),r=row(d);
  await assert.rejects(a.reserve(d,{...r,replayUntil:now+100}));
  await assert.rejects(a.reserve(d,{...r,envelope:new Uint8Array(8193)}));
  await a.reserve(d,{...r,message:'must not persist'});
  assert.equal('message' in (await a.pending())[0],false);
  await assert.rejects(a.decide(d,r.replayKey,'ff'.repeat(32),grant));
  await assert.rejects(a.decide(d,r.replayKey,r.requestId,{status:'accept'})); a.close();
});
