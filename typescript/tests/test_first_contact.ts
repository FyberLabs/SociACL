import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { test } from 'node:test';
import { parsePrincipalId, signWithKeyring, historyState, type ResolutionContext } from '../ids/src/index.js';
import { firstContactRequestBytes, parseFirstContactRequest, verifyFirstContactRequest,
  type FirstContactRequest } from '../contract/first-contact.ts';
import { sealFirstContactRequest, openFirstContactRequest } from '../contract/first-contact-seal.ts';
const vectors = JSON.parse(readFileSync(new URL('../../vectors/first-contact/v1.json', import.meta.url), 'utf8'));
const records = JSON.parse(readFileSync(new URL('../../vectors/ids/records.json', import.meta.url), 'utf8'));
const raw = vectors.request;
const ctx: ResolutionContext = { ...records.context, now: raw.issuedAt + 20,
  links: new Map(records.context.links), pinnedIss: new Set(records.context.pinnedIss),
  history: (p, at, until) => ({ ok: true, value: historyState(p, [], at, until) }) };
function signed(patch: Partial<FirstContactRequest> = {}, scalar = 1): FirstContactRequest {
  const request = { ...raw, ...patch };
  const sender = parsePrincipalId(raw.sender); assert.equal(sender.ok, true);
  if (!sender.ok) throw Error('fixture principal');
  const key = new Uint8Array(32); key[31] = scalar;
  const result = signWithKeyring(key, firstContactRequestBytes(request), sender.value);
  if (!result.ok) throw Error(result.reason);
  return { ...request, sig: result.value };
}
const verify = (input: unknown, descriptor = vectors.descriptor, context = ctx) =>
  verifyFirstContactRequest(input, [], context, descriptor);

test('first contact shared canonical bytes preserve exact message and disclose no lane', () => {
  const request = signed();
  assert.equal(Buffer.from(firstContactRequestBytes(request)).toString('hex'), vectors.signingBytesHex);
  const result = verify(request); assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.requestId, vectors.requestId);
  assert.equal(result.value.replayKey, vectors.replayKey);
  assert.equal(result.value.request.message, raw.message);
  assert.deepEqual(Object.keys(result.value).sort(), ['replayKey', 'replayUntil', 'request', 'requestId']);
  assert.equal('allowed' in result.value, false);
  assert.equal('laneId' in result.value, false);
});

test('first contact binds every field and refuses wrong channel, revision, key and expiry', () => {
  const request = signed();
  for (const patch of [{ channelId: 'cd'.repeat(32) }, { descriptorRevision: 2 },
    { replyEpub: raw.sender }, { sender: raw.replyEpub }, { nonce: 'ef'.repeat(32) },
    { issuedAt: raw.issuedAt - 1 }, { expiresAt: raw.expiresAt - 1 }, { message: 'tampered' }]) {
    assert.equal(verify({ ...request, ...patch }).ok, false);
  }
  assert.equal(verify(request, { ...vectors.descriptor, revision: 2 }).ok, false);
  assert.equal(verify(request, vectors.descriptor, { ...ctx, now: raw.expiresAt }).ok, false);
  assert.equal(verify(request, vectors.descriptor, { ...ctx, now: raw.issuedAt - 1 }).ok, false);
  assert.equal(verify(request, { ...vectors.descriptor, maxLifetimeSeconds: 1 }).ok, false);
  assert.equal(verify(request, { ...vectors.descriptor, maxMessageBytes: 1 }).ok, false);
});

test('first contact replay key cannot change by re-signing or changing the message', () => {
  const a = verify(signed()), b = verify(signed({ message: 'different' }));
  assert.equal(a.ok, true); assert.equal(b.ok, true);
  if (!a.ok || !b.ok) return;
  assert.equal(a.value.replayKey, b.value.replayKey);
  assert.notEqual(a.value.requestId, b.value.requestId);
  const shorter = verify(signed({ expiresAt: ctx.now + 1 }));
  assert.equal(shorter.ok, true);
  if (!shorter.ok) return;
  assert.equal(shorter.value.replayKey, a.value.replayKey);
  assert.equal(shorter.value.replayUntil, vectors.descriptor.expiresAt);
  assert.equal(a.value.replayUntil, shorter.value.replayUntil);
  const reservations = new Map([[shorter.value.replayKey, shorter.value.replayUntil]]);
  const laterTime = ctx.now + 2; // The first request expired one second earlier.
  const later = verify(signed(), vectors.descriptor, { ...ctx, now: laterTime });
  assert.equal(later.ok, true);
  if (!later.ok) return;
  assert.ok((reservations.get(later.value.replayKey) ?? 0) > laterTime,
    'the descriptor deadline still blocks the later signed nonce reuse');
});

test('first contact parser rejects coercions, getters, malformed unicode and oversized messages', () => {
  const request = signed(); let reads = 0;
  const hostile = { ...request };
  Object.defineProperty(hostile, 'message', { get() { reads++; throw Error('getter'); } });
  assert.equal(parseFirstContactRequest(hostile).ok, false); assert.equal(reads, 0);
  for (const patch of [{ extra: true }, { descriptorRevision: '1' }, { issuedAt: -0 },
    { message: '\ud800' }, { message: 'é'.repeat(2049) }, { nonce: 'AB'.repeat(32) },
    { replyEpub: 'https://attacker.example' }, { sig: '' },
    { channelId: request.channelId + '\n' }, { nonce: request.nonce + '\n' }, { sig: request.sig + '\n' }]) {
    assert.equal(parseFirstContactRequest({ ...request, ...patch }).ok, false);
  }
  assert.equal(verify(request, vectors.descriptor, { ...ctx, history: () => ({ ok: false, reason: 'missing-history' }) }).ok, false);
});

test('first contact does not accept a retired sender key', () => {
  const rotation = records.accept.find((row: { name: string }) => row.name === 'wallet-rotate').input;
  const request = signed({ issuedAt: rotation.issuedAt - 1, expiresAt: ctx.now + 100 });
  const result = verifyFirstContactRequest(request, [rotation], { ...ctx, now: records.context.now },
    { ...vectors.descriptor, expiresAt: ctx.now + 200, maxLifetimeSeconds: 86400 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'unwitnessed-retired-key');
});


test('confidential first contact authenticates after opening and never returns a grant', () => {
  const descriptor = { ...vectors.descriptor, encryptionEpub: raw.replyEpub };
  const scalar = Buffer.alloc(32); scalar[31] = 2;
  const privateKey = scalar.toString('base64url');
  const request = signed();
  const envelope = sealFirstContactRequest(request, descriptor);
  assert.notDeepEqual(envelope, sealFirstContactRequest(request, descriptor));
  for (const secret of [request.sender, request.replyEpub, request.sig, request.message, request.nonce]) {
    assert.equal(Buffer.from(envelope).includes(Buffer.from(secret)), false);
  }
  if (process.env.FIRST_CONTACT_RUST_VECTOR) {
    const rust = openFirstContactRequest(readFileSync(process.env.FIRST_CONTACT_RUST_VECTOR), privateKey, descriptor, [], ctx);
    assert.equal(rust.ok, true);
    if (rust.ok) {
      assert.equal(rust.value.requestId, vectors.requestId);
      assert.equal(rust.value.replayKey, vectors.replayKey);
      assert.equal(rust.value.replayUntil, descriptor.expiresAt);
      assert.equal(rust.value.request.message, request.message);
    }
  }
  if (process.env.FIRST_CONTACT_TS_VECTOR) writeFileSync(process.env.FIRST_CONTACT_TS_VECTOR, envelope);
  const opened = openFirstContactRequest(envelope, privateKey, descriptor, [], ctx);
  assert.deepEqual(opened, verify(request));
  for (const offset of [0, 1, 20, 66, 78, envelope.length - 1]) {
    const tampered = new Uint8Array(envelope); tampered[offset] = (tampered[offset] ?? 0) ^ 1;
    assert.equal(openFirstContactRequest(tampered, privateKey, descriptor, [], ctx).ok, false);
  }
  for (const patch of [{ revision: 2 }, { channelId: 'ab'.repeat(32) }, { encryptionEpub: raw.sender }]) {
    assert.equal(openFirstContactRequest(envelope, privateKey, { ...descriptor, ...patch }, [], ctx).ok, false);
  }
  scalar[31] = 3;
  assert.equal(openFirstContactRequest(envelope, scalar.toString('base64url'), descriptor, [], ctx).ok, false);
  for (const blob of [envelope.slice(0, -1), new Uint8Array(8193), new Uint8Array(93)]) {
    assert.equal(openFirstContactRequest(blob, privateKey, descriptor, [], ctx).ok, false);
  }
  assert.equal(openFirstContactRequest(envelope, privateKey, descriptor, [], { ...ctx, now: raw.expiresAt }).ok, false);
  assert.equal(openFirstContactRequest(envelope, privateKey, descriptor, [],
    { ...ctx, history: () => ({ ok: false, reason: 'missing-history' }) }).ok, false);
  const bom = signed({ message: '\uFEFFhello' });
  assert.deepEqual(openFirstContactRequest(sealFirstContactRequest(bom, descriptor), privateKey,
    descriptor, [], ctx), verify(bom));
  const forged = sealFirstContactRequest({ ...request, message: 'forged' }, descriptor);
  assert.equal(openFirstContactRequest(forged, privateKey, descriptor, [], ctx).ok, false);
});

// Durable discovery observation is distinct from recipient inbox admission.
import { createRequire } from 'node:module';
import { firstContactDescriptorBytes } from '../contract/first-contact-descriptor.ts';
import { openFirstContactFloor } from '../ids/src/first-contact-floor.js';
import { firstContactDescriptorFloor, observeFirstContactDescriptor } from '../contract/first-contact-discovery.ts';
test('discovery authenticates before committing floors and refuses a signed same-revision fork',async()=>{
  const { IDBFactory } = createRequire(new URL('../ids/package.json', import.meta.url))('fake-indexeddb');
  const signDescriptor=(descriptor:any)=>{
    const value={v:1 as const,owner:raw.sender,issuedAt:ctx.now,descriptor};
    const key=new Uint8Array(32);key[31]=1;
    const signature=signWithKeyring(key,firstContactDescriptorBytes(value),raw.sender);
    if(!signature.ok)throw Error(signature.reason);
    return {...value,sig:signature.value};
  };
  const descriptor={...vectors.descriptor,encryptionEpub:raw.replyEpub};
  const signed=signDescriptor(descriptor);
  const store=await openFirstContactFloor({name:'discovery',owner:raw.sender,
    anchor:firstContactDescriptorFloor(signed),now:()=>ctx.now,create:true,indexedDB:new IDBFactory()});
  assert.deepEqual(await observeFirstContactDescriptor(signed,raw.sender,store,[],ctx),signed);
  const newer=signDescriptor({...descriptor,revision:descriptor.revision+1});
  await assert.rejects(observeFirstContactDescriptor({...newer,sig:'A'.repeat(86)},raw.sender,store,[],ctx));
  assert.deepEqual(await store.read(),firstContactDescriptorFloor(signed));
  await observeFirstContactDescriptor(newer,raw.sender,store,[],ctx);
  await assert.rejects(observeFirstContactDescriptor(signed,raw.sender,store,[],ctx));
  const fork=signDescriptor({...newer.descriptor,channelId:'ef'.repeat(32)});
  await assert.rejects(observeFirstContactDescriptor(fork,raw.sender,store,[],ctx));
  await assert.rejects(observeFirstContactDescriptor(newer,raw.sender,store,[],{...ctx,history:()=>({ok:false,reason:'missing-history'})}));
  store.close();
});

import { createHash } from 'node:crypto';
import { pollFirstContact } from '../contract/first-contact-poll.ts';
import type { FirstContactStore } from '../ids/src/first-contact-store.js';
test('public polling authenticates ciphertext and commits replay state before disclosure',async()=>{
  const descriptor={...vectors.descriptor,encryptionEpub:raw.replyEpub};
  const scalar=Buffer.alloc(32);scalar[31]=2;const privateKey=scalar.toString('base64url');
  const ciphertext=sealFirstContactRequest(signed(),descriptor);
  const forged=sealFirstContactRequest({...signed(),message:'forged'},descriptor);
  const row=(ciphertext:Uint8Array)=>({id:createHash('sha256').update(ciphertext).digest('hex'),ciphertext});
  const seen=new Set<string>();let writes=0,fail=false,expired=false,disabled=false;
  const store:FirstContactStore={owner:raw.sender,descriptor:async()=>{if(disabled)throw Error('disabled');return descriptor;},
    reserve:async(_d:unknown,r:{replayKey:string})=>{
      if(fail)throw Error('commit failed');if(seen.has(r.replayKey))return false;
      writes++;seen.add(r.replayKey);return true;
    },activate:async()=>{throw Error('unexpected activation');},disable:async()=>{disabled=true;},
    pending:async()=>[],decide:async()=>{throw Error('polling must not decide');},outbox:async()=>[],
    acknowledge:async()=>{throw Error('polling must not acknowledge');},close:()=>{}};
  const state=()=>({rotations:[],context:{...ctx,now:expired?raw.expiresAt:ctx.now}});
  const source=async(channel:string)=>{assert.equal(channel,descriptor.channelId);return [row(forged),row(ciphertext),row(ciphertext)];};
  const result=await pollFirstContact(store,source,privateKey,state);
  assert.equal(writes,1);assert.equal(result.length,1);assert.equal(result[0]!.request.message,raw.message);
  assert.deepEqual(await pollFirstContact(store,source,privateKey,state),[]);
  seen.clear();fail=true;await assert.rejects(pollFirstContact(store,source,privateKey,state),/commit failed/);
  fail=false;
  const reserve=store.reserve;store.reserve=async(...args)=>{const added=await reserve(...args);expired=true;return added;};
  assert.deepEqual(await pollFirstContact(store,source,privateKey,state),[]);
  assert.equal(seen.size,1);
  expired=false;seen.clear();store.reserve=async(...args)=>{const added=await reserve(...args);disabled=true;return added;};
  await assert.rejects(pollFirstContact(store,source,privateKey,state),/disabled/);
  disabled=false;store.reserve=reserve;
  let clockCalls=0;
  await assert.rejects(pollFirstContact(store,async()=>[row(ciphertext)],privateKey,()=>({rotations:[],context:{...ctx,now:++clockCalls===2?ctx.now-1:ctx.now}})),/clock rollback/);

  await assert.rejects(pollFirstContact(store,async()=>[{...row(ciphertext),id:'00'.repeat(32)}],privateKey,state),/digest/);
  await assert.rejects(pollFirstContact(store,async()=>new Array(129),privateKey,state),/batch/);
  let aborted=false;
  await assert.rejects(pollFirstContact(store,async(_,signal)=>{signal.addEventListener('abort',()=>{aborted=true;});return new Promise(()=>{});},privateKey,state,5),/timeout/);
  assert.equal(aborted,true);
});

import { sealFirstContactRequestBrowser,openFirstContactRequestBrowser } from '../contract/first-contact-browser.ts';
test('WebCrypto interoperates with Node and Rust and rechecks time after decryption',async()=>{
  const descriptor={...vectors.descriptor,encryptionEpub:raw.replyEpub};
  const scalar=Buffer.alloc(32);scalar[31]=2;const privateKey=scalar.toString('base64url');
  const request=signed(), state=()=>({rotations:[],context:ctx});
  const browser=await sealFirstContactRequestBrowser(request,descriptor);
  assert.ok(openFirstContactRequest(browser,privateKey,descriptor,[],ctx).ok);
  assert.ok((await openFirstContactRequestBrowser(sealFirstContactRequest(request,descriptor),privateKey,descriptor,state)).ok);
  if(process.env.FIRST_CONTACT_RUST_VECTOR)assert.ok((await openFirstContactRequestBrowser(readFileSync(process.env.FIRST_CONTACT_RUST_VECTOR),privateKey,descriptor,state)).ok);
  if(process.env.FIRST_CONTACT_TS_VECTOR)writeFileSync(process.env.FIRST_CONTACT_TS_VECTOR,browser);
  assert.notDeepEqual(browser,await sealFirstContactRequestBrowser(request,descriptor));
  const tampered=new Uint8Array(browser);tampered[tampered.length-1]=tampered[tampered.length-1]!^1;
  assert.equal((await openFirstContactRequestBrowser(tampered,privateKey,descriptor,state)).ok,false);
  let calls=0;
  assert.equal((await openFirstContactRequestBrowser(browser,privateKey,descriptor,()=>({rotations:[],context:{...ctx,now:++calls===1?ctx.now:raw.expiresAt}}))).ok,false);
  calls=0;
  assert.equal((await openFirstContactRequestBrowser(browser,privateKey,descriptor,()=>({rotations:[],context:{...ctx,now:++calls===1?ctx.now:ctx.now-1}}))).ok,false);
  const change={...descriptor};const opening=openFirstContactRequestBrowser(browser,privateKey,change,state);change.revision++;
  assert.ok((await opening).ok); // Decryption binds the immutable start snapshot.
});

import { prepareFirstContactSubmission } from '../contract/first-contact-send.ts';
test('sender retries exact encrypted bytes and checks signed descriptor floors before transport',async()=>{
  const { IDBFactory }=createRequire(new URL('../ids/package.json',import.meta.url))('fake-indexeddb');
  const descriptor={...vectors.descriptor,encryptionEpub:raw.replyEpub};
  const signDescriptor=(d:typeof descriptor)=>{
    const candidate={v:1 as const,owner:raw.sender,issuedAt:ctx.now,descriptor:d};
    const key=new Uint8Array(32);key[31]=1;
    const s=signWithKeyring(key,firstContactDescriptorBytes(candidate),raw.sender);if(!s.ok)throw Error(s.reason);
    return {...candidate,sig:s.value};
  };
  const advertisement=signDescriptor(descriptor);let now=ctx.now;
  const floor=await openFirstContactFloor({name:'send',owner:raw.sender,anchor:firstContactDescriptorFloor(advertisement),
    now:()=>now,create:true,indexedDB:new IDBFactory()});
  const state=()=>({rotations:[],context:{...ctx,now}});
  let calls=0;const transmitted:Uint8Array[]=[];
  await assert.rejects(prepareFirstContactSubmission(signed(),{...advertisement,sig:'A'.repeat(86)},raw.sender,floor,state,state));
  const prepared=await prepareFirstContactSubmission(signed(),advertisement,raw.sender,floor,state,state);
  await assert.rejects(prepared.submit(async(channel,body)=>{
    calls++;assert.equal(channel,descriptor.channelId);transmitted.push(new Uint8Array(body));body.fill(0);throw Error('lost response');
  }));
  assert.equal(await prepared.submit(async(channel,body)=>{calls++;transmitted.push(body);return prepared.ciphertextId;}),prepared.ciphertextId);
  assert.deepEqual(transmitted[0],transmitted[1]);assert.equal(calls,2);
  const key=Buffer.alloc(32);key[31]=2;
  assert.equal(openFirstContactRequest(transmitted[1]!,key.toString('base64url'),descriptor,[],ctx).ok,true);
  await assert.rejects(prepared.submit(async()=> '00'.repeat(32)));
  const next=signDescriptor({...descriptor,revision:descriptor.revision+1});
  await observeFirstContactDescriptor(next,raw.sender,floor,[],ctx);
  await assert.rejects(prepared.submit(async()=>{calls++;return prepared.ciphertextId;}));
  assert.equal(calls,2);floor.close();
});

test('sender deadline aborts transport and expiry refuses retry without a new write',async()=>{
  const { IDBFactory }=createRequire(new URL('../ids/package.json',import.meta.url))('fake-indexeddb');
  const descriptor={...vectors.descriptor,encryptionEpub:raw.replyEpub};
  const candidate={v:1 as const,owner:raw.sender,issuedAt:ctx.now,descriptor};
  const key=new Uint8Array(32);key[31]=1;
  const s=signWithKeyring(key,firstContactDescriptorBytes(candidate),raw.sender);if(!s.ok)throw Error(s.reason);
  const advertisement={...candidate,sig:s.value};let now=ctx.now;
  const floor=await openFirstContactFloor({name:'send-expiry',owner:raw.sender,anchor:firstContactDescriptorFloor(advertisement),now:()=>now,create:true,indexedDB:new IDBFactory()});
  const state=()=>({rotations:[],context:{...ctx,now}});
  const prepared=await prepareFirstContactSubmission(signed(),advertisement,raw.sender,floor,state,state);
  let signal:AbortSignal|undefined;
  await assert.rejects(prepared.submit(async(_channel,_body,s)=>{signal=s;return new Promise(()=>{});},10));
  assert.equal(signal?.aborted,true);
  now=raw.expiresAt;
  await assert.rejects(prepared.submit(async()=>{throw Error('must not transport expired request');}));
  floor.close();
});
