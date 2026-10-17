import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ids from '../src/index.js';
const f=JSON.parse(readFileSync(new URL('../../../vectors/ids/records.json',import.meta.url),'utf8'));
const ctx={...f.context,links:new Map(f.context.links),pinnedIss:new Set(f.context.pinnedIss),history:(p,at,until)=>({ok:true,value:ids.historyState(p,[],at,until)})};
const rotation=f.accept.find(c=>c.name==='wallet-rotate').input;
test('hostile link-map values and retained-link arrays never run getters',()=>{
  let reads=0;
  const hostile={get issuedAt(){reads++;throw Error('getter');},get principal(){reads++;throw Error('getter');}};
  for(const raw of [hostile,new Proxy({},{ownKeys(){throw Error('proxy');}})]) {
    const links=new Map([[rotation.authorizer.link,raw]]);
    assert.deepEqual(ids.verifyRotate(rotation,ctx.currentKey,{...ctx,links}),{ok:false,reason:'missing-history'});
    const r=ids.resolveCurrentKey(ctx.genesis,[rotation],{...ctx,links});
    assert.equal(r.ok,false);assert.equal(r.reason,'missing-history');assert.equal(r.diagnostics[0].reason,'missing-history');assert.equal('value' in r,false);
  }
  const retained=[];Object.defineProperty(retained,0,{get(){reads++;throw Error('getter');}});
  assert.deepEqual(ids.signingBytes({...rotation,retainedLinks:retained}),{ok:false,reason:'bad-record'});
  const revoked=Proxy.revocable([],{});revoked.revoke();
  assert.deepEqual(ids.signingBytes({...rotation,retainedLinks:revoked.proxy}),{ok:false,reason:'bad-record'});
  assert.equal(reads,0);
});
test('runtime collection checks and explicit verifier history',()=>{
  assert.throws(()=>ids.objectSoul('acl','room_'+'00'.repeat(16)),/collection/);
  const w=f.accept.find(c=>c.name==='wallet').input;
  assert.deepEqual(ids.verifyWalletLink(w,ctx.jwks,ctx.policy,ctx.now),{ok:false,reason:'missing-history'});
  assert.deepEqual(ids.verifyRotate(rotation,ctx.currentKey,{...ctx,history:undefined}),{ok:false,reason:'missing-history'});
});

test('optional revoke witness never invokes getters and history aliases stay witness-only',()=>{
  const offline=f.accept.find(c=>c.name==='offline-current-key-revoke').input;
  const w=f.accept.find(c=>c.name==='wallet').input;
  let reads=0;
  const hostile={...offline};Object.defineProperty(hostile,'attest',{enumerable:true,get(){reads++;throw Error('getter');}});
  assert.deepEqual(ids.verifyRevokeNow(hostile,ctx.currentKey,ctx.now),{ok:false,reason:'bad-record'});
  const result=ids.resolveWalletLinkNow(w.address,[w],[hostile],ctx);
  assert.equal(result.ok,true);assert.deepEqual(result.diagnostics.map(d=>d.reason),['bad-record']);
  assert.equal(reads,0);
  const historical=ids.resolveWalletLinkAtKey(w.address,[w],[offline],{...ctx,present:true});
  assert.equal(historical.ok,true);assert.deepEqual(historical.diagnostics.map(d=>d.reason),['bad-attestation']);
  assert.equal(ids.verifyRotateAtKey(rotation,ctx.currentKey,{...ctx,revocations:[offline],present:true}).ok,true);
  const present=ids.resolveWalletLinkNow(w.address,[w],[offline],ctx);
  assert.equal(present.ok,false);assert.equal(present.reason,'revoked-link');
});

test('damaged duplicate rotation proof getters cannot run or veto a valid copy',()=>{
  let reads=0;
  const damaged={...rotation,authorizer:{...rotation.authorizer,siwe:{
    get message(){reads++;throw Error('getter');},signature:'0x'+'00'.repeat(65),
  }}};
  for(const copies of [[damaged,rotation],[rotation,damaged]]) {
    const r=ids.resolveCurrentKey(ctx.genesis,copies,ctx);
    assert.equal(r.ok,true);assert.equal(r.value.currentKey,rotation.nextKey);
    assert.deepEqual(r.diagnostics.map(d=>d.reason),['missing-history']);
    assert.deepEqual(r.value.rotations,[rotation]);
  }
  assert.equal(reads,0);
});
