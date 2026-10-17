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
    assert.deepEqual(ids.verifyRotate(rotation,ctx.currentKey,{...ctx,links}),{ok:false,reason:'bad-record'});
    const r=ids.resolveCurrentKey(ctx.genesis,[rotation],{...ctx,links});
    assert.equal(r.ok,true);assert.equal(r.value.currentKey,ctx.genesis);assert.equal(r.diagnostics[0].reason,'bad-record');
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
