import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { parsePrincipalId,signWithKeyring,historyState,type PrincipalId,type ResolutionContext } from '../ids/src/index.js';
import { seaPoint } from '../contract/account-key-seal.ts';
import { verifyIndependentWitnesses,witnessRequestBytes,witnessReceiptBytes,
  type IndependentWitnessPolicy,type WitnessRequest,type WitnessReceipt } from '../contract/independent-witness.ts';
const scalar=(n:number)=>{const b=new Uint8Array(32);b[31]=n;return b;};
const pub=(n:number)=>{const p=parsePrincipalId(seaPoint(scalar(n)));if(!p.ok)throw Error(p.reason);return p.value;};
const records=JSON.parse(readFileSync(new URL('../../vectors/ids/records.json',import.meta.url),'utf8'));
const context:ResolutionContext={...records.context,now:1700000020,links:new Map(),pinnedIss:new Set(),
  history:(p:PrincipalId,at:number,until:number)=>({ok:true,value:historyState(p,[],at,until)})};
const policy:IndependentWitnessPolicy={id:'12'.repeat(32),epoch:1,threshold:3,maxFaulty:1,
  operators:[2,3,4,5].map(n=>({id:`operator-${n}`,keys:[{key:pub(n),notBefore:1699990000,notAfter:1700010000}]}))};
const signed=(change:Partial<WitnessRequest>={}):WitnessRequest=>{
  const r={v:1 as const,principal:pub(1),operation:'rotate' as const,recordDigest:'34'.repeat(32),policyId:policy.id,
    epoch:1,issuedAt:1700000000,expiresAt:1700000300,sig:'',...change};
  const s=signWithKeyring(scalar(1),witnessRequestBytes(r),r.principal);if(!s.ok)throw Error(s.reason);return {...r,sig:s.value};
};
const receipt=(r:WitnessRequest,n:number):WitnessReceipt=>{
  const operator=`operator-${n}`,observedAt=1700000010;
  const s=signWithKeyring(scalar(n),witnessReceiptBytes(r,operator,observedAt),pub(n));if(!s.ok)throw Error(s.reason);
  return {operator,observedAt,sig:s.value};
};
const verify=(r:WitnessRequest,rows:WitnessReceipt[],p=policy)=>verifyIndependentWitnesses(r,rows,p,r.recordDigest,[],context);

test('independent receipts tolerate one outage and never replace an account signature',()=>{
  const r=signed(),rows=[2,3,4].map(n=>receipt(r,n));
  const result=verify(r,rows);assert.ok(result.ok);if(!result.ok)return;
  assert.equal(result.value.timestampUpperBound,1700000010);assert.equal('allowed' in result.value,false);
  assert.equal(verify({...r,sig:'A'.repeat(86)},rows).ok,false);
  assert.equal(verify(r,rows.slice(0,2)).ok,false);
  assert.equal(verify(r,[rows[0]!,rows[0]!,rows[1]!]).ok,false);
  assert.equal(verify(r,[...rows.slice(0,2),receipt(signed({recordDigest:'ab'.repeat(32)}),4)]).ok,false);
  assert.equal(verify(r,[...rows.slice(0,2),receipt(signed({epoch:2}),4)]).ok,false);
  assert.equal(verifyIndependentWitnesses(r,rows,policy,'cd'.repeat(32),[],context).ok,false);
});

test('operator aliases, account-as-witness and unsafe fork thresholds fail closed',()=>{
  const r=signed(),rows=[2,3,4].map(n=>receipt(r,n));
  const alias={...policy,operators:policy.operators.map((op,i)=>i===3?{id:'operator-5',keys:policy.operators[0]!.keys}:op)};
  assert.equal(verify(r,rows,alias).ok,false);
  const reused={...policy,operators:policy.operators.map((op,i)=>i===3?{id:'operator-5',keys:[{key:pub(1),notBefore:0,notAfter:1700010000}]}:op)};
  assert.equal(verify(r,rows,reused).ok,false);
  const twoOfThree={...policy,threshold:2,operators:policy.operators.slice(0,3)};
  assert.equal(verify(r,rows.slice(0,2),twoOfThree).ok,false);
  const revoke=signed({operation:'revoke'});
  assert.ok(verify(revoke,[2,3].map(n=>receipt(revoke,n)),twoOfThree).ok);
  assert.equal(verify(r,rows,{...policy,threshold:1}).ok,false);
});

test('witness issuance windows, future times and missing account history are rejected',()=>{
  const r=signed(),rows=[2,3,4].map(n=>receipt(r,n));
  const expired={...policy,operators:policy.operators.map(op=>({...op,keys:op.keys.map(k=>({...k,notAfter:1700000010}))}))};
  assert.equal(verify(r,rows,expired).ok,false);
  assert.equal(verify(r,[{...rows[0]!,observedAt:context.now+1},...rows.slice(1)]).ok,false);
  assert.equal(verifyIndependentWitnesses(r,rows,policy,r.recordDigest,[],{...context,history:()=>({ok:false,reason:'missing-history'})}).ok,false);
  assert.equal(verifyIndependentWitnesses(r,rows,policy,r.recordDigest,[],{...context,now:r.expiresAt}).ok,false);
});


test('receipt parsing bounds arrays before crypto and never invokes accessors',()=>{
  const r=signed(),rows=[2,3,4].map(n=>receipt(r,n));let reads=0;
  const hostile={...r};Object.defineProperty(hostile,'recordDigest',{get(){reads++;throw Error('getter');}});
  assert.equal(verifyIndependentWitnesses(hostile,rows,policy,r.recordDigest,[],context).ok,false);assert.equal(reads,0);
  assert.equal(verify(r,new Array(1000)).ok,false);
  for(const suffix of ['\n','\r']) {
    const malformed={...policy,operators:policy.operators.map((op,i)=>i===0?{...op,id:op.id+suffix}:op)};
    assert.equal(verify(r,rows,malformed).ok,false);
  }
  assert.equal(verify(r,[...rows,{...rows[0]!,extra:true}] as WitnessReceipt[]).ok,false);
  const getters=[...rows];Object.defineProperty(getters,'0',{get(){reads++;return rows[0];}});
  assert.equal(verify(r,getters).ok,false);assert.equal(reads,0);
});

test('shared witness transcripts, rejection fixtures and Rust signatures agree',()=>{
  const v=JSON.parse(readFileSync(new URL('../../vectors/independent-witness/v1.json',import.meta.url),'utf8'));
  const request=signed(v.request),rows=[2,3,4].map(n=>receipt(request,n));
  const fields=v.requestFields.map((s:string)=>{const b=Buffer.from(s),n=Buffer.alloc(4);n.writeUInt32LE(b.length);return Buffer.concat([n,b]);});
  assert.deepEqual(Buffer.from(witnessRequestBytes(request)),Buffer.concat(fields));
  for(const patch of v.rejectRequestPatches)assert.equal(verifyIndependentWitnesses({...request,...patch},rows,policy,request.recordDigest,[],context).ok,false);
  for(const patch of v.rejectPolicyPatches)assert.equal(verify(request,rows,{...policy,...patch}).ok,false);
  const own=verify(request,rows);assert.ok(own.ok);if(!own.ok)return;
  const next={...policy,epoch:2},digest=independentWitnessTransitionDigest(policy,next);
  const oldRequest=signed({recordDigest:digest}),newRequest=signed({recordDigest:digest,epoch:2});
  const transition={digest,next,oldRequest,newRequest,oldReceipts:[2,3,4].map(n=>receipt(oldRequest,n)),newReceipts:[2,3,4].map(n=>receipt(newRequest,n))};
  if(process.env.WITNESS_RUST_VECTOR){
    const rust=JSON.parse(readFileSync(process.env.WITNESS_RUST_VECTOR,'utf8'));
    assert.deepEqual(rust.policy,policy);
    assert.equal(rust.transition.digest,digest);
    const t=rust.transition;
    assert.deepEqual(advanceIndependentWitnessPolicy(policy,t.next,pub(1),t.oldRequest,t.oldReceipts,t.newRequest,t.newReceipts,[],context),next);
    const checked=verifyIndependentWitnesses(rust.request,rust.receipts,policy,request.recordDigest,[],context);
    assert.ok(checked.ok);if(checked.ok)assert.deepEqual(checked.value,rust.result);
  }
  if(process.env.WITNESS_TS_VECTOR)writeFileSync(process.env.WITNESS_TS_VECTOR,JSON.stringify({request,receipts:rows,result:own.value,transition}));
});

import { collectIndependentWitnesses, type WitnessTransport } from '../contract/independent-witness-client.ts';
test('collection survives one hanging operator, binds operators and never weakens quorum',async()=>{
  const r=signed();let aborted=false;
  const transports=new Map<string,WitnessTransport>([2,3,4].map(n=>[`operator-${n}`,async request=>receipt(request,n)]));
  transports.set('operator-5',async(_,signal)=>{signal.addEventListener('abort',()=>{aborted=true;});return new Promise(()=>{});});
  const result=await collectIndependentWitnesses(r,r.recordDigest,[],()=>policy,()=>context,transports,100);
  assert.equal(aborted,true);assert.deepEqual(result.observation.operators,['operator-2','operator-3','operator-4']);
  transports.set('operator-4',async request=>receipt(request,2));
  await assert.rejects(collectIndependentWitnesses(r,r.recordDigest,[],()=>policy,()=>context,transports,100));
});
test('collection rejects before sending forged account intent and rechecks expiry and policy after replies',async()=>{
  const r=signed();let calls=0,changed=false;
  const transports=new Map<string,WitnessTransport>([2,3,4,5].map(n=>[`operator-${n}`,async request=>{calls++;changed=true;return receipt(request,n);} ]));
  await assert.rejects(collectIndependentWitnesses({...r,sig:'A'.repeat(86)},r.recordDigest,[],()=>policy,()=>context,transports));
  assert.equal(calls,0);
  await assert.rejects(collectIndependentWitnesses(r,r.recordDigest,[],()=>policy,()=>changed?{...context,now:r.expiresAt}:context,transports));
  changed=false;
  await assert.rejects(collectIndependentWitnesses(r,r.recordDigest,[],()=>changed?{...policy,epoch:2}:policy,()=>context,transports));
  changed=false;
  await assert.rejects(collectIndependentWitnesses(r,r.recordDigest,[],()=>policy,()=>changed?{...context,now:context.now-1}:context,transports));
});

test('collection detects rollback when the provider mutates a shared context',async()=>{
  const r=signed(), shared={...context};
  const transports=new Map<string,WitnessTransport>([2,3,4,5].map(n=>[`operator-${n}`,async request=>{
    shared.now=context.now-1;
    return receipt(request,n);
  }]));
  await assert.rejects(collectIndependentWitnesses(r,r.recordDigest,[],()=>policy,()=>shared,transports),/clock rollback/);
});

import { advanceIndependentWitnessPolicy, independentWitnessTransitionDigest } from '../contract/independent-witness-transition.ts';
test('policy changes require account intent and both old and new rotation quorums',()=>{
  const next={...policy,epoch:2};
  const digest=independentWitnessTransitionDigest(policy,next);
  const old=signed({recordDigest:digest}), fresh=signed({recordDigest:digest,epoch:2});
  const rows=(r:WitnessRequest)=>[2,3,4].map(n=>receipt(r,n));
  const advance=(p=next,a=old,b=fresh,oldRows=rows(a),newRows=rows(b))=>
    advanceIndependentWitnessPolicy(policy,p,pub(1),a,oldRows,b,newRows,[],context);
  assert.deepEqual(advance(),next);
  assert.throws(()=>advance(next,old,fresh,rows(old).slice(0,2)));
  assert.throws(()=>advance(next,old,fresh,rows(old),rows(fresh).slice(0,2)));
  assert.throws(()=>advance({...next,epoch:3}));
  assert.throws(()=>advance({...next,threshold:2}));
  assert.throws(()=>advance(next,{...old,sig:'A'.repeat(86)}));
  assert.throws(()=>advance(next,signed({recordDigest:digest,operation:'revoke'})));
  assert.throws(()=>advanceIndependentWitnessPolicy(policy,next,pub(2),old,rows(old),fresh,rows(fresh),[],context));
  assert.equal(independentWitnessTransitionDigest({...policy,operators:[...policy.operators].reverse()},next),digest);
  assert.notEqual(independentWitnessTransitionDigest(policy,{...next,operators:next.operators.slice(0,3)}),digest);
});

test('transition parsing never invokes request accessors',()=>{
  const next={...policy,epoch:2}, digest=independentWitnessTransitionDigest(policy,next);
  const old=signed({recordDigest:digest}), fresh=signed({recordDigest:digest,epoch:2});let reads=0;
  const hostile={...old};Object.defineProperty(hostile,'principal',{get(){reads++;throw Error('getter');}});
  assert.throws(()=>advanceIndependentWitnessPolicy(policy,next,pub(1),hostile,[],fresh,[],[],context));
  assert.equal(reads,0);
});

import { createRequire } from 'node:module';
import { openIndependentWitnessPolicyStore } from '../contract/independent-witness-store.ts';
test('joint policy installation retains its exact floor across reopen and competing transitions',async()=>{
  const {IDBFactory,IDBObjectStore}=createRequire(new URL('../ids/package.json',import.meta.url))('fake-indexeddb');
  const options={name:'independent-membership',principal:pub(1),anchor:policy,now:()=>context.now,indexedDB:new IDBFactory()};
  await assert.rejects(openIndependentWitnessPolicyStore(options));
  const a=await openIndependentWitnessPolicyStore({...options,create:true}),b=await openIndependentWitnessPolicyStore(options);
  const next={...policy,epoch:2},alternate={...next,operators:policy.operators.map(op=>({...op,keys:op.keys.map(k=>({...k,notAfter:k.notAfter+1}))}))};
  const advance=(store:typeof a,p:IndependentWitnessPolicy)=>{
    const digest=independentWitnessTransitionDigest(policy,p),old=signed({recordDigest:digest}),fresh=signed({recordDigest:digest,epoch:2});
    return store.advance(policy,p,old,[2,3,4].map(n=>receipt(old,n)),fresh,[2,3,4].map(n=>receipt(fresh,n)),()=>({rotations:[],context}));
  };
  const original=IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put=function(){throw Error('commit failed');};
  try{await assert.rejects(advance(a,next));}finally{IDBObjectStore.prototype.put=original;}
  assert.deepEqual(await a.read(policy),policy);
  const attempts=await Promise.allSettled([advance(a,next),advance(b,alternate)]);
  assert.equal(attempts.filter(r=>r.status==='fulfilled').length,1);
  const winner=attempts[0]!.status==='fulfilled'?next:alternate;
  a.close();b.close();
  const reopened=await openIndependentWitnessPolicyStore(options);
  assert.deepEqual(await reopened.read(winner),winner);
  await assert.rejects(reopened.read(policy));
  await assert.rejects(reopened.read(winner===next?alternate:next));
  await assert.rejects(advance(reopened,winner)); // Lost-response reconciliation uses read(exact candidate).
  reopened.close();
});

test('collection accepts reordered policy bytes restored under the same canonical floor',async()=>{
  const r=signed();let changed=false;
  const transports=new Map<string,WitnessTransport>([2,3,4,5].map(n=>[`operator-${n}`,async request=>{changed=true;return receipt(request,n);} ]));
  const observed=await collectIndependentWitnesses(r,r.recordDigest,[],()=>changed?{...policy,operators:[...policy.operators].reverse()}:policy,()=>context,transports);
  assert.equal(observed.observation.epoch,policy.epoch);
  assert.deepEqual(observed.observation.operators,['operator-2','operator-3','operator-4','operator-5']);
});

test('retained-policy collection rejects concurrent membership change and stale policy before sending',async()=>{
  const {IDBFactory}=createRequire(new URL('../ids/package.json',import.meta.url))('fake-indexeddb');
  const options={name:'collection-floor',principal:pub(1),anchor:policy,now:()=>context.now,indexedDB:new IDBFactory()};
  const a=await openIndependentWitnessPolicyStore({...options,create:true}),b=await openIndependentWitnessPolicyStore(options);
  const r=signed(),state=()=>({rotations:[],context});let calls=0;
  const next={...policy,epoch:2},digest=independentWitnessTransitionDigest(policy,next);
  const old=signed({recordDigest:digest}),fresh=signed({recordDigest:digest,epoch:2});
  let transition:Promise<unknown>|undefined;
  const transports=new Map<string,WitnessTransport>([2,3,4,5].map(n=>[`operator-${n}`,async request=>{
    calls++;transition??=b.advance(policy,next,old,[2,3,4].map(n=>receipt(old,n)),fresh,[2,3,4].map(n=>receipt(fresh,n)),state);
    await transition;return receipt(request,n);
  }]));
  await assert.rejects(a.collect(r,r.recordDigest,policy,state,transports));
  assert.equal(calls,4);assert.deepEqual(await a.read(next),next);
  await assert.rejects(a.collect(r,r.recordDigest,policy,state,transports));assert.equal(calls,4);
  const current=signed({epoch:2});
  const good=new Map<string,WitnessTransport>([2,3,4,5].map(n=>[`operator-${n}`,async request=>receipt(request,n)]));
  assert.equal((await a.collect(current,current.recordDigest,next,state,good)).observation.epoch,2);
  await assert.rejects(a.collect({...current,principal:pub(2)},current.recordDigest,next,state,good));
  a.close();b.close();
});
