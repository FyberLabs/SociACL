// Shared producer/admission contracts run in CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {historyState,verifyKeySignature} from '../ids/src/index.js';
import {signMembershipAssent,signObjectSet,signGroupCancel,parseMembershipAssent,parseObjectSet,parseGroupCancel,
  membershipSoul,objectSetSoul} from '../src/group.js';
import {runGroupCase} from './group-case.js';
const vectors=JSON.parse(readFileSync(new URL('../../vectors/mesh/v2/group.json',import.meta.url)));
const keys=JSON.parse(readFileSync(new URL('../ids/test/test-keys.json',import.meta.url)));
const scalar=n=>{const key=new Uint8Array(32);key[31]=n;return key;};
const unsigned=row=>{const {sig,...draft}=row;return draft;};
const steps=vectors.accept[0].steps;
const member=unsigned(steps.find(step=>step.op==='admit-member').row);
const edge=unsigned(steps.find(step=>step.op==='admit-object-set').row);
function context(raw){return {...raw,links:new Map(raw.links??[]),pinnedIss:new Set(raw.pinnedIss??[]),
  history:(principal,from,until)=>raw.authenticatedAccounts.includes(principal)?{ok:true,value:historyState(principal,[],from,until)}:{ok:false,reason:'missing-history'}};}
test('shared producers preserve both assents and admit through the existing group contract',()=>{
  const candidate=structuredClone(steps);
  for(const step of candidate){
    if(step.op==='admit-member'){
      const role=step.row.role,n=role==='member'?2:1,pub=role==='member'?keys.p2:keys.p;
      step.row=signMembershipAssent(unsigned(step.row),scalar(n),pub);
      assert.equal(verifyKeySignature(pub,step.row.sig,parseMembershipAssent(step.row).bytes).ok,true);
    }
    if(step.op==='admit-object-set')step.row=signObjectSet(unsigned(step.row),scalar(1),keys.p);
  }
  runGroupCase(candidate,{ctx:context(vectors.context),rotations:name=>vectors.context.rotationSets[name]});
  const key=scalar(2),draft=structuredClone(member),row=signMembershipAssent(draft,key,keys.p2);
  assert.deepEqual(key,scalar(2));draft.cancels.push('a'.repeat(64));assert.deepEqual(row.cancels,[]);
  assert.ok(Object.isFrozen(row));assert.ok(Object.isFrozen(row.cancels));
  assert.equal(verifyKeySignature(keys.p,signObjectSet(edge,scalar(1),keys.p).sig,parseObjectSet({...edge,sig:''}).bytes).ok,true);
});
const cancel=kind=>({kind,rowSoul:kind==='membership'?membershipSoul(member.setOwner,member.predicate,member.set,member.member):objectSetSoul(edge.owner,edge.object,edge.predicate,edge.set),
  cancelId:'a'.repeat(64),prior:[],signer:kind==='membership'?member.member:edge.owner,predicate:member.predicate,set:member.set,
  member:member.member,setOwner:member.setOwner,issuedAt:member.issuedAt,...(kind==='object-set'?{object:edge.object}:{})});
test('current-key cancellations bind the canonical soul and retain immutable prior ids',()=>{
  for(const kind of ['membership','object-set']){
    const n=kind==='membership'?2:1,pub=kind==='membership'?keys.p2:keys.p;
    const draft=cancel(kind),row=signGroupCancel(draft,scalar(n),pub);
    assert.equal(verifyKeySignature(pub,row.sig,parseGroupCancel(row).bytes).ok,true);
    draft.prior.push('b'.repeat(64));assert.deepEqual(row.prior,[]);assert.ok(Object.isFrozen(row.prior));
    assert.throws(()=>signGroupCancel({...cancel(kind),rowSoul:'other'},scalar(n),pub));
  }
});
test('signing rejects unsupported fields, accessors, malformed drafts and mismatched keys',()=>{
  for(const [sign,draft,n,pub] of [[signMembershipAssent,member,2,keys.p2],[signObjectSet,edge,1,keys.p],[signGroupCancel,cancel('membership'),2,keys.p2]]){
    for(const bad of [null,{}, {...draft,extra:1},{...draft,sig:'injected'},{...draft,attest:'injected'},
      {...draft,predicate:'other'},{...draft,set:'bad'},{...draft,issuedAt:-1},
      Object.defineProperty({...draft},'predicate',{get(){throw Error('getter executed');}})])assert.throws(()=>sign(bad,scalar(n),pub));
    assert.throws(()=>sign(draft,scalar(n===1?2:1),pub));
    assert.throws(()=>sign(draft,scalar(n),'bad'));
  }
  assert.throws(()=>signGroupCancel(null,scalar(1),keys.p));
  assert.throws(()=>signGroupCancel({...cancel('membership'),object:edge.object},scalar(2),keys.p2));
});

test('producer cancellation lists are bounded data arrays without getter or iterator execution',()=>{
  let accessed=false;
  const getter=Object.defineProperty(['a'.repeat(64)],'0',{get(){accessed=true;return 'a'.repeat(64);}});
  const iterator=[];iterator[Symbol.iterator]=function*(){accessed=true;yield 'a'.repeat(64);};
  for(const list of [getter,iterator,new Array(1),Array(65).fill('a'.repeat(64)),[1],null])
    assert.throws(()=>signMembershipAssent({...member,cancels:list},scalar(2),keys.p2));
  assert.equal(accessed,false);
  const prior=['b'.repeat(64)];
  const row=signGroupCancel({...cancel('membership'),prior},scalar(2),keys.p2);
  prior.length=0;assert.equal(row.prior.length,1);
});
