// Signature and native transcript contracts: CI only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { signPrivateMediaGrant, signPrivateMediaEpoch, signPrivateMediaFinalization, signPrivateMediaStatus } from '../contract/private-media.ts';
const {p:owner,p2:other,obj} = JSON.parse(readFileSync(new URL('../ids/test/test-keys.json',import.meta.url),'utf8'));
const object=String(obj).replace('room_','media_'), scalar=new Uint8Array(32);scalar[31]=1;
const claims={object,owner,accessor:owner,from:0,until:7200000,stated:1,epoch:1,grantRevision:1,itemCiphertextDigest:'a'.repeat(64)};
const snapshot={entries:[{accessor:owner,grantRevision:1,stated:1,from:0,until:7200000,scope:'direct',setId:'',hamState:0}]};
const draft={object,previousEpoch:0,epoch:1,deviceId:'browser',keyCommitment:'b'.repeat(64),settleWindowMs:3600000};
const epoch=signPrivateMediaEpoch(draft,snapshot,scalar,owner);
const finalDraft={object,previousEpoch:0,epoch:1,revisionId:epoch.manifest.revisionId,candidateRevisionIds:[epoch.manifest.revisionId],previousFinalizationId:''};
const statusDraft={object,epoch:1,revisionId:epoch.manifest.revisionId,accessor:owner,grantRevision:1,stated:1,signedAt:3601000,maxAgeMs:60000,zookie:{object,objectVersion:3,snapshotHash:epoch.manifest.aclSnapshot}};
test('browser producers preserve drafts and caller-held keys',()=>{
  const held=scalar.slice(),input=structuredClone(claims);
  const grant=signPrivateMediaGrant(claims,scalar,owner);
  assert.deepEqual(grant.claims,input);assert.deepEqual(claims,input);assert.deepEqual(scalar,held);
  assert.match(grant.proof.signature,/^[0-9a-f]{128}$/);
  const finalization=signPrivateMediaFinalization(finalDraft,scalar,owner);
  const status=signPrivateMediaStatus(statusDraft,scalar,owner);
  if(process.env.PRIVATE_MEDIA_VECTOR)writeFileSync(process.env.PRIVATE_MEDIA_VECTOR,JSON.stringify({owner,object,grant,
    cancel:signPrivateMediaGrant({...claims,stated:0,grantRevision:2},scalar,owner),epoch,finalization,status}));
});
test('grant fields, key mismatch and accessors reject before signing',()=>{
  for(const change of [{epoch:0},{grantRevision:0},{from:7200000},{until:-1},{until:-0},{stated:2},{stated:-0},{owner:'bad'},
    {accessor:'bad'},{object:'room_bad'},{itemCiphertextDigest:'bad'},{extra:true},{epoch:NaN},{epoch:2**54}])
    assert.throws(()=>signPrivateMediaGrant({...claims,...change},scalar,owner));
  assert.throws(()=>signPrivateMediaGrant(claims,scalar,other));
  assert.throws(()=>signPrivateMediaGrant(claims,new Uint8Array(32),owner));
  assert.throws(()=>signPrivateMediaGrant(null,scalar,owner));
  let reads=0;const hostile={...claims};Object.defineProperty(hostile,'owner',{get(){reads++;return owner;}});
  assert.throws(()=>signPrivateMediaGrant(hostile,scalar,owner));assert.equal(reads,0);
  assert.throws(()=>signPrivateMediaGrant({...claims,[Symbol('hidden')]:1},scalar,owner));
});
test('direct snapshots and epoch steps are bounded and never coerced',()=>{
  for(const change of [{epoch:3},{previousEpoch:2},{settleWindowMs:1},{deviceId:''},{deviceId:'bad\n'},
    {keyCommitment:'bad'},{object:'bad'}])assert.throws(()=>signPrivateMediaEpoch({...draft,...change},snapshot,scalar,owner));
  for(const invalid of [{entries:[...snapshot.entries,...snapshot.entries]},{entries:new Array(65).fill(snapshot.entries[0])},
    {entries:[{...snapshot.entries[0],scope:'same-group'}]},{entries:[{...snapshot.entries[0],hamState:1}]},
    {entries:[{...snapshot.entries[0],hamState:-0}]},{entries:[{...snapshot.entries[0],setId:'group'}]},
    {entries:new Array(1)},{entries:{}},{entries:[],objectSet:{}},null])
    assert.throws(()=>signPrivateMediaEpoch(draft,invalid,scalar,owner));
  let reads=0;const entries:unknown[]=[];Object.defineProperty(entries,'0',{get(){reads++;return snapshot.entries[0];}});
  assert.throws(()=>signPrivateMediaEpoch(draft,{entries},scalar,owner));assert.equal(reads,0);
});
test('finalization candidates and status windows reject ambiguity',()=>{
  for(const change of [{candidateRevisionIds:[]},{candidateRevisionIds:[finalDraft.revisionId,finalDraft.revisionId]},
    {candidateRevisionIds:['bad']},{previousFinalizationId:'a'.repeat(64)},{epoch:2}])
    assert.throws(()=>signPrivateMediaFinalization({...finalDraft,...change},scalar,owner));
  for(const change of [{maxAgeMs:60001},{maxAgeMs:0},{epoch:0},{grantRevision:0},{signedAt:-1},
    {zookie:{...statusDraft.zookie,object:'bad'}},{zookie:{...statusDraft.zookie,snapshotHash:'bad'}}])
    assert.throws(()=>signPrivateMediaStatus({...statusDraft,...change},scalar,owner));
});
