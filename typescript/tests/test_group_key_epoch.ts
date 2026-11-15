// Browser/native transcript compatibility runs only in CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {groupKeySnapshotId,parseGroupKeySnapshot,signPrivateGroupEpoch,signPrivateGroupFinalization} from '../contract/group-key-epoch.ts';
import {signPrivateMediaGroupConfig} from '../contract/private-media.ts';
const {p:owner,p2:other,obj}=JSON.parse(readFileSync(new URL('../ids/test/test-keys.json',import.meta.url),'utf8'));
const set=String(obj).replace('room_','set_'),scalar=new Uint8Array(32);scalar[31]=1;
const member={accessor:owner,stated:1,hamState:1,signingPub:owner,encryptionPub:other,identityHead:0};
const snapshot={predicate:'same-group',setId:set,setOwner:owner,ownerSigningPub:owner,ownerEncryptionPub:other,ownerIdentityHead:0,members:[member]};
const draft={object:set,previousEpoch:0,epoch:1,deviceId:'browser',keyCommitment:'a'.repeat(64),settleWindowMs:3600000};
const epoch=signPrivateGroupEpoch(draft,snapshot,scalar,owner);
const finalDraft={object:set,previousEpoch:0,epoch:1,revisionId:epoch.manifest.revisionId,candidateRevisionIds:[epoch.manifest.revisionId],previousFinalizationId:''};
test('group snapshot, manifest and finalization bind independent scope without media grants',()=>{
 const saved=scalar.slice();assert.equal(groupKeySnapshotId(snapshot),epoch.manifest.aclSnapshot);
 const finalization=signPrivateGroupFinalization(finalDraft,scalar,owner);assert.deepEqual(scalar,saved);
 assert.deepEqual(epoch.snapshot,snapshot);assert.match(finalization.signature,/^[a-f0-9]{128}$/);
 const config=signPrivateMediaGroupConfig({owner,setId:set,predicate:'same-group',settleWindowMs:3600000,configRevision:0},scalar,owner);
 assert.notEqual(groupKeySnapshotId({...snapshot,predicate:'named-circle'}),groupKeySnapshotId(snapshot));
 if(process.env.GROUP_KEY_VECTOR)writeFileSync(process.env.GROUP_KEY_VECTOR,JSON.stringify({owner,epoch,finalization,config}));
});
test('snapshot fields, identities, sorted retained membership and hostile properties refuse',()=>{
 for(const patch of [{predicate:'direct'},{setId:'media_bad'},{setOwner:other},{ownerSigningPub:'bad'},{ownerIdentityHead:-0},
  {members:null},{members:Array(65).fill(member)},{members:[member,member]},{members:[{...member,stated:2}]},
  {members:[{...member,identityHead:1}]},{members:[{...member,signingPub:other}]},{members:[{...member,encryptionPub:owner}]},
  {members:[{...member,hamState:2**54}]},{extra:1}])assert.throws(()=>groupKeySnapshotId({...snapshot,...patch}));
 const sparse=Array(1);assert.throws(()=>groupKeySnapshotId({...snapshot,members:sparse}));
 let reads=0;const list=[member];Object.defineProperty(list,'0',{get(){reads++;return member;}});
 assert.throws(()=>groupKeySnapshotId({...snapshot,members:list}));assert.equal(reads,0);
 const hostile={...snapshot};Object.defineProperty(hostile,'setOwner',{get(){reads++;return owner;}});
 assert.throws(()=>parseGroupKeySnapshot(hostile));assert.equal(reads,0);
 assert.throws(()=>parseGroupKeySnapshot({...snapshot,[Symbol('hidden')]:true}));
 assert.throws(()=>parseGroupKeySnapshot({'predicate,setId,setOwner,ownerSigningPub,ownerEncryptionPub,ownerIdentityHead,members':1}));
 assert.equal(parseGroupKeySnapshot({...snapshot,members:[]}).members.length,0);
});
test('signing refuses scope, step, key and candidate changes and keeps caller buffers',()=>{
 for(const patch of [{object:'media_bad'},{object:set.slice(0,-1)+'2'},{previousEpoch:2},{epoch:0},{deviceId:''},{deviceId:'x\n'},
  {keyCommitment:'bad'},{settleWindowMs:1},{epoch:NaN}])assert.throws(()=>signPrivateGroupEpoch({...draft,...patch},snapshot,scalar,owner));
 assert.throws(()=>signPrivateGroupEpoch(draft,snapshot,scalar,other));
 assert.throws(()=>signPrivateGroupEpoch(draft,snapshot,new Uint8Array(1),owner));
 assert.throws(()=>signPrivateGroupEpoch(draft,snapshot,new Uint8Array(32),owner));
 for(const patch of [{candidateRevisionIds:[]},{candidateRevisionIds:[finalDraft.revisionId,finalDraft.revisionId]},
  {previousFinalizationId:'a'.repeat(64)},{revisionId:'bad'},{epoch:3}])assert.throws(()=>signPrivateGroupFinalization({...finalDraft,...patch},scalar,owner));
 const next={...finalDraft,previousEpoch:1,epoch:2,previousFinalizationId:'a'.repeat(64)};
 assert.match(signPrivateGroupFinalization(next,scalar,owner).finalizationId,/^[a-f0-9]{64}$/);
});
