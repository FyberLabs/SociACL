/** Independent group epoch producers. Current admitted cohort and identities
 * must come from protected authority; signing never grants media access. */
import {p256} from '@noble/curves/nist.js';
import {sha256} from '@noble/hashes/sha2.js';
import {data,integer,hex,unb64,lp} from '../ids/src/util.js';
import {parsePrincipalId,parseObjectId,objectPrincipal,signWithKeyring} from '../ids/src/index.js';
import {epochRevisionId} from './canonical.ts';
import {epochManifestSigBytes,epochFinalizationSigBytes,epochFinalizationId,settleWindowInRange} from './epoch.ts';
import type {ObjectId} from '../../docs/s3rch-check.js';
function record(input:unknown,keys:string[]){const d=data(input);if(!d.ok||Reflect.ownKeys(input as object).length!==keys.length||Object.keys(d.value).length!==keys.length||!keys.every(key=>Object.hasOwn(d.value,key)))throw Error('Invalid group epoch');return d.value;}
function number(value:unknown):number{if(!integer(value))throw Error('Invalid group number');return value as number;}
function principal(value:unknown){const p=parsePrincipalId(value);if(!p.ok)throw Error('Invalid group identity');return p.value;}
function group(value:unknown):ObjectId{if(typeof value!=='string'||!value.startsWith('set_')||!parseObjectId(value).ok)throw Error('Invalid group');return value as ObjectId;}
function digest(value:unknown):string{if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value))throw Error('Invalid group digest');return value;}
function list(input:unknown):unknown[]{
 if(!Array.isArray(input))throw Error('Invalid group list');
 const ds=Object.getOwnPropertyDescriptors(input),length=number(ds.length?.value);
 if(length>64||Reflect.ownKeys(input).length!==length+1)throw Error('Invalid group list');
 const rows:unknown[]=[];for(let n=0;n<length;n++){const d=ds[String(n)];if(!d||!('value'in d))throw Error('Invalid group list');rows.push(d.value);}return rows;
}
export function parseGroupKeySnapshot(input:unknown){
 const r=record(input,['predicate','setId','setOwner','ownerSigningPub','ownerEncryptionPub','ownerIdentityHead','members']);
 if(r.predicate!=='same-group'&&r.predicate!=='named-circle')throw Error('Invalid group predicate');
 const setId=group(r.setId),setOwner=principal(r.setOwner),owner=objectPrincipal(setId);
 if(!owner.ok||owner.value!==setOwner)throw Error('Invalid group owner');
 const ownerSigningPub=principal(r.ownerSigningPub),ownerEncryptionPub=principal(r.ownerEncryptionPub),ownerIdentityHead=number(r.ownerIdentityHead);
 let previous='';
 const members=list(r.members).map(raw=>{
  const m=record(raw,['accessor','stated','hamState','signingPub','encryptionPub','identityHead']);
  const accessor=principal(m.accessor),stated=number(m.stated),hamState=number(m.hamState),signingPub=principal(m.signingPub),encryptionPub=principal(m.encryptionPub),identityHead=number(m.identityHead);
  if(stated>1||accessor<=previous||(accessor===setOwner&&(signingPub!==ownerSigningPub||encryptionPub!==ownerEncryptionPub||identityHead!==ownerIdentityHead)))throw Error('Invalid group member');
  previous=accessor;return {accessor,stated,hamState,signingPub,encryptionPub,identityHead};
 });
 return {predicate:r.predicate,setId,setOwner,ownerSigningPub,ownerEncryptionPub,ownerIdentityHead,members};
}
export function groupKeySnapshotId(input:unknown):string{
 const s=parseGroupKeySnapshot(input);
 const fields=['s3rch-group-key-snapshot-v1',s.predicate,s.setId,s.setOwner,s.ownerSigningPub,s.ownerEncryptionPub,String(s.ownerIdentityHead),String(s.members.length)];
 for(const m of s.members)fields.push(m.accessor,String(m.stated),String(m.hamState),m.signingPub,m.encryptionPub,String(m.identityHead));
 return hex(sha256(lp(fields)));
}
function sign(scalar:Uint8Array,key:string,bytes:Uint8Array){
 if(!(scalar instanceof Uint8Array)||scalar.byteLength!==32)throw Error('Invalid group signing key');
 const copy=new Uint8Array(scalar);
 try{
  const result=signWithKeyring(copy,bytes,principal(key));if(!result.ok)throw Error('Group signing key mismatch');
  const sig=p256.Signature.fromBytes(unb64(result.value),'compact');
  return hex((sig.hasHighS()?new p256.Signature(sig.r,p256.Point.Fn.ORDER-sig.s):sig).toBytes('compact'));
 }finally{copy.fill(0);}
}
export function signPrivateGroupEpoch(input:unknown,snapshot:unknown,scalar:Uint8Array,currentKey:string){
 const r=record(input,['object','previousEpoch','epoch','deviceId','keyCommitment','settleWindowMs']),held=parseGroupKeySnapshot(snapshot);
 if(typeof r.deviceId!=='string'||!/^[\x21-\x7e]{1,128}$/.test(r.deviceId)||currentKey!==held.ownerSigningPub)throw Error('Invalid group signer');
 const body={object:group(r.object),previousEpoch:number(r.previousEpoch),epoch:number(r.epoch),deviceId:r.deviceId,
  keyCommitment:digest(r.keyCommitment),settleWindowMs:number(r.settleWindowMs),aclSnapshot:groupKeySnapshotId(held)};
 if(body.object!==held.setId||body.epoch!==body.previousEpoch+1||!settleWindowInRange(body.settleWindowMs))throw Error('Invalid group epoch step');
 const revisionId=epochRevisionId(body);return {manifest:{...body,revisionId,signature:sign(scalar,currentKey,epochManifestSigBytes(revisionId))},snapshot:held};
}
export function signPrivateGroupFinalization(input:unknown,scalar:Uint8Array,currentKey:string){
 const r=record(input,['object','previousEpoch','epoch','revisionId','candidateRevisionIds','previousFinalizationId']);
 const body={object:group(r.object),previousEpoch:number(r.previousEpoch),epoch:number(r.epoch),revisionId:digest(r.revisionId),
  candidateRevisionIds:list(r.candidateRevisionIds).map(digest),previousFinalizationId:r.previousFinalizationId===''?'':digest(r.previousFinalizationId)};
 if(body.epoch!==body.previousEpoch+1||(body.previousEpoch===0)!==(body.previousFinalizationId==='')||body.candidateRevisionIds[0]!==body.revisionId||
  body.candidateRevisionIds.some((v,n)=>n>0&&v<=body.candidateRevisionIds[n-1]!))throw Error('Invalid group candidates');
 const finalizationId=epochFinalizationId(body.object,body.epoch,body.previousEpoch,body.revisionId,body.previousFinalizationId,body.candidateRevisionIds);
 return {...body,finalizationId,signature:sign(scalar,currentKey,epochFinalizationSigBytes(finalizationId))};
}
