/** Client-side producers for existing private-media transcripts. These do not
 * establish enrollment, current authorization, settlement or freshness. */
import { p256 } from '@noble/curves/nist.js';
import { data, integer, hex, unb64 } from '../ids/src/util.js';
import { parsePrincipalId, parseObjectId, objectPrincipal, signWithKeyring } from '../ids/src/index.js';
import { grantPayloadBytes, epochRevisionId, epochStatusBytes } from './canonical.ts';
import { aclSnapshotId, epochManifestSigBytes, epochFinalizationSigBytes, epochFinalizationId, settleWindowInRange, groupEpochConfigBytes } from './epoch.ts';
import type { AclSnapshotBody, AclSnapshotEntry, ObjectId } from '../../docs/s3rch-check.js';

function record(input: unknown, keys: string[]) {
  const d = data(input);
  if (!d.ok || Reflect.ownKeys(input as object).length !== keys.length || Object.keys(d.value).sort().join() !== keys.sort().join()) throw Error('Invalid private media input');
  return d.value;
}
function number(value: unknown): number { if (!integer(value)) throw Error('Invalid private media number'); return value as number; }
function principal(value: unknown) { const p = parsePrincipalId(value); if (!p.ok) throw Error('Invalid private media principal'); return p.value; }
function object(value: unknown): ObjectId { const p = parseObjectId(value); if (!p.ok || typeof value !== 'string' || !value.startsWith('media_')) throw Error('Invalid private media object'); return value as ObjectId; }
function digest(value: unknown): string { if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw Error('Invalid private media digest'); return value; }
function label(value: unknown): string { if (typeof value !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(value)) throw Error('Invalid private media label'); return value; }
function stated(value: unknown): 0 | 1 { if (value !== 0 && value !== 1 || Object.is(value, -0)) throw Error('Invalid private media state'); return value; }
function list(input: unknown): unknown[] {
  if (!Array.isArray(input)) throw Error('Invalid private media list');
  const length = number(Object.getOwnPropertyDescriptor(input, 'length')?.value);
  if (length > 64) throw Error('Invalid private media list');
  const ds = Object.getOwnPropertyDescriptors(input as object);
  if (Reflect.ownKeys(ds).length !== length + 1) throw Error('Invalid private media list');
  const result: unknown[] = [];
  for (let n=0; n<length; n++) { const d=ds[String(n)]; if (!d || !('value' in d)) throw Error('Invalid private media list'); result.push(d.value); }
  return result;
}
function sign(scalar: Uint8Array, currentKey: string, bytes: Uint8Array): string {
  const result = signWithKeyring(scalar, bytes, principal(currentKey));
  if (!result.ok) throw Error('Private media signing key mismatch');
  const signature = p256.Signature.fromBytes(unb64(result.value), 'compact');
  // The private-media Rust transcript requires low-S; identity signatures also
  // accept high-S, so normalize only this producer's output.
  const canonical = signature.hasHighS() ? new p256.Signature(signature.r, p256.Point.Fn.ORDER - signature.s) : signature;
  return hex(canonical.toBytes('compact'));
}
function mediaSnapshot(input: unknown): AclSnapshotBody {
  const shape=data(input);
  if(!shape.ok)throw Error('Invalid private media snapshot');
  const hasEdge=Object.hasOwn(shape.value,'objectSet');
  const raw=record(input,hasEdge?['entries','objectSet']:['entries']);
  let objectSet: AclSnapshotBody['objectSet'];
  if(hasEdge) {
    const r=record(raw.objectSet,['predicate','setId','stated','hamState']);
    if((r.predicate!=='same-group'&&r.predicate!=='named-circle')||typeof r.setId!=='string'||
        !r.setId.startsWith('set_')||!parseObjectId(r.setId).ok)throw Error('Invalid private media object set');
    objectSet={predicate:r.predicate,setId:r.setId,stated:stated(r.stated),hamState:number(r.hamState)};
  }
  const entries: AclSnapshotEntry[]=list(raw.entries).map(input=>{
    const r=record(input,['accessor','grantRevision','stated','from','until','scope','setId','hamState']);
    const hamState=number(r.hamState);
    if(r.scope==='direct') {
      if(r.setId!==''||hamState!==0)throw Error('Invalid direct private media scope');
    } else if(!objectSet||r.scope!==objectSet.predicate||r.setId!==objectSet.setId) {
      throw Error('Invalid private media membership scope');
    }
    return {accessor:principal(r.accessor),grantRevision:number(r.grantRevision),stated:stated(r.stated),
      from:number(r.from),until:number(r.until),scope:r.scope as AclSnapshotEntry['scope'],setId:r.setId as string,hamState};
  });
  const result={entries,...(objectSet?{objectSet}:{})};aclSnapshotId(result);return result;
}

/** Sign a live grant or cancellation. Current key must come from the protected
 * owner view, independently of the draft. No key is created or retained. */
export function signPrivateMediaGrant(input: unknown, scalar: Uint8Array, currentKey: string) {
  const r = record(input, ['object','owner','accessor','from','until','stated','epoch','grantRevision','itemCiphertextDigest']);
  const claims = {object:object(r.object),owner:principal(r.owner),accessor:principal(r.accessor),from:number(r.from),until:number(r.until),
    stated:stated(r.stated),epoch:number(r.epoch),grantRevision:number(r.grantRevision),itemCiphertextDigest:digest(r.itemCiphertextDigest)};
  if (!claims.epoch || !claims.grantRevision || claims.from >= claims.until) throw Error('Invalid private media grant window');
  const bytes=grantPayloadBytes(claims);
  return {claims,proof:{grantBytes:hex(bytes),signature:sign(scalar,currentKey,bytes)}};
}

/** Builds one direct or group snapshot epoch candidate. Call only after independently
 * resolving the complete snapshot and enrolled keys; this does not settle it. */
export function signPrivateMediaEpoch(input: unknown, snapshot: unknown, scalar: Uint8Array, currentKey: string) {
  const r = record(input,['object','previousEpoch','epoch','deviceId','keyCommitment','settleWindowMs']);
  const held = mediaSnapshot(snapshot);
  const body = {object:object(r.object),previousEpoch:number(r.previousEpoch),epoch:number(r.epoch),deviceId:label(r.deviceId),
    keyCommitment:digest(r.keyCommitment),settleWindowMs:number(r.settleWindowMs),aclSnapshot:aclSnapshotId(held)};
  if (body.epoch !== body.previousEpoch+1 || !settleWindowInRange(body.settleWindowMs)) throw Error('Invalid private media epoch step');
  const revisionId=epochRevisionId(body);
  return {manifest:{...body,revisionId,signature:sign(scalar,currentKey,epochManifestSigBytes(revisionId))},snapshot:held};
}

/** Candidates must already be authenticated and sorted. Never treats the
 * candidate list or signature as proof of completeness or elapsed settlement. */
export function signPrivateMediaFinalization(input: unknown, scalar: Uint8Array, currentKey: string) {
  const r=record(input,['object','previousEpoch','epoch','revisionId','candidateRevisionIds','previousFinalizationId']);
  const body={object:object(r.object),previousEpoch:number(r.previousEpoch),epoch:number(r.epoch),revisionId:digest(r.revisionId),
    candidateRevisionIds:list(r.candidateRevisionIds).map(digest),previousFinalizationId:r.previousFinalizationId === '' ? '' : digest(r.previousFinalizationId)};
  if (body.epoch !== body.previousEpoch+1 || (body.previousEpoch === 0) !== (body.previousFinalizationId === '') ||
      body.candidateRevisionIds[0] !== body.revisionId || body.candidateRevisionIds.some((v,n)=>n>0 && v<=body.candidateRevisionIds[n-1]!)) throw Error('Invalid private media candidates');
  const finalizationId=epochFinalizationId(body.object,body.epoch,body.previousEpoch,body.revisionId,body.previousFinalizationId,body.candidateRevisionIds);
  return {...body,finalizationId,signature:sign(scalar,currentKey,epochFinalizationSigBytes(finalizationId))};
}

/** Sign bounded status from the current protected owner view. The service
 * separately verifies elapsed settlement, current grants and the signed clock. */
export function signPrivateMediaStatus(input: unknown, scalar: Uint8Array, currentKey: string) {
  const r=record(input,['object','epoch','revisionId','accessor','grantRevision','stated','signedAt','maxAgeMs','zookie']);
  const z=record(r.zookie,['object','objectVersion','snapshotHash']);
  const body={object:object(r.object),epoch:number(r.epoch),revisionId:digest(r.revisionId),accessor:principal(r.accessor),
    grantRevision:number(r.grantRevision),stated:stated(r.stated),signedAt:number(r.signedAt),maxAgeMs:number(r.maxAgeMs),
    zookie:{object:object(z.object),objectVersion:number(z.objectVersion),snapshotHash:digest(z.snapshotHash)}};
  if (!body.epoch || !body.grantRevision || !body.maxAgeMs || body.maxAgeMs>60000 || body.zookie.object !== body.object) throw Error('Invalid private media status');
  const bytes=epochStatusBytes({...body,zookieObject:body.zookie.object,zookieVersion:body.zookie.objectVersion,zookieSnapshot:body.zookie.snapshotHash});
  return {...body,signature:sign(scalar,currentKey,bytes)};
}

/** Explicit irreversible deletion intent, never inferred from unshare or expiry.
 * Consumers must bind these claims to current protected owner state before
 * tombstoning, and separately complete storage cleanup and quota release. */
export function signPrivateMediaDeletion(input: unknown, scalar: Uint8Array, currentKey: string) {
  const r=record(input,['tenant','object','owner','objectVersion','fence','issuedAt','expiresAt']);
  if(typeof r.tenant!=='string'||! /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(r.tenant)||r.tenant==='00000000-0000-0000-0000-000000000000')throw Error('Invalid deletion tenant');
  const claims={tenant:r.tenant,object:object(r.object),owner:principal(r.owner),objectVersion:number(r.objectVersion),
    fence:digest(r.fence),issuedAt:number(r.issuedAt),expiresAt:number(r.expiresAt)};
  if(claims.expiresAt<=claims.issuedAt||claims.expiresAt-claims.issuedAt>60000)throw Error('Invalid deletion window');
  const bytes=new TextEncoder().encode('SOCIACL_PRIVATE_MEDIA_DELETE_V1\n'+JSON.stringify([claims.tenant,claims.object,claims.owner,claims.objectVersion,claims.fence,claims.issuedAt,claims.expiresAt]));
  return {claims,proof:{deletionBytes:hex(bytes),signature:sign(scalar,currentKey,bytes)}};
}

/** Sign the existing group policy transcript. Consumers independently resolve
 * set ownership/current keys and select the current revision; this is not Check. */
export function signPrivateMediaGroupConfig(input: unknown, scalar: Uint8Array, currentKey: string) {
  const r=record(input,['owner','setId','predicate','settleWindowMs','configRevision']);
  const owner=principal(r.owner),setOwner=objectPrincipal(r.setId);
  if(typeof r.setId!=='string'||!r.setId.startsWith('set_')||!parseObjectId(r.setId).ok||!setOwner.ok||setOwner.value!==owner||
      (r.predicate!=='same-group'&&r.predicate!=='named-circle'))throw Error('Invalid private media group policy scope');
  const body={owner,setId:r.setId,predicate:r.predicate,settleWindowMs:number(r.settleWindowMs),configRevision:number(r.configRevision)};
  if(!settleWindowInRange(body.settleWindowMs))throw Error('Invalid private media group policy window');
  return {...body,signature:sign(scalar,currentKey,groupEpochConfigBytes(body.owner,body.setId,body.predicate,body.settleWindowMs,body.configRevision))};
}
