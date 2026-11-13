/** Client-side producers for existing private-media transcripts. These do not
 * establish enrollment, current authorization, settlement or freshness. */
import { p256 } from '@noble/curves/nist.js';
import { data, integer, hex, unb64 } from '../ids/src/util.js';
import { parsePrincipalId, parseObjectId } from '../ids/src/ids.js';
import { signWithKeyring } from '../ids/src/records.js';
import { grantPayloadBytes, epochRevisionId, epochStatusBytes } from './canonical.ts';
import { aclSnapshotId, epochManifestSigBytes, epochFinalizationSigBytes, epochFinalizationId, settleWindowInRange } from './epoch.ts';
import type { AclSnapshotBody, AclSnapshotEntry } from '../../docs/s3rch-check.js';

function record(input: unknown, keys: string[]) {
  const d = data(input);
  if (!d.ok || Reflect.ownKeys(input as object).length !== keys.length || Object.keys(d.value).sort().join() !== keys.sort().join()) throw Error('Invalid private media input');
  return d.value;
}
function number(value: unknown): number { if (!integer(value)) throw Error('Invalid private media number'); return value as number; }
function principal(value: unknown) { const p = parsePrincipalId(value); if (!p.ok) throw Error('Invalid private media principal'); return p.value; }
function object(value: unknown): string { const p = parseObjectId(value); if (!p.ok || typeof value !== 'string' || !value.startsWith('media_')) throw Error('Invalid private media object'); return value; }
function digest(value: unknown): string { if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw Error('Invalid private media digest'); return value; }
function label(value: unknown): string { if (typeof value !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(value)) throw Error('Invalid private media label'); return value; }
function stated(value: unknown): 0 | 1 { if (value !== 0 && value !== 1 || Object.is(value, -0)) throw Error('Invalid private media state'); return value; }
function list(input: unknown): unknown[] {
  if (!Array.isArray(input)) throw Error('Invalid private media list');
  const ds = Object.getOwnPropertyDescriptors(input as object), length = number(ds.length?.value);
  if (length > 64 || Reflect.ownKeys(ds).length !== length + 1) throw Error('Invalid private media list');
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
function directSnapshot(input: unknown): AclSnapshotBody {
  const raw = record(input, ['entries']);
  const entries: AclSnapshotEntry[] = list(raw.entries).map(input => {
    const r = record(input, ['accessor','grantRevision','stated','from','until','scope','setId','hamState']);
    if (r.scope !== 'direct' || r.setId !== '' || r.hamState !== 0 || Object.is(r.hamState,-0)) throw Error('Only direct private media snapshots are supported');
    return {accessor:principal(r.accessor),grantRevision:number(r.grantRevision),stated:stated(r.stated),from:number(r.from),until:number(r.until),scope:'direct',setId:'',hamState:0};
  });
  const result = {entries}; aclSnapshotId(result); return result;
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

/** Builds one direct-snapshot epoch candidate. Call only after independently
 * resolving the complete snapshot and enrolled keys; this does not settle it. */
export function signPrivateMediaEpoch(input: unknown, snapshot: unknown, scalar: Uint8Array, currentKey: string) {
  const r = record(input,['object','previousEpoch','epoch','deviceId','keyCommitment','settleWindowMs']);
  const held = directSnapshot(snapshot);
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
