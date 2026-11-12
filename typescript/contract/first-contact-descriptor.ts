/** Authenticated public descriptor. Publishing it intentionally advertises a request channel. */
import { parsePrincipalId, verifySignedAt, signWithKeyring } from '../ids/src/index.js';
import type { PrincipalId, ResolutionContext, Result } from '../ids/src/index.js';
import { data, integer, lp, fail, ok } from '../ids/src/util.js';
import type { FirstContactSealDescriptor } from './first-contact-seal.ts';
import type { AccountKeyring } from './account-keyring.ts';
import { unb64 } from './account-key-seal.ts';

export const FIRST_CONTACT_DESCRIPTOR_DOMAIN = 'sociacl-first-contact-descriptor-v1';
export type SignedFirstContactDescriptor = Readonly<{
  v:1; owner:PrincipalId; issuedAt:number; descriptor:FirstContactSealDescriptor; sig:string;
}>;
export function firstContactDescriptorBytes(r: Omit<SignedFirstContactDescriptor,'sig'>): Uint8Array {
  const d=r.descriptor;
  return lp([FIRST_CONTACT_DESCRIPTOR_DOMAIN,'1',r.owner,String(r.issuedAt),d.channelId,String(d.revision),
    d.encryptionEpub,String(d.expiresAt),String(d.maxLifetimeSeconds),String(d.maxMessageBytes)]);
}
function parse(input:unknown):Result<SignedFirstContactDescriptor> {
  const root=data(input);if(!root.ok)return root;
  const r=root.value,d=data(r.descriptor);if(!d.ok)return d;
  const p=d.value,owner=parsePrincipalId(r.owner),epub=parsePrincipalId(p.encryptionEpub);
  if(!owner.ok)return owner;if(!epub.ok)return epub;
  if(Object.keys(r).sort().join()!=='descriptor,issuedAt,owner,sig,v' ||
    Object.keys(p).sort().join()!=='channelId,encryptionEpub,expiresAt,maxLifetimeSeconds,maxMessageBytes,revision' ||
    r.v!==1 || !integer(r.issuedAt) || typeof r.sig!=='string' || r.sig.length!==86 || !/^[A-Za-z0-9_-]{86}$/.test(r.sig) ||
    typeof p.channelId!=='string' || p.channelId.length!==64 || !/^[0-9a-f]{64}$/.test(p.channelId) ||
    !integer(p.revision) || (p.revision as number)<1 || !integer(p.expiresAt) ||
    (p.expiresAt as number)<=(r.issuedAt as number) || (p.expiresAt as number)-(r.issuedAt as number)>604800 ||
    !integer(p.maxLifetimeSeconds) || (p.maxLifetimeSeconds as number)<1 || (p.maxLifetimeSeconds as number)>604800 ||
    !integer(p.maxMessageBytes) || (p.maxMessageBytes as number)<1 || (p.maxMessageBytes as number)>4096) return fail('bad-record');
  return ok(Object.freeze({v:1,owner:owner.value,issuedAt:r.issuedAt as number,sig:r.sig,
    descriptor:Object.freeze({channelId:p.channelId,revision:p.revision as number,encryptionEpub:epub.value,
      expiresAt:p.expiresAt as number,maxLifetimeSeconds:p.maxLifetimeSeconds as number,maxMessageBytes:p.maxMessageBytes as number})}));
}
/** Expected owner and revision floor come from independent authenticated state.
 * A signature proves who advertised the descriptor, not that it is their latest.
 * Discovery must supply freshness; a locally observed floor prevents rollback.
 */
export function verifyFirstContactDescriptor(input:unknown,expectedOwner:PrincipalId,minimumRevision:number,
  rotations:readonly unknown[],context:ResolutionContext):Result<SignedFirstContactDescriptor> {
  const parsed=parse(input);if(!parsed.ok)return parsed;
  const r=parsed.value;
  if(!integer(minimumRevision) || minimumRevision<1 || !integer(context.now) ||
    r.owner!==expectedOwner || r.descriptor.revision<minimumRevision) return fail('bad-record');
  if(r.issuedAt>context.now)return fail('future-record');
  if(r.descriptor.expiresAt<=context.now)return fail('expired');
  const proof=verifySignedAt(r.owner,rotations,context,firstContactDescriptorBytes(r),r.sig,r.issuedAt);
  if(!proof.ok)return proof;
  try {
    const history=context.history(r.owner,r.issuedAt,context.now);
    if(!history.ok)return history;
    if(history.value.key!==proof.value.key || history.value.currentKey!==proof.value.key)return fail('missing-history');
  }catch{return fail('missing-history');}
  return parsed;
}
/** Sign only after local opt-in has committed its fresh descriptor. */
export function signFirstContactDescriptor(keyring:AccountKeyring,descriptor:FirstContactSealDescriptor,
  rotations:readonly unknown[],context:ResolutionContext):SignedFirstContactDescriptor {
  const currentKey=keyring.confirm(rotations,context);
  const candidate=parse({v:1,owner:keyring.principal,issuedAt:context.now,descriptor,sig:'A'.repeat(86)});
  if(!candidate.ok)throw Error(candidate.reason);
  const key=unb64(keyring.currentPriv());
  try {
    const sig=signWithKeyring(key,firstContactDescriptorBytes(candidate.value),currentKey);
    if(!sig.ok)throw Error(sig.reason);
    const result={...candidate.value,sig:sig.value};
    const verified=verifyFirstContactDescriptor(result,keyring.principal,descriptor.revision,rotations,context);
    if(!verified.ok)throw Error(verified.reason);
    return verified.value;
  }finally{key.fill(0);}
}
