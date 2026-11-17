/** Private signed sync metadata. Encrypt before publishing to untrusted storage. */
import { sha256 } from '@noble/hashes/sha2.js';
import { parsePrincipalId, verifySignedAt, type PrincipalId, type ResolutionContext } from '../ids/src/index.js';
import { data, hex, integer, lp } from '../ids/src/util.js';
import { openFirstContactFloor, type DescriptorFloor } from '../ids/src/first-contact-floor.js';
export const VAULT_SYNC_HEAD_DOMAIN='sociacl-vault-sync-head-v1';
export type VaultSyncHead=Readonly<{v:1;owner:PrincipalId;vaultId:string;revision:number;previousDigest:string;
  keybagDigest:string;indexDigest:string;minimumProfile:1|2;issuedAt:number;sig:string}>;
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
function parse(input:unknown):VaultSyncHead {
  const parsed=data(input);if(!parsed.ok)throw Error('Invalid vault head');const r=parsed.value;
  if(Object.keys(r).sort().join()!=='indexDigest,issuedAt,keybagDigest,minimumProfile,owner,previousDigest,revision,sig,v,vaultId')throw Error('Invalid vault head');
  const owner=parsePrincipalId(r.owner);
  if(!owner.ok||r.v!==1||!digest(r.vaultId)||!digest(r.previousDigest)||!digest(r.keybagDigest)||!digest(r.indexDigest)||
    !integer(r.revision)||(r.revision as number)<1||!integer(r.issuedAt)||![1,2].includes(r.minimumProfile as number)||
    typeof r.sig!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(r.sig)||
    ((r.revision===1)!==(r.previousDigest==='00'.repeat(32))))throw Error('Invalid vault head');
  return Object.freeze({v:1,owner:owner.value,vaultId:r.vaultId,revision:r.revision as number,previousDigest:r.previousDigest,
    keybagDigest:r.keybagDigest,indexDigest:r.indexDigest,minimumProfile:r.minimumProfile as 1|2,issuedAt:r.issuedAt as number,sig:r.sig});
}
function bytes(r:VaultSyncHead):Uint8Array {
  return lp([VAULT_SYNC_HEAD_DOMAIN,'1',r.owner,r.vaultId,String(r.revision),r.previousDigest,
    r.keybagDigest,r.indexDigest,String(r.minimumProfile),String(r.issuedAt)]);
}
/** Supply a placeholder sig when preparing a signature; it is excluded from the transcript. */
export function vaultSyncHeadSigningBytes(input:unknown):Uint8Array{return bytes(parse(input));}
export function vaultSyncHeadFloor(input:unknown):DescriptorFloor {
  const r=parse(input);return Object.freeze({revision:r.revision,digest:hex(sha256(bytes(r)))});
}
export function verifyVaultSyncHead(input:unknown,owner:PrincipalId,vaultId:string,
  rotations:readonly unknown[],context:ResolutionContext):VaultSyncHead {
  const r=parse(input);
  if(r.owner!==owner||r.vaultId!==vaultId||!integer(context.now)||r.issuedAt>context.now)throw Error('Wrong vault head binding or clock');
  const proof=verifySignedAt(owner,rotations,context,bytes(r),r.sig,r.issuedAt);
  if(!proof.ok)throw Error('Unauthenticated vault head');
  const history=context.history(owner,r.issuedAt,context.now);
  if(!history.ok||history.value.key!==proof.value.key||history.value.currentKey!==proof.value.key)throw Error('Missing current vault owner history');
  return r;
}
export type VaultHeadIdentityState=()=>{rotations:readonly unknown[];context:ResolutionContext};
/** This trusted client IndexedDB is separate from Spanopticon's untrusted record
 * store. An exact independently authenticated anchor is mandatory even on create.
 * Storage loss is never first use. No remote ETag is an anchor or authorization.
 * Authentication at commit prevents delayed writes from retaining obsolete keys.
 */
export async function openVaultSyncHeadStore(options:{name:string;owner:PrincipalId;vaultId:string;anchor:DescriptorFloor;
  now:()=>number;create?:boolean;indexedDB?:IDBFactory}) {
  if(!digest(options.vaultId)||!parsePrincipalId(options.owner).ok||typeof options.name!=='string'||!options.name)throw Error('Invalid vault head store');
  const owner=options.owner,vaultId=options.vaultId;
  const store=await openFirstContactFloor({...options,name:`sociacl-vault-head:${options.name}:${vaultId}`});
  function authenticate(r:VaultSyncHead,current:VaultHeadIdentityState,now:number){
    const state=current();
    if(state.context.now!==now)throw Error('Vault identity clock mismatch');
    verifyVaultSyncHead(r,owner,vaultId,state.rotations,state.context);
  }
  return Object.freeze({read:()=>store.read(),close:()=>store.close(),
    /** Verify a decrypted candidate against the exact retained floor. This proves
     * continuity only, not remote freshness or permission to read item plaintext. */
    async verifyCurrent(input:unknown,current:VaultHeadIdentityState){
      const r=parse(input),floor=vaultSyncHeadFloor(r),saved=await store.read();
      if(floor.revision!==saved.revision||floor.digest!==saved.digest)throw Error('Vault head continuity mismatch');
      await store.observe(floor,now=>authenticate(r,current,now));return r;
    },
    /** Return only after local commit. Retain a conflicting prepared candidate for
     * explicit reconciliation; do not select by timestamp or silently retry CAS.
     * The caller must separately confirm remote ciphertext readback, and must not
     * release secrets until Check and fresh epoch verification have also passed. */
    async advance(previous:unknown,input:unknown,current:VaultHeadIdentityState){
      const prior=parse(previous),next=parse(input),before=vaultSyncHeadFloor(prior),after=vaultSyncHeadFloor(next);
      if(prior.owner!==owner||prior.vaultId!==vaultId||next.owner!==owner||next.vaultId!==vaultId||
        next.revision!==prior.revision+1||next.previousDigest!==before.digest||next.minimumProfile<prior.minimumProfile||
        next.issuedAt<prior.issuedAt)throw Error('Invalid vault head successor');
      const saved=await store.read();
      if(saved.revision===after.revision&&saved.digest===after.digest){
        await store.observe(after,now=>authenticate(next,current,now));return next;
      }
      if(saved.revision!==before.revision||saved.digest!==before.digest)throw Error('Vault head conflict');
      await store.observe(after,now=>authenticate(next,current,now));return next;
    },
  });
}
