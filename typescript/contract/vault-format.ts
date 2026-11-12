/** Phase-one vault signing transcripts only. A signature/wrap never grants a read. */
import { parsePrincipalId } from '../ids/src/index.js';
import { lp, integer } from '../ids/src/util.js';
export const VAULT_VERSION_DOMAIN='sociacl-vault-version-v1';
export const VAULT_AUDIT_DOMAIN='sociacl-vault-audit-v1';
export const VAULT_MAX_PARENTS=16;
export type VaultVersion=Readonly<{itemId:string;versionId:string;owner:string;parents:readonly string[];
  epoch:number;revisionId:string;ciphertextDigest:string;sensitive:boolean;issuedAt:number}>;
export type VaultAudit=Readonly<{eventId:string;itemId:string;versionId:string;actor:string;deviceId:string;
  operation:'put'|'share'|'revoke'|'read'|'use'|'enroll'|'recover';outcome:'allowed'|'denied'|'failed';issuedAt:number;previousDigest:string}>;
const opaque=(s:string)=>{if(typeof s!=='string'||s.length!==64||!/^[0-9a-f]{64}$/.test(s))throw Error('bad-vault-id');};
const principal=(s:string)=>{if(!parsePrincipalId(s).ok)throw Error('bad-vault-principal');};
const decimal=(n:number)=>{if(!integer(n))throw Error('bad-vault-integer');return String(n);};
/** Encrypt the full signed manifest; owner, epoch, parents and sensitivity are private. */
export function vaultVersionSigningBytes(v:VaultVersion):Uint8Array {
  [v.itemId,v.versionId,v.revisionId,v.ciphertextDigest].forEach(opaque);principal(v.owner);
  if(!Array.isArray(v.parents)||v.parents.length>VAULT_MAX_PARENTS||typeof v.sensitive!=='boolean')throw Error('bad-vault-version');
  v.parents.forEach((parent,i)=>{opaque(parent);if(parent===v.versionId||(i>0&&v.parents[i-1]!>=parent))throw Error('bad-vault-parents');});
  return lp([VAULT_VERSION_DOMAIN,'1',v.itemId,v.versionId,v.owner,decimal(v.epoch),v.revisionId,
    v.ciphertextDigest,v.sensitive?'1':'0',decimal(v.issuedAt),String(v.parents.length),...v.parents]);
}
export function vaultAuditSigningBytes(v:VaultAudit):Uint8Array {
  [v.eventId,v.itemId,v.versionId,v.deviceId,v.previousDigest].forEach(opaque);principal(v.actor);
  if(!['put','share','revoke','read','use','enroll','recover'].includes(v.operation)||!['allowed','denied','failed'].includes(v.outcome))throw Error('bad-vault-audit');
  return lp([VAULT_AUDIT_DOMAIN,'1',v.eventId,v.itemId,v.versionId,v.actor,v.deviceId,v.operation,v.outcome,decimal(v.issuedAt),v.previousDigest]);
}
