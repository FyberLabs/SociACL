/** Experimental independent timestamp receipt contract. Not rotation authorization. */
import { sha256 } from '@noble/hashes/sha2.js';
import { parsePrincipalId, verifySignedAt, verifyKeySignature } from '../ids/src/index.js';
import type { PrincipalId, ResolutionContext, Result } from '../ids/src/index.js';
import { lp, hex, integer, fail, ok } from '../ids/src/util.js';
export const WITNESS_REQUEST_DOMAIN='sociacl-independent-witness-request-v1';
export const WITNESS_RECEIPT_DOMAIN='sociacl-independent-witness-receipt-v1';
export type WitnessOperator=Readonly<{id:string;keys:readonly Readonly<{key:PrincipalId;notBefore:number;notAfter:number}>[]}>;
/** Independently authenticated policy, never sourced from the receipt bundle. */
export type IndependentWitnessPolicy=Readonly<{id:string;epoch:number;threshold:number;maxFaulty:number;operators:readonly WitnessOperator[]}>;
export type WitnessRequest=Readonly<{v:1;principal:PrincipalId;operation:'rotate'|'revoke';recordDigest:string;
  policyId:string;epoch:number;issuedAt:number;expiresAt:number;sig:string}>;
export type WitnessReceipt=Readonly<{operator:string;observedAt:number;sig:string}>;
const hash=(s:unknown):s is string=>typeof s==='string' && s.length===64 && /^[0-9a-f]{64}$/.test(s);
const operator=(s:unknown):s is string=>typeof s==='string' && s.length<=64 && /^[a-z][a-z0-9-]*$/.test(s);
export function witnessRequestBytes(r:Omit<WitnessRequest,'sig'>):Uint8Array {
  return lp([WITNESS_REQUEST_DOMAIN,'1',r.principal,r.operation,r.recordDigest,r.policyId,String(r.epoch),String(r.issuedAt),String(r.expiresAt)]);
}
export function witnessReceiptBytes(r:WitnessRequest,operatorId:string,observedAt:number):Uint8Array {
  return lp([WITNESS_RECEIPT_DOMAIN,hex(sha256(witnessRequestBytes(r))),operatorId,String(observedAt)]);
}
/** Authenticate account intent and distinct operator observations of identical bytes.
 * This cannot validate the underlying rotate/revoke record or provide fork consensus.
 * Existing record verification remains mandatory and does not consume this prototype.
 */
export function verifyIndependentWitnesses(request:WitnessRequest,receipts:readonly WitnessReceipt[],
  policy:IndependentWitnessPolicy,expectedRecordDigest:string,rotations:readonly unknown[],context:ResolutionContext):
  Result<Readonly<{requestId:string;recordDigest:string;policyId:string;epoch:number;operators:readonly string[];timestampUpperBound:number}>> {
  try {
    const r=structuredClone(request),p=structuredClone(policy),rows=structuredClone(receipts);
    if(!r || !p || !Array.isArray(p.operators) || !Array.isArray(rows) || p.operators.length<1 || p.operators.length>16 || rows.length>16 ||
      !hash(p.id) || !integer(p.epoch) || p.epoch<1 || !integer(p.threshold) || p.threshold<1 || !integer(p.maxFaulty) ||
      p.threshold<=p.maxFaulty || p.threshold>p.operators.length-p.maxFaulty ||
      !hash(expectedRecordDigest) || r.recordDigest!==expectedRecordDigest || r.v!==1 ||
      r.policyId!==p.id || r.epoch!==p.epoch || !['rotate','revoke'].includes(r.operation) ||
      !integer(r.issuedAt) || !integer(r.expiresAt) || r.expiresAt<=r.issuedAt || r.expiresAt-r.issuedAt>600 ||
      !integer(context.now) || context.now<r.issuedAt || context.now>=r.expiresAt || !parsePrincipalId(r.principal).ok) return fail('bad-attestation');
    // Honest quorum intersection is necessary for single-successor rotation, but
    // also needs durable witness anti-equivocation; this arithmetic alone is not consensus.
    if(r.operation==='rotate' && 2*p.threshold-p.operators.length<=p.maxFaulty) return fail('bad-attestation');
    const operators=new Map<string,WitnessOperator>(),keys=new Set<string>();
    for(const op of p.operators) {
      if(!operator(op.id) || operators.has(op.id) || !Array.isArray(op.keys) || op.keys.length<1 || op.keys.length>4) return fail('bad-attestation');
      for(const k of op.keys) {
        if(!parsePrincipalId(k.key).ok || k.key===r.principal || keys.has(k.key) || !integer(k.notBefore) ||
          !integer(k.notAfter) || k.notBefore>=k.notAfter) return fail('bad-attestation');
        keys.add(k.key);
      }
      operators.set(op.id,op);
    }
    const account=verifySignedAt(r.principal,rotations,context,witnessRequestBytes(r),r.sig,r.issuedAt);
    if(!account.ok)return account;
    const history=context.history(r.principal,r.issuedAt,context.now);
    if(!history.ok)return history;
    if(history.value.key!==account.value.key || history.value.currentKey!==account.value.key || keys.has(account.value.key)) return fail('missing-history');
    const seen=new Set<string>();let upper=r.issuedAt;
    for(const receipt of rows) {
      const op=operators.get(receipt.operator);
      if(!op || seen.has(op.id) || !integer(receipt.observedAt) || receipt.observedAt<r.issuedAt ||
        receipt.observedAt>=r.expiresAt || receipt.observedAt>context.now) return fail('bad-attestation');
      const bytes=witnessReceiptBytes(r,op.id,receipt.observedAt);
      const valid=op.keys.some(k=>k.notBefore<=receipt.observedAt && receipt.observedAt<k.notAfter && verifyKeySignature(k.key,receipt.sig,bytes).ok);
      if(!valid)return fail('bad-attestation');
      seen.add(op.id);upper=Math.max(upper,receipt.observedAt);
    }
    if(seen.size<p.threshold)return fail('bad-attestation');
    return ok(Object.freeze({requestId:hex(sha256(witnessRequestBytes(r))),recordDigest:r.recordDigest,
      policyId:p.id,epoch:p.epoch,operators:Object.freeze([...seen].sort()),timestampUpperBound:upper}));
  }catch{return fail('bad-attestation');}
}
