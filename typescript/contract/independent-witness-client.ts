/** Multi-operator collection. Provisioned transports are trusted configuration. */
import { verifyKeySignature } from '../ids/src/index.js';
import type { ResolutionContext } from '../ids/src/index.js';
import { data, integer, hex } from '../ids/src/util.js';
import { admitIndependentWitnessRequest, independentWitnessPolicyBytes, verifyIndependentWitnesses, witnessReceiptBytes,
  type WitnessRequest, type WitnessReceipt, type IndependentWitnessPolicy } from './independent-witness.ts';
export type WitnessTransport = (request:Readonly<WitnessRequest>,signal:AbortSignal)=>Promise<unknown>;
/** Never accepts URLs or membership from returned data. Each transport is bound to
 * exactly one provisioned operator. Failed/malformed operators count as outages.
 * Both context and policy providers must return current independently authenticated
 * state. A membership change during collection invalidates this attempt.
 */
export async function collectIndependentWitnesses(request:WitnessRequest,expectedRecordDigest:string,
  rotations:readonly unknown[],currentPolicy:()=>IndependentWitnessPolicy,currentContext:()=>ResolutionContext,
  transports:ReadonlyMap<string,WitnessTransport>,timeoutMs=10000) {
  if(!integer(timeoutMs) || timeoutMs<1 || timeoutMs>10000)throw Error('Invalid witness deadline');
  const context=currentContext(), startedAt=context.now;
  const admitted=admitIndependentWitnessRequest(request,currentPolicy(),expectedRecordDigest,rotations,context);
  if(!admitted.ok)throw Error(admitted.reason);
  // Snapshot only sanitized own-data fields, before handing anything to a transport.
  const r=Object.freeze({...admitted.value.request});
  const p=structuredClone(admitted.value.policy), policyBytes=hex(independentWitnessPolicyBytes(p));
  const deadlineAt=performance.now()+timeoutMs;
  const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
  const deadline=new Promise<undefined>(resolve=>{timer=setTimeout(()=>{controller.abort();resolve(undefined);},timeoutMs);});
  try {
    const results=await Promise.all(p.operators.map(async op=>{
      const transport=transports.get(op.id);if(!transport)return undefined;
      try {
        const value=await Promise.race([Promise.resolve().then(()=>transport(r,controller.signal)),deadline]);
        const parsed=data(value);if(!parsed.ok)return undefined;
        const row=parsed.value;
        if(Object.keys(row).sort().join()!=='observedAt,operator,sig' || row.operator!==op.id ||
          !integer(row.observedAt) || typeof row.sig!=='string' || row.sig.length!==86)return undefined;
        const at=row.observedAt as number;
        if(at<r.issuedAt || at>=r.expiresAt)return undefined;
        const bytes=witnessReceiptBytes(r,op.id,at);
        if(!op.keys.some(k=>k.notBefore<=at && at<k.notAfter && verifyKeySignature(k.key,row.sig as string,bytes).ok))return undefined;
        if(performance.now()>=deadlineAt)return undefined;
        return Object.freeze({operator:op.id,observedAt:at,sig:row.sig});
      }catch{return undefined;}
    }));
    const fresh=currentContext();
    if(fresh.now<startedAt)throw Error('Witness clock rollback');
    const readmitted=admitIndependentWitnessRequest(r,currentPolicy(),expectedRecordDigest,rotations,fresh);
    if(!readmitted.ok || hex(independentWitnessPolicyBytes(readmitted.value.policy))!==policyBytes)throw Error('Witness policy or account changed');
    const receipts=results.filter((row):row is WitnessReceipt=>row!==undefined && row.observedAt<=fresh.now);
    const observed=verifyIndependentWitnesses(r,receipts,p,expectedRecordDigest,rotations,fresh);
    if(!observed.ok)throw Error(observed.reason);
    return Object.freeze({request:r,receipts:Object.freeze(receipts),observation:observed.value});
  }finally{if(timer!==undefined)clearTimeout(timer);controller.abort();}
}
