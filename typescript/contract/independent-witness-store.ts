/** Retained membership floor. Origin storage is trusted; loss is never bootstrap. */
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '../ids/src/util.js';
import { openFirstContactFloor } from '../ids/src/first-contact-floor.js';
import type { PrincipalId, ResolutionContext } from '../ids/src/index.js';
import { independentWitnessPolicyBytes, type IndependentWitnessPolicy, type WitnessRequest, type WitnessReceipt } from './independent-witness.ts';
import { collectIndependentWitnesses, type WitnessTransport } from './independent-witness-client.ts';
import { admitIndependentWitnessRequest, verifyIndependentWitnesses } from './independent-witness.ts';
import { advanceIndependentWitnessPolicy } from './independent-witness-transition.ts';
const floor=(policy:IndependentWitnessPolicy)=>({revision:policy.epoch,digest:hex(sha256(independentWitnessPolicyBytes(policy)))});
function snapshot(policy:IndependentWitnessPolicy):IndependentWitnessPolicy {
  independentWitnessPolicyBytes(policy); // Reject accessors/unknown fields before cloning.
  const copy=structuredClone(policy);
  return Object.freeze({...copy,operators:Object.freeze(copy.operators.map(op=>Object.freeze({...op,
    keys:Object.freeze(op.keys.map(k=>Object.freeze({...k})))})))});
}
/** The anchor is independently authenticated operator membership, not server input.
 * Reuses the strict monotonic IndexedDB floor primitive in a separate namespace.
 * Only digests/epochs are retained: matching policy bytes may be fetched from an
 * untrusted cache, but missing or mismatching bytes cannot become trusted policy.
 */
export async function openIndependentWitnessPolicyStore(options:{name:string;principal:PrincipalId;
  anchor:IndependentWitnessPolicy;now:()=>number;create?:boolean;indexedDB?:IDBFactory}) {
  if(typeof options.name!=='string'||!options.name)throw Error('Witness policy store name required');
  const anchor=snapshot(options.anchor),principal=options.principal;
  const store=await openFirstContactFloor({name:`sociacl-independent-witness:${options.name}:${anchor.id}`,
    owner:principal,anchor:floor(anchor),now:options.now,create:options.create,indexedDB:options.indexedDB});
  async function read(candidate:IndependentWitnessPolicy){
    const copy=snapshot(candidate),expected=floor(copy),saved=await store.read();
    if(copy.id!==anchor.id||expected.revision!==saved.revision||expected.digest!==saved.digest)throw Error('Witness policy continuity mismatch');
    return copy;
  }
  return Object.freeze({read,close:()=>store.close(),
    /** Collection is usable only if the exact retained membership still applies
     * when results commit. A concurrent transition cannot return an old quorum. */
    async collect(request:WitnessRequest,expectedDigest:string,candidate:IndependentWitnessPolicy,
      currentState:()=>{rotations:readonly unknown[];context:ResolutionContext},
      transports:ReadonlyMap<string,WitnessTransport>,timeoutMs=10000) {
      const policy=await read(candidate);
      const initial=currentState();
      const admitted=admitIndependentWitnessRequest(request,policy,expectedDigest,initial.rotations,initial.context);
      if(!admitted.ok)throw Error(admitted.reason);
      if(admitted.value.request.principal!==principal)throw Error('Wrong witness principal');
      const result=await collectIndependentWitnesses(admitted.value.request,expectedDigest,initial.rotations,
        ()=>policy,()=>currentState().context,transports,timeoutMs);
      await store.observe(floor(policy),now=>{
        const state=currentState();
        const verified=verifyIndependentWitnesses(result.request,result.receipts,policy,expectedDigest,
          state.rotations,{...state.context,now});
        if(!verified.ok)throw Error(verified.reason);
      });
      return result;
    },
    async advance(previous:IndependentWitnessPolicy,next:IndependentWitnessPolicy,
      oldRequest:WitnessRequest,oldReceipts:readonly WitnessReceipt[],newRequest:WitnessRequest,newReceipts:readonly WitnessReceipt[],
      currentState:()=>{rotations:readonly unknown[];context:ResolutionContext}) {
      const prior=snapshot(previous),candidate=snapshot(next);
      // Authenticate before cloning any untrusted request/response objects.
      const initial=currentState();
      advanceIndependentWitnessPolicy(prior,candidate,principal,oldRequest,oldReceipts,newRequest,newReceipts,initial.rotations,initial.context);
      const bundle=structuredClone({oldRequest,oldReceipts,newRequest,newReceipts});
      await read(prior);
      await store.observe(floor(candidate),now=>{
        const state=currentState();
        advanceIndependentWitnessPolicy(prior,candidate,principal,bundle.oldRequest,bundle.oldReceipts,
          bundle.newRequest,bundle.newReceipts,state.rotations,{...state.context,now});
      });
      return candidate;
    },
  });
}
