/** Joint old/new quorum authorization; persistence and independent bootstrap belong to the caller. */
import { sha256 } from '@noble/hashes/sha2.js';
import { hex, lp } from '../ids/src/util.js';
import type { PrincipalId, ResolutionContext } from '../ids/src/index.js';
import { independentWitnessPolicyBytes, verifyIndependentWitnesses,
  type IndependentWitnessPolicy, type WitnessRequest, type WitnessReceipt } from './independent-witness.ts';
export function independentWitnessTransitionDigest(previous:IndependentWitnessPolicy,next:IndependentWitnessPolicy):string {
  return hex(sha256(lp(['sociacl-independent-witness-transition-v1',
    hex(sha256(independentWitnessPolicyBytes(previous))),hex(sha256(independentWitnessPolicyBytes(next)))])));
}
/** `previous` is the latest independently trusted, durably retained policy. Never
 * bootstrap it from this proposal. Both account-signed requests must bind this exact
 * transition and independently satisfy rotation quorum under their respective policy.
 * The caller must atomically CAS previous -> returned policy before installing it.
 */
export function advanceIndependentWitnessPolicy(previous:IndependentWitnessPolicy,next:IndependentWitnessPolicy,
  principal:PrincipalId,oldRequest:WitnessRequest,oldReceipts:readonly WitnessReceipt[],
  newRequest:WitnessRequest,newReceipts:readonly WitnessReceipt[],rotations:readonly unknown[],context:ResolutionContext):IndependentWitnessPolicy {
  const digest=independentWitnessTransitionDigest(previous,next);
  if(next.id!==previous.id||next.epoch!==previous.epoch+1||
    oldRequest.principal!==principal||newRequest.principal!==principal||
    oldRequest.operation!=='rotate'||newRequest.operation!=='rotate')throw Error('Invalid witness transition');
  const oldProof=verifyIndependentWitnesses(oldRequest,oldReceipts,previous,digest,rotations,context);
  const newProof=verifyIndependentWitnesses(newRequest,newReceipts,next,digest,rotations,context);
  if(!oldProof.ok||!newProof.ok)throw Error('Witness transition lacks joint quorum');
  return Object.freeze({...next,operators:Object.freeze(next.operators.map(op=>Object.freeze({...op,
    keys:Object.freeze(op.keys.map(k=>Object.freeze({...k})))})))});
}
