/** Authenticated descriptor observation; does not claim discovery freshness. */
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '../ids/src/util.js';
import type { PrincipalId, ResolutionContext } from '../ids/src/index.js';
import type { FirstContactFloor, DescriptorFloor } from '../ids/src/first-contact-floor.js';
import { firstContactDescriptorBytes, verifyFirstContactDescriptor, type SignedFirstContactDescriptor } from './first-contact-descriptor.ts';
/** Call only on a cryptographically verified descriptor. Signature bytes are not
 * part of the floor: re-signing identical intent is not equivocation. */
export function firstContactDescriptorFloor(descriptor:SignedFirstContactDescriptor):DescriptorFloor {
  return Object.freeze({revision:descriptor.descriptor.revision,digest:hex(sha256(firstContactDescriptorBytes(descriptor)))});
}
/** Independently authenticated expected owner and bootstrap anchor are mandatory.
 * The store rechecks monotonic revision and same-revision digest atomically across
 * tabs. The supplied history callback must authenticate history at the given time.
 * A floor detects observed rollback; first-contact freshness still needs an
 * authenticated discovery protocol, including disabled channels. */
export async function observeFirstContactDescriptor(input:unknown,expectedOwner:PrincipalId,
  store:FirstContactFloor,rotations:readonly unknown[],context:ResolutionContext):Promise<SignedFirstContactDescriptor> {
  if(store.owner!==expectedOwner)throw Error('Wrong descriptor floor owner');
  const initial=verifyFirstContactDescriptor(input,expectedOwner,1,rotations,context);
  if(!initial.ok)throw Error(initial.reason);
  const descriptor=initial.value;
  await store.observe(firstContactDescriptorFloor(descriptor),now=>{
    const result=verifyFirstContactDescriptor(descriptor,expectedOwner,1,rotations,{...context,now});
    if(!result.ok)throw Error(result.reason);
  });
  return descriptor;
}
