/**
 * Per-contact inbox lanes.
 *
 * The contact-lane secret is 32 random bytes on the keyring. It is not
 * the disclosed base lane id. A contact lane id is HKDF-SHA256 of that
 * secret. The recipient seals the id to the sender's resolved currentEpub.
 * The signature is inside that ciphertext. Storage indexes the lane id
 * hex and nothing else. A lane is delivery only. It does not grant.
 *
 * This module does not wire Panopticon or Gun, and it does not open a
 * first-contact transport. Those are SociACL#71 and SociACL#70. The signed
 * first-contact request below belongs inside a separate confidential envelope;
 * no lane grant exists until recipient acceptance. Never publish the parties
 * or a verifiable signature beside ciphertext.
 */
export {
  deriveContactLane,
  laneLookupKey,
  openContactLaneGrant,
  regrantContactLanes,
  resolveContactLane,
  sealContactLaneGrant,
} from "./contact-lane-seal.ts";
export type { ContactLaneGrant, ContactTarget, OpenedContactLane } from "./contact-lane-seal.ts";

export { firstContactRequestBytes, parseFirstContactRequest, verifyFirstContactRequest } from './first-contact.ts';
export type { FirstContactRequest, FirstContactDescriptor, VerifiedFirstContact } from './first-contact.ts';
