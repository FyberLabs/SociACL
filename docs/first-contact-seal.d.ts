/** Reference contract only; not a public request endpoint or replay store. */
import type { ResolutionContext, Result } from './identity-consume/types.js';
import type { FirstContactDescriptor, VerifiedFirstContact } from './first-contact.js';
export const FIRST_CONTACT_SEAL_DOMAIN: 'sociacl-first-contact-seal-v1';
export const FIRST_CONTACT_ENVELOPE_MAX_BYTES: 8192;
/** Independently authenticated recipient configuration, immutable per revision. */
export type FirstContactSealDescriptor = FirstContactDescriptor & Readonly<{ encryptionEpub: string }>;
/** Fresh random ephemeral P-256 key and nonce; sealing is not sender authentication. */
export function sealFirstContactRequest(input: unknown, descriptor: FirstContactSealDescriptor): Uint8Array;
/**
 * Authenticated decryption followed by current sender/history verification.
 * Before display/acceptance atomically reserve replayKey through replayUntil in
 * durable recipient-owned state. Success creates no lane, grant or ACL authority.
 */
export function openFirstContactRequest(envelope: Uint8Array, recipientEpriv: string,
  descriptor: FirstContactSealDescriptor, rotations: readonly unknown[],
  context: ResolutionContext): Result<VerifiedFirstContact>;
