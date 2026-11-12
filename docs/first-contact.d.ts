/** Decrypted first-contact payload only. No network endpoint or grant authority. */
import type { PrincipalId, ResolutionContext, Result } from './identity-consume/types.js';
export const FIRST_CONTACT_DOMAIN: 'sociacl-first-contact-request-v1';
export const FIRST_CONTACT_REPLAY_DOMAIN: 'sociacl-first-contact-replay-v1';
export const FIRST_CONTACT_MAX_MESSAGE_BYTES: 4096;
export type FirstContactRequest = Readonly<{
  v: 1; channelId: string; descriptorRevision: number; sender: PrincipalId;
  /** Dedicated ephemeral P-256 encryption point, not an identity assertion. */
  replyEpub: PrincipalId; nonce: string; issuedAt: number; expiresAt: number;
  message: string; sig: string;
}>;
/** Recipient-owned policy, never sourced from the request itself. */
export type FirstContactDescriptor = Readonly<{
  channelId: string; revision: number; expiresAt: number;
  maxLifetimeSeconds: number; maxMessageBytes: number;
}>;
export type VerifiedFirstContact = Readonly<{
  request: FirstContactRequest; requestId: string; replayKey: string;
}>;
export function firstContactRequestBytes(request: Omit<FirstContactRequest, 'sig'>): Uint8Array;
export function parseFirstContactRequest(input: unknown): Result<FirstContactRequest>;
/**
 * Caller supplies complete authenticated history and recipient policy. After
 * success, atomically consume replayKey in durable state until request expiry
 * before display/acceptance. Missing replay state fails closed. Do not send this
 * plaintext to storage: sender, reply point, message and signature are encrypted.
 */
export function verifyFirstContactRequest(input: unknown, rotations: readonly unknown[],
  context: ResolutionContext, descriptor: FirstContactDescriptor): Result<VerifiedFirstContact>;
