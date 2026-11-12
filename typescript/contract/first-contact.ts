/** Signed plaintext INSIDE a confidential first-contact envelope; never a grant. */
import { sha256 } from '@noble/hashes/sha2.js';
import { parsePrincipalId, verifySignedAt } from '../ids/src/index.js';
import type { PrincipalId, ResolutionContext, Result } from '../ids/src/index.js';
import { data, integer, lp, hex, fail, ok } from '../ids/src/util.js';

export const FIRST_CONTACT_DOMAIN = 'sociacl-first-contact-request-v1';
export const FIRST_CONTACT_REPLAY_DOMAIN = 'sociacl-first-contact-replay-v1';
export const FIRST_CONTACT_MAX_MESSAGE_BYTES = 4096;
export type FirstContactRequest = Readonly<{
  v: 1; channelId: string; descriptorRevision: number; sender: PrincipalId;
  replyEpub: PrincipalId; nonce: string; issuedAt: number; expiresAt: number;
  message: string; sig: string;
}>;
/** Trusted recipient configuration, obtained independently of the request. */
export type FirstContactDescriptor = Readonly<{
  channelId: string; revision: number; expiresAt: number;
  maxLifetimeSeconds: number; maxMessageBytes: number;
}>;
export type VerifiedFirstContact = Readonly<{
  request: FirstContactRequest; requestId: string; replayKey: string; replayUntil: number;
}>;
const hex32 = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const wellFormed = (s: string) => !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);

/** Encode already validated fields with little-endian UTF-8 length prefixes. */
export function firstContactRequestBytes(r: Omit<FirstContactRequest, 'sig'>): Uint8Array {
  return lp([FIRST_CONTACT_DOMAIN, String(r.v), r.channelId, String(r.descriptorRevision),
    r.sender, r.replyEpub, r.nonce, String(r.issuedAt), String(r.expiresAt), r.message]);
}

/** Snapshot data properties; no coercion, getters, normalization or extra fields. */
export function parseFirstContactRequest(input: unknown): Result<FirstContactRequest> {
  const d = data(input); if (!d.ok) return d;
  const r = d.value;
  if (Object.keys(r).sort().join() !== 'channelId,descriptorRevision,expiresAt,issuedAt,message,nonce,replyEpub,sender,sig,v' ||
      r.v !== 1 || !hex32(r.channelId) || !hex32(r.nonce) ||
      !integer(r.descriptorRevision) || (r.descriptorRevision as number) < 1 ||
      !integer(r.issuedAt) || !integer(r.expiresAt) || (r.expiresAt as number) <= (r.issuedAt as number)) return fail('bad-record');
  const sender = parsePrincipalId(r.sender), reply = parsePrincipalId(r.replyEpub);
  if (!sender.ok) return sender; if (!reply.ok) return reply;
  if (typeof r.sig !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(r.sig) ||
      typeof r.message !== 'string' || r.message.length > FIRST_CONTACT_MAX_MESSAGE_BYTES ||
      !wellFormed(r.message) || new TextEncoder().encode(r.message).length > FIRST_CONTACT_MAX_MESSAGE_BYTES) return fail('bad-record');
  return ok(Object.freeze({ v: 1, channelId: r.channelId, descriptorRevision: r.descriptorRevision as number,
    sender: sender.value, replyEpub: reply.value, nonce: r.nonce, issuedAt: r.issuedAt as number,
    expiresAt: r.expiresAt as number, message: r.message, sig: r.sig }));
}

/** Authenticate after decryption. No network, replay-store mutation, lane or grant.
 * Before displaying/accepting, atomically reserve replayKey until replayUntil using
 * durable recipient-owned state. Missing replay state fails closed. The signature
 * is not proof of sender possession beyond this message and never grants access.
 */
export function verifyFirstContactRequest(input: unknown, rotations: readonly unknown[],
  context: ResolutionContext, descriptor: FirstContactDescriptor): Result<VerifiedFirstContact> {
  const parsed = parseFirstContactRequest(input); if (!parsed.ok) return parsed;
  if (!context || !integer(context.now) || !descriptor || !hex32(descriptor.channelId) ||
      !integer(descriptor.revision) || descriptor.revision < 1 || !integer(descriptor.expiresAt) ||
      !integer(descriptor.maxLifetimeSeconds) || descriptor.maxLifetimeSeconds < 1 ||
      !integer(descriptor.maxMessageBytes) || descriptor.maxMessageBytes < 1 ||
      descriptor.maxMessageBytes > FIRST_CONTACT_MAX_MESSAGE_BYTES) return fail('bad-record');
  const r = parsed.value;
  if (r.channelId !== descriptor.channelId || r.descriptorRevision !== descriptor.revision ||
      r.expiresAt > descriptor.expiresAt || r.expiresAt - r.issuedAt > descriptor.maxLifetimeSeconds ||
      new TextEncoder().encode(r.message).length > descriptor.maxMessageBytes) return fail('bad-record');
  if (context.now < r.issuedAt) return fail('future-record');
  if (context.now >= r.expiresAt || context.now >= descriptor.expiresAt) return fail('expired');
  const bytes = firstContactRequestBytes(r);
  const proof = verifySignedAt(r.sender, rotations, context, bytes, r.sig, r.issuedAt);
  if (!proof.ok) return proof;
  // Independently authenticated complete history must agree with raw resolution.
  // Missing transport history cannot be treated as an empty genesis account.
  try {
    const history = context.history(r.sender, r.issuedAt, context.now);
    if (!history.ok) return history;
    if (history.value.key !== proof.value.key || history.value.currentKey !== proof.value.key) return fail('missing-history');
  } catch { return fail('missing-history'); }
  const replay = lp([FIRST_CONTACT_REPLAY_DOMAIN, r.channelId, String(r.descriptorRevision), r.sender, r.nonce]);
  return ok(Object.freeze({ request: r, requestId: hex(sha256(bytes)), replayKey: hex(sha256(replay)), replayUntil: descriptor.expiresAt }));
}
