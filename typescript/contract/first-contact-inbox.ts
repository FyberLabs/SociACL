/** Reference recipient workflow. The UI explicitly calls accept; receiving never grants. */
import type { ResolutionContext } from '../ids/src/index.js';
import type { FirstContactStore } from '../ids/src/first-contact-store.js';
import { openFirstContactRequest } from './first-contact-seal.ts';
import type { VerifiedFirstContact } from './first-contact.ts';
import { sealContactLaneGrant, type ContactLaneGrant } from './contact-lane-seal.ts';
import type { AccountKeyring } from './account-keyring.ts';

/** Returns plaintext only after the replay reservation commits. */
export async function receiveFirstContact(store: FirstContactStore, envelope: Uint8Array,
  epriv: string, senderRotations: readonly unknown[], context: ResolutionContext): Promise<VerifiedFirstContact> {
  const descriptor = await store.descriptor();
  const snapshot = new Uint8Array(envelope);
  const opened = openFirstContactRequest(snapshot, epriv, descriptor, senderRotations, context);
  if (!opened.ok) throw Error(opened.reason);
  const v = opened.value;
  if (!await store.reserve(descriptor, { replayKey:v.replayKey,requestId:v.requestId,
    replayUntil:v.replayUntil,expiresAt:v.request.expiresAt,envelope:snapshot })) throw Error('first-contact-replayed');
  return v;
}

/** Explicit recipient acceptance. Reloads the committed ciphertext and verifies it
 * with fresh caller-supplied histories before sealing the existing lane grant.
 * No grant leaves this function until its outbox transaction commits. Retry a lost
 * response from the committed outbox; never turn a duplicate receive into acceptance.
 */
export async function acceptFirstContactRequest(store: FirstContactStore, replayKey: string,
  epriv: string, keyring: AccountKeyring, senderRotations: readonly unknown[],
  senderContext: ResolutionContext, recipientRotations: readonly unknown[],
  recipientContext: ResolutionContext): Promise<ContactLaneGrant> {
  if (keyring.principal !== store.owner) throw Error('wrong-recipient');
  const descriptor = await store.descriptor();
  const row = (await store.pending()).find(r => r.replayKey === replayKey);
  if (!row) throw Error('first-contact-not-pending');
  const opened = openFirstContactRequest(row.envelope, epriv, descriptor, senderRotations, senderContext);
  if (!opened.ok) throw Error(opened.reason);
  const v = opened.value;
  if (v.replayKey !== replayKey || v.requestId !== row.requestId || v.replayUntil !== row.replayUntil) throw Error('first-contact-record-mismatch');
  const grant = sealContactLaneGrant(keyring,v.request.sender,senderRotations,senderContext,recipientRotations,recipientContext);
  await store.decide(descriptor,replayKey,v.requestId,{status:'accepted',ciphertextHex:grant.ciphertextHex,rotationSeq:keyring.rotationSeq});
  return grant;
}
