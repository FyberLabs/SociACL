/** Explicit recipient decision over the existing atomic replay/outbox journal. */
import type { FirstContactStore } from '../ids/src/first-contact-store.js';
import type { ContactLaneIssuerState, ContactLaneRecipientState } from '../ids/src/contact-lane.js';
import { openFirstContactRequestBrowser } from './first-contact-browser.ts';
import { verifyFirstContactRequest } from './first-contact.ts';
import { resolveCurrentKey, parsePrincipalId } from '../ids/src/index.js';
import { integer } from '../ids/src/util.js';
import { sealContactLaneGrant } from './contact-lane-browser.ts';

/** Never accepts on receive. expectedRequestId binds the click to the displayed
 * request; concurrent rejection/descriptor changes fail in store.decide. A lost
 * response is retried from the existing committed outbox, not by accepting again.
 */
export async function acceptFirstContactRequest(store: FirstContactStore, replayKey: string,
  expectedRequestId: string, epriv: string, senderState: ContactLaneRecipientState,
  issuerState: ContactLaneIssuerState) {
  const selected = issuerState();
  const bound = { ...selected.issuer, baseLaneIds: [...selected.issuer.baseLaneIds], contactSecrets: [...selected.issuer.contactSecrets] };
  if (bound.principal !== store.owner) throw Error('wrong-recipient');
  let ownerTime = selected.context.now, senderTime = -1;
  const currentIssuer: ContactLaneIssuerState = () => {
    const state = issuerState(), key = state.issuer;
    if (!integer(state.context.now) || state.context.now < ownerTime ||
        key.principal !== bound.principal || key.signingPriv !== bound.signingPriv ||
        key.contactSecretHex !== bound.contactSecretHex || key.rotationSeq !== bound.rotationSeq ||
        JSON.stringify(key.baseLaneIds) !== JSON.stringify(bound.baseLaneIds) ||
        JSON.stringify(key.contactSecrets) !== JSON.stringify(bound.contactSecrets)) throw Error('first-contact-stale');
    ownerTime = state.context.now; return state;
  };
  const currentSender: ContactLaneRecipientState = () => {
    const state = senderState();
    if (!integer(state.context.now) || state.context.now < senderTime) throw Error('first-contact-stale');
    senderTime = state.context.now; return state;
  };
  const descriptor = Object.freeze({ ...await store.descriptor() });
  const row = (await store.pending(descriptor)).find(value => value.replayKey === replayKey);
  if (!row || row.status !== 'pending' || row.requestId !== expectedRequestId || row.revision !== descriptor.revision) throw Error('first-contact-not-pending');
  const envelope = new Uint8Array(row.envelope);
  const opened = await openFirstContactRequestBrowser(envelope, epriv, descriptor, currentSender);
  if (!opened.ok) throw Error(opened.reason);
  const value = opened.value;
  if (value.replayKey !== replayKey || value.requestId !== expectedRequestId || value.replayUntil !== row.replayUntil ||
      value.request.expiresAt !== row.expiresAt) throw Error('first-contact-record-mismatch');
  const initial = currentIssuer();
  if (initial.issuer.principal !== store.owner) throw Error('wrong-recipient');
  const seq = initial.issuer.rotationSeq;
  const recipient = parsePrincipalId(store.owner);
  if (!recipient.ok) throw Error('wrong-recipient');
  const peer = currentSender();
  const peerAuthority = resolveCurrentKey(value.request.sender, peer.rotations, peer.context);
  const ownerAuthority = resolveCurrentKey(recipient.value, initial.rotations, initial.context);
  if (!peerAuthority.ok || !peerAuthority.value.currentEpub || !ownerAuthority.ok) throw Error('first-contact-stale');
  const peerKey = peerAuthority.value.currentKey, peerEpub = peerAuthority.value.currentEpub,
    peerSeq = peerAuthority.value.rotations.length, ownerKey = ownerAuthority.value.currentKey;
  const validateAuthority = () => {
    const fresh = currentSender(), owner = currentIssuer();
    const sender = resolveCurrentKey(value.request.sender, fresh.rotations, fresh.context);
    const recipientNow = resolveCurrentKey(recipient.value, owner.rotations, owner.context);
    const senderHistory = fresh.context.history(value.request.sender, fresh.context.now, fresh.context.now);
    const ownerHistory = owner.context.history(recipient.value, owner.context.now, owner.context.now);
    if (!verifyFirstContactRequest(value.request, fresh.rotations, fresh.context, descriptor).ok ||
        !sender.ok || sender.value.currentKey !== peerKey || sender.value.currentEpub !== peerEpub || sender.value.rotations.length !== peerSeq ||
        !recipientNow.ok || recipientNow.value.currentKey !== ownerKey || recipientNow.value.rotations.length !== seq ||
        !senderHistory.ok || senderHistory.value.currentKey !== peerKey || !ownerHistory.ok || ownerHistory.value.currentKey !== ownerKey)
      throw Error('first-contact-stale');
  };
  validateAuthority();
  const grant = await sealContactLaneGrant(value.request.sender, currentSender, currentIssuer);
  validateAuthority();
  await store.decide(descriptor, replayKey, expectedRequestId,
    { status: 'accepted', ciphertextHex: grant.ciphertextHex, rotationSeq: seq }, validateAuthority);
  validateAuthority();
  return grant;
}
