/** Explicit recipient decision over the existing atomic replay/outbox journal. */
import type { FirstContactStore } from '../ids/src/first-contact-store.js';
import type { ContactLaneIssuerState, ContactLaneRecipientState } from '../ids/src/contact-lane.js';
import { openFirstContactRequestBrowser } from './first-contact-browser.ts';
import { verifyFirstContactRequest } from './first-contact.ts';
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
  const grant = await sealContactLaneGrant(value.request.sender, currentSender, currentIssuer);
  const fresh = currentSender(), owner = currentIssuer();
  if (!verifyFirstContactRequest(value.request, fresh.rotations, fresh.context, descriptor).ok ||
      owner.issuer.principal !== store.owner || owner.issuer.rotationSeq !== seq) throw Error('first-contact-stale');
  await store.decide(descriptor, replayKey, expectedRequestId, { status: 'accepted', ciphertextHex: grant.ciphertextHex, rotationSeq: seq });
  return grant;
}
