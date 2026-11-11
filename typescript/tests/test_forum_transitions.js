import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { historyState, objectRecordBytes, signWithKeyring, seeGrantBytes } from '../ids/src/index.js';
import { putObject, admitRow, admittedOwner } from '../src/see.js';
import { acceptForumNeedTransition as needStep, acceptForumOfferTransition as offerStep } from '../src/gun.js';
const doc = JSON.parse(readFileSync(new URL('../../vectors/mesh/forums.json', import.meta.url)));
const vector = JSON.parse(readFileSync(new URL('../../vectors/mesh/v2/see.json', import.meta.url)));
function sign(bytes) {
  const scalar = new Uint8Array(32); scalar[31] = 1;
  const signed = signWithKeyring(scalar, bytes, doc.seaPubkey);
  assert.equal(signed.ok, true); return signed.value;
}
function setup() {
  const graph = {}, raw = vector.context;
  const resolver = { rotations: () => [], ctx: { ...raw, links: new Map(), pinnedIss: new Set(raw.pinnedIss),
    history: (principal, at, until) => ({ ok: true, value: historyState(principal, [], at, until) }) } };
  const source = vector.accept.find(row => row.name === 'equal-ham-cancel-wins');
  const record = { ...source.steps[0].record, object: doc.needId };
  record.sig = sign(objectRecordBytes(record));
  assert.equal(putObject(graph, record, resolver).ok, true);
  const need = { id: doc.needId, forumId: doc.forumId, subject: doc.secondPubkey,
    severity: 'need', body: 'help', stated: 1, hamState: 1, ts: 10 };
  const offer = { id: doc.offerId, forumId: need.forumId, need: need.id, helper: doc.seaPubkey,
    body: 'offering help', artifacts: '', stated: 1 };
  return { graph, resolver, source, need, offer };
}
const closed = (need, offer) => ({ ...need, stated: 0, acceptedOffer: offer.id, hamState: need.hamState + 1 });

test('forum transitions: stored offer, subject accept, owner-only reopen and no election', () => {
  const { graph, need, offer } = setup();
  const owner = admittedOwner(graph, need.id);
  assert.equal(needStep(graph, need, closed(need, offer), offer, need.subject, 10).ok, false);
  assert.equal(offerStep(graph, need, undefined, offer, offer.helper, 10).ok, true);
  assert.equal(admittedOwner(graph, offer.id), undefined);
  const resolved = needStep(graph, need, closed(need, offer), offer, need.subject, 10);
  assert.equal(resolved.ok, true);
  assert.equal(offerStep(graph, resolved.need, offer, { ...offer, stated: 0 }, offer.helper, 10).ok, false);
  const reopened = { ...need, hamState: 3 };
  assert.equal(needStep(graph, resolved.need, reopened, undefined, need.subject, 10).ok, false);
  assert.equal(needStep(graph, resolved.need, reopened, undefined, offer.helper, 10).ok, true);
  assert.deepEqual(admittedOwner(graph, need.id), owner);
});

test('forum transitions: withdrawals are tombstones and returned rows cannot mutate stored offers', () => {
  const { graph, need, offer } = setup();
  const posted = offerStep(graph, need, undefined, offer, offer.helper, 10);
  assert.equal(posted.ok, true); posted.offer.body = 'tampered';
  assert.equal(needStep(graph, need, closed(need, offer), posted.offer, need.subject, 10).ok, false);
  assert.equal(needStep(graph, need, closed(need, offer), offer, need.subject, 10).ok, true);
  assert.equal(offerStep(graph, need, offer, { ...offer, stated: 0 }, need.subject, 10).ok, true);
  assert.equal(offerStep(graph, need, undefined, offer, offer.helper, 10).ok, false);
  assert.equal(needStep(graph, need, closed(need, offer), offer, need.subject, 10).ok, false);
});

test('forum transitions: immutable fields, invalid times, unknown admission and raw Check booleans fail', () => {
  const { graph, need, offer } = setup();
  for (const patch of [{ body: 'changed' }, { severity: 'emergency' }, { subject: offer.helper },
    { forumId: doc.wrongForumId }, { spec: doc.specId }, { hamState: 1 }, { hamState: NaN },
    { stated: 0 }, { acceptedOffer: offer.id }]) {
    assert.equal(needStep(graph, need, { ...need, hamState: 2, ...patch }, undefined, offer.helper, 10).ok, false);
  }
  for (const now of [-1, NaN, Infinity, 1.5]) {
    assert.equal(offerStep(graph, need, undefined, offer, offer.helper, now).ok, false);
  }
  assert.equal(offerStep({ allowed: true, ownerOf: () => offer.helper }, need, undefined, offer, offer.helper, 10).ok, false);
  assert.equal(needStep({}, need, { ...need, hamState: 2 }, undefined, offer.helper, 10).ok, false);
  assert.equal(needStep(graph, need, { ...need, hamState: 2 }, undefined, need.subject, 10).ok, false);
  assert.equal(needStep(graph, need, { ...need, hamState: 2 }, undefined, offer.helper, 10).ok, true);
});

test('forum transitions: helper cancellation between posting and accepting is enforced', () => {
  const { graph, resolver, source, need, offer } = setup();
  const grant = { ...source.steps[1].row, object: need.id };
  grant.sig = sign(seeGrantBytes(grant));
  assert.equal(admitRow(graph, grant, resolver).ok, true);
  const helperOffer = { ...offer };
  const point = Buffer.concat(need.subject.split('.').map(part => Buffer.from(part, 'base64url'))).toString('hex');
  helperOffer.id = `offer_p_${point}_${'07'.repeat(16)}`; helperOffer.helper = need.subject;
  assert.equal(grant.accessor, need.subject);
  assert.equal(offerStep(graph, need, undefined, helperOffer, need.subject, 10).ok, true);
  const cancel = { ...source.steps[2].row, object: need.id };
  cancel.sig = sign(seeGrantBytes(cancel));
  assert.equal(admitRow(graph, cancel, resolver).ok, true);
  assert.equal(needStep(graph, need, closed(need, helperOffer), helperOffer, offer.helper, 10).ok, false);
});

const transitions = JSON.parse(readFileSync(new URL('../../vectors/mesh/forum-transitions.json', import.meta.url)));
for (const entry of transitions.cases) {
  test(`shared forum transition: ${entry.name}`, () => {
    const { graph, need, offer } = setup();
    const patch = { ...entry.patch };
    if (patch.acceptedOffer === '$offer') patch.acceptedOffer = offer.id;
    const result = needStep(graph, need, { ...need, hamState: 2, ...patch }, undefined, offer.helper, 10);
    assert.equal(result.ok, entry.ok);
  });
}
