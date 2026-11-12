import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parsePrincipalId, signWithKeyring, historyState, type ResolutionContext } from '../ids/src/index.js';
import { firstContactRequestBytes, parseFirstContactRequest, verifyFirstContactRequest,
  type FirstContactRequest } from '../contract/first-contact.ts';
const vectors = JSON.parse(readFileSync(new URL('../../vectors/first-contact/v1.json', import.meta.url), 'utf8'));
const records = JSON.parse(readFileSync(new URL('../../vectors/ids/records.json', import.meta.url), 'utf8'));
const raw = vectors.request;
const ctx: ResolutionContext = { ...records.context, now: raw.issuedAt + 20,
  links: new Map(records.context.links), pinnedIss: new Set(records.context.pinnedIss),
  history: (p, at, until) => ({ ok: true, value: historyState(p, [], at, until) }) };
function signed(patch: Partial<FirstContactRequest> = {}, scalar = 1): FirstContactRequest {
  const request = { ...raw, ...patch };
  const sender = parsePrincipalId(raw.sender); assert.equal(sender.ok, true);
  if (!sender.ok) throw Error('fixture principal');
  const key = new Uint8Array(32); key[31] = scalar;
  const result = signWithKeyring(key, firstContactRequestBytes(request), sender.value);
  if (!result.ok) throw Error(result.reason);
  return { ...request, sig: result.value };
}
const verify = (input: unknown, descriptor = vectors.descriptor, context = ctx) =>
  verifyFirstContactRequest(input, [], context, descriptor);

test('first contact shared canonical bytes preserve exact message and disclose no lane', () => {
  const request = signed();
  assert.equal(Buffer.from(firstContactRequestBytes(request)).toString('hex'), vectors.signingBytesHex);
  const result = verify(request); assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.requestId, vectors.requestId);
  assert.equal(result.value.replayKey, vectors.replayKey);
  assert.equal(result.value.request.message, raw.message);
  assert.deepEqual(Object.keys(result.value).sort(), ['replayKey', 'replayUntil', 'request', 'requestId']);
  assert.equal('allowed' in result.value, false);
  assert.equal('laneId' in result.value, false);
});

test('first contact binds every field and refuses wrong channel, revision, key and expiry', () => {
  const request = signed();
  for (const patch of [{ channelId: 'cd'.repeat(32) }, { descriptorRevision: 2 },
    { replyEpub: raw.sender }, { sender: raw.replyEpub }, { nonce: 'ef'.repeat(32) },
    { issuedAt: raw.issuedAt - 1 }, { expiresAt: raw.expiresAt - 1 }, { message: 'tampered' }]) {
    assert.equal(verify({ ...request, ...patch }).ok, false);
  }
  assert.equal(verify(request, { ...vectors.descriptor, revision: 2 }).ok, false);
  assert.equal(verify(request, vectors.descriptor, { ...ctx, now: raw.expiresAt }).ok, false);
  assert.equal(verify(request, vectors.descriptor, { ...ctx, now: raw.issuedAt - 1 }).ok, false);
  assert.equal(verify(request, { ...vectors.descriptor, maxLifetimeSeconds: 1 }).ok, false);
  assert.equal(verify(request, { ...vectors.descriptor, maxMessageBytes: 1 }).ok, false);
});

test('first contact replay key cannot change by re-signing or changing the message', () => {
  const a = verify(signed()), b = verify(signed({ message: 'different' }));
  assert.equal(a.ok, true); assert.equal(b.ok, true);
  if (!a.ok || !b.ok) return;
  assert.equal(a.value.replayKey, b.value.replayKey);
  assert.notEqual(a.value.requestId, b.value.requestId);
  const shorter = verify(signed({ expiresAt: ctx.now + 1 }));
  assert.equal(shorter.ok, true);
  if (!shorter.ok) return;
  assert.equal(shorter.value.replayKey, a.value.replayKey);
  assert.equal(shorter.value.replayUntil, vectors.descriptor.expiresAt);
  assert.equal(a.value.replayUntil, shorter.value.replayUntil);
  const seen = new Set([a.value.replayKey]);
  assert.equal(seen.has(b.value.replayKey), true);
});

test('first contact parser rejects coercions, getters, malformed unicode and oversized messages', () => {
  const request = signed(); let reads = 0;
  const hostile = { ...request };
  Object.defineProperty(hostile, 'message', { get() { reads++; throw Error('getter'); } });
  assert.equal(parseFirstContactRequest(hostile).ok, false); assert.equal(reads, 0);
  for (const patch of [{ extra: true }, { descriptorRevision: '1' }, { issuedAt: -0 },
    { message: '\ud800' }, { message: 'é'.repeat(2049) }, { nonce: 'AB'.repeat(32) },
    { replyEpub: 'https://attacker.example' }, { sig: '' }]) {
    assert.equal(parseFirstContactRequest({ ...request, ...patch }).ok, false);
  }
  assert.equal(verify(request, vectors.descriptor, { ...ctx, history: () => ({ ok: false, reason: 'missing-history' }) }).ok, false);
});

test('first contact does not accept a retired sender key', () => {
  const rotation = records.accept.find((row: { name: string }) => row.name === 'wallet-rotate').input;
  const request = signed({ issuedAt: rotation.issuedAt - 1, expiresAt: ctx.now + 100 });
  const result = verifyFirstContactRequest(request, [rotation], { ...ctx, now: records.context.now },
    { ...vectors.descriptor, expiresAt: ctx.now + 200, maxLifetimeSeconds: 86400 });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'unwitnessed-retired-key');
});
