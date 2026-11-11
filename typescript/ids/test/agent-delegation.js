import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import * as ids from '../src/index.js';
const fixture = JSON.parse(readFileSync(new URL('../../../vectors/ids/records.json', import.meta.url), 'utf8'));
const secret = n => Uint8Array.from([...Array(31).fill(0), n]);
const principal = n => ids.principalFromSec1(p256.getPublicKey(secret(n), false)).value;
const owner = principal(1), agent = principal(2), now = fixture.context.now;
const ctx = { ...fixture.context, links: new Map(), pinnedIss: new Set(fixture.context.pinnedIss),
  history: (p, at, until) => ({ ok: true, value: ids.historyState(p, [], at, until) }) };
const b64 = b => Buffer.from(b).toString('base64url');
const sign = (bytes, n = 1) => b64(p256.sign(bytes, secret(n), { prehash: true, format: 'compact' }));
function grant(overrides = {}) {
  const row = { v: 1, principal: owner, agent, audience: 'https://s3r.ch', scopes: ['forum:read', 'turn:allocate'],
    nonce: 'ab'.repeat(32), issuedAt: now - 10, expiresAt: now + 300, ...overrides };
  return { ...row, sig: sign(ids.agentDelegationBytes(row)) };
}
const request = { audience: 'https://s3r.ch', agent, scopes: ['forum:read'], revocations: [] };
const verify = (row, req = request, context = ctx) => ids.verifyAgentDelegation(row, [], context, req);
test('owner-signed delegation permits only the specified agent, audience and exact scopes', () => {
  const row = grant(); assert.equal(verify(row).ok, true);
  for (const change of [{ agent: principal(3) }, { audience: 'https://other.example' },
    { scopes: ['forum:write'] }, { scopes: ['forum'] }, { scopes: ['*'] }, { scopes: [] }]) {
    assert.equal(verify(row, { ...request, ...change }).ok, false);
  }
  for (const key of ['agent', 'principal', 'audience', 'nonce', 'issuedAt', 'expiresAt', 'scopes']) {
    const value = { agent: principal(3), principal: principal(3), audience: 'https://other.example', nonce: 'cd'.repeat(32),
      issuedAt: now - 11, expiresAt: now + 301, scopes: ['forum:read'] }[key];
    assert.equal(verify({ ...row, [key]: value }, { ...request, agent: key === 'agent' ? value : agent,
      audience: key === 'audience' ? value : request.audience }).ok, false, key);
  }
});
test('expiry, future issuance, wrong signing key and signature domain fail closed', () => {
  assert.equal(verify(grant({ expiresAt: now })).reason, 'expired');
  assert.equal(verify(grant({ issuedAt: now + 1 })).reason, 'future-record');
  const row = grant(), bytes = ids.agentDelegationBytes(row);
  assert.equal(verify({ ...row, sig: sign(bytes, 2) }).reason, 'bad-signature');
  assert.equal(verify({ ...row, sig: sign(new TextEncoder().encode(JSON.stringify(row))) }).reason, 'bad-signature');
  assert.equal(ids.parseAgentDelegation(grant({ expiresAt: now + 86400 })).ok, false);
});
test('authenticated revocation denies and missing or invalid revocation history never allows', () => {
  const row = grant(), id = ids.parseAgentDelegation(row).value.id;
  const r = { v: 1, principal: owner, delegationId: id, issuedAt: now - 1 };
  const rev = { ...r, sig: sign(ids.agentRevocationBytes(r)) };
  assert.equal(verify(row, { ...request, revocations: [rev] }).reason, 'revoked-link');
  assert.equal(verify(row, { ...request, revocations: undefined }).reason, 'missing-history');
  assert.equal(verify(row, { ...request, revocations: [{ ...rev, sig: sign(ids.agentRevocationBytes(r), 2) }] }).ok, false);
  const unrelated = { ...r, delegationId: 'cd'.repeat(32) };
  assert.equal(verify(row, { ...request, revocations: [{ ...unrelated, sig: sign(ids.agentRevocationBytes(unrelated)) }] }).ok, true);
  assert.equal(verify(row, { ...request, revocations: [{ ...rev, principal: agent }] }).reason, 'owner-mismatch');
});
test('strict records reject alternate origins, wildcard/duplicate scopes, aliases and getters', () => {
  const row = grant(); let reads = 0;
  for (const change of [{ audience: 'http://localhost:8080' }, { audience: 'https://s3r.ch/' }, { scopes: ['*'] },
    { scopes: ['forum:read', 'forum:read'] }, { scopes: ['turn:allocate', 'forum:read'] }, { principal: '0x' + '11'.repeat(20) },
    { agent: owner }, { extra: true }, { nonce: 'AB'.repeat(32) }, { issuedAt: -0 }]) {
    assert.equal(ids.parseAgentDelegation({ ...row, ...change }).ok, false);
  }
  const hostile = { ...row }; Object.defineProperty(hostile, 'principal', { get() { reads++; throw Error('getter'); } });
  assert.equal(ids.parseAgentDelegation(hostile).ok, false);
  const list = []; Object.defineProperty(list, 0, { get() { reads++; throw Error('getter'); } });
  assert.equal(ids.parseAgentDelegation({ ...row, scopes: list }).ok, false);
  assert.equal(reads, 0);
});

test('shared consume vector locks domain, encoding, ID and owner signatures', () => {
  const v = JSON.parse(readFileSync(new URL('../../../vectors/agent-delegation/v1.json', import.meta.url), 'utf8'));
  const parsed = ids.parseAgentDelegation(v.record); assert.equal(parsed.ok, true);
  assert.equal(Buffer.from(parsed.value.bytes).toString('hex'), v.signingBytesHex);
  assert.equal(parsed.value.id, v.id);
  assert.equal(ids.verifyKeySignature(v.record.principal, v.record.sig, parsed.value.bytes).ok, true);
  const rev = ids.parseAgentRevocation(v.revocation); assert.equal(rev.ok, true);
  assert.equal(Buffer.from(rev.value.bytes).toString('hex'), v.revocationBytesHex);
  assert.equal(ids.verifyKeySignature(v.record.principal, v.revocation.sig, rev.value.bytes).ok, true);
  assert.equal(ids.verifyKeySignature(v.record.agent, v.record.sig, parsed.value.bytes).ok, false);
});
test('owner rotation prevents reuse of an old-key delegation', () => {
  const rotation = fixture.accept.find(c => c.name === 'wallet-rotate').input;
  const context = { ...ctx, links: new Map(fixture.context.links) };
  const row = grant({ issuedAt: rotation.issuedAt - 1, expiresAt: ctx.now + 100 });
  const verified = ids.verifyAgentDelegation(row, [rotation], context, request);
  assert.equal(verified.ok, false);
  assert.equal(verified.reason, 'unwitnessed-retired-key');
});
