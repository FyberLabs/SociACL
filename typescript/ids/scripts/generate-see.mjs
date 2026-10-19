// Author vectors/mesh/v2/see.json. Public test scalars only. Not part of CI.
import { writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import * as ids from '../src/index.js';
import { runSeeCase } from '../../src/see.js';
import { b64, hex, utf8 } from './vector-util.mjs';

const val = (r) => { if (!r.ok) throw Error(r.reason); return r.value; };
const secret = (n) => { const b = new Uint8Array(32); b[31] = n; return b; };
const principal = (n) => {
  const pub = p256.getPublicKey(secret(n), false);
  return val(ids.parsePrincipalId(b64(pub.slice(1, 33)) + '.' + b64(pub.slice(33))));
};
const p = principal(1);
const p2 = principal(2);
const p3 = principal(3);
const wallet = val(ids.parseWalletInput('0x' + hex(keccak_256(secp256k1.getPublicKey(secret(4), false).slice(1))).slice(-40)));
const at = 1700000000;
const now = at + 60;
const retiredAt = at + 10;
const date = (n) => new Date(n * 1000).toISOString().replace('.000Z', 'Z');
const bytesOf = (r) => val(ids.signingBytes(r));
const keySig = (r, n = 1) => b64(p256.sign(bytesOf(r), secret(n), { lowS: false }));
const jwkPrincipal = principal(5);
const jwks = { keys: [{ kty: 'EC', crv: 'P-256', kid: 'fixture-1', x: jwkPrincipal.slice(0, 43), y: jwkPrincipal.slice(44), alg: 'ES256', use: 'sig', key_ops: ['verify'] }] };
const jws = (claims) => {
  const body = b64(utf8.encode(JSON.stringify({ alg: 'ES256', kid: 'fixture-1', typ: 'JWT' }))) + '.' + b64(utf8.encode(JSON.stringify(claims)));
  return body + '.' + b64(p256.sign(utf8.encode(body), secret(5), { lowS: false }));
};
const signMessage = (message) => {
  const raw = utf8.encode(message);
  const digest = keccak_256(new Uint8Array([...utf8.encode('\x19Ethereum Signed Message:\n' + raw.length), ...raw]));
  const sig = secp256k1.sign(digest, secret(4), { prehash: false, format: 'recovered' });
  return { message, signature: '0x' + hex(new Uint8Array([...sig.slice(1), sig[0] + 27])) };
};
const siwe = (r) => signMessage(`s3r.ch wants you to sign in with your Ethereum account:\n${wallet}\n\nSociACL link: ${hex(sha256(bytesOf(r)))}\n\nURI: https://s3r.ch/identity/link\nVersion: 1\nChain ID: 1\nNonce: ${r.nonce ?? 'rotation1234'}\nIssued At: ${date(r.issuedAt)}`);
function walletLink(principalId = p, issuedAt = at, n = 1) {
  const r = { v: 1, kind: 'wallet', principal: principalId, address: wallet, issuedAt, nonce: 'fixtureNonce123' };
  return { ...r, keySig: keySig(r, n), siwe: siwe(r), attest: jws({ typ: 'sociacl-wallet-attest-v1', principal: principalId, linkId: val(ids.linkId(r)), iat: issuedAt, exp: issuedAt + 600 }) };
}
const w = walletLink();
const wid = val(ids.linkId(w));
const rotation = (next = p2, n = 2, seq = 1, prev = p, issuedAt = at + 30) => {
  const r = { v: 1, kind: 'rotate', principal: p, seq, prevKey: prev, nextKey: next, issuedAt, retainedLinks: [wid], authorizer: { kind: 'wallet', link: wid } };
  return { ...r, nextSig: keySig(r, n), authorizer: { ...r.authorizer, siwe: siwe(r) }, attest: jws({ typ: 'sociacl-rotate-attest-v2', principal: p, nextKey: next, seq, iat: issuedAt, exp: issuedAt + 600, auth: 'wallet', linkId: wid, retainedLinks: [wid] }) };
};
const rot = rotation();
const policy = { allowedDomains: ['s3r.ch'], allowedUris: ['https://s3r.ch/identity/link'], allowedChainIds: ['1'] };
const chatA = val(ids.mintObjectId('chat', p, () => new Uint8Array(16).fill(0x11)));
const chatB = val(ids.mintObjectId('chat', p, () => new Uint8Array(16).fill(0x22)));
const unbound = val(ids.parseObjectId('chat_' + '33'.repeat(16)));
const context = {
  jwks,
  links: [[wid, w]],
  revocations: [],
  now,
  policy,
  pinnedIss: ['https://id.fyberlabs.com/realms/test'],
  authenticatedAccounts: [p, p2, p3],
  genesisEpubBindings: [],
  rotationSets: { genesis: [], rotated: [rot] },
};
const history = (principalId, issued, until) => context.authenticatedAccounts.includes(principalId)
  ? { ok: true, value: ids.historyState(principalId, [], issued, until) }
  : { ok: false, reason: 'missing-history' };
const ctx = {
  jwks,
  links: new Map(context.links),
  revocations: [],
  now,
  policy,
  pinnedIss: new Set(context.pinnedIss),
  history,
  genesisEpubBindings: [],
};
const keyFor = (n) => n === 1 ? p : n === 2 ? p2 : p3;
function attest(bytes, issuedAt, principalId, patch = {}) {
  return jws({
    typ: patch.typ ?? 'sociacl-acl-attest-v1',
    principal: patch.principal ?? principalId,
    recordId: patch.recordId ?? hex(sha256(bytes)),
    iat: patch.iat ?? issuedAt,
    exp: patch.exp ?? issuedAt + 600,
  });
}
function seeRow(fields, signer, patch) {
  const bare = { ...fields, sig: '' };
  const bytes = ids.seeGrantBytes(bare);
  const row = { ...fields, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
  if (patch !== undefined) row.attest = typeof patch === 'string' ? patch : attest(bytes, fields.issuedAt, fields.owner, patch);
  return { row, bytes };
}
const base = (extra) => ({ owner: p, object: chatA, accessor: p2, stated: 1, from: 0, until: 100, hamState: 1, issuedAt: at, ...extra });
function objectRecord(object, owner, signer, issuedAt = at) {
  const bare = { object, owner, issuedAt, sig: '' };
  const bytes = ids.objectRecordBytes(bare);
  return { object, owner, issuedAt, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
}
function put(object, owner, signer, issuedAt = at) {
  return { op: 'put', record: objectRecord(object, owner, signer, issuedAt), rotations: 'genesis', ok: true, kept: true };
}
function putCurrent(object = chatA) {
  return { op: 'put', record: objectRecord(object, p, 2, at + 40), rotations: 'rotated', ok: true, kept: true };
}
const options = { ctx, rotations: (name) => context.rotationSets[name] };
const accept = [];
const reject = [];
function add(bucket, name, steps) {
  runSeeCase(steps, options);
  (bucket === 'accept' ? accept : reject).push({ name, steps });
}
const edge = (kind, value) => {
  const got = kind === 'object' ? ids.parseObjectId(value) : ids.parsePrincipalId(value);
  if (got.ok) throw Error('edge accepted ' + value);
  return { op: 'edge', kind, value, reason: got.reason };
};
const chain = "0xattacker.get('s3rch').get('users').get('0xvictim')";
add('reject', 'accessor-gun-chain-spoof', [edge('principal', chain)]);
add('accept', 'owner-path-needs-exact-principal', [
  put(chatA, p, 1),
  { op: 'check', object: chatA, accessor: p, now: 10, allowed: true, reason: 'owner' },
  { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
  edge('principal', p + ' '),
]);
for (const [name, value] of [
  ['fold-room-dot', 'room.alpha'],
  ['fold-room-slash', 'room/alpha'],
  ['fold-room-underscore', 'room_alpha'],
  ['fold-item-soul', 's3rch/items/room_alpha'],
]) add('reject', name, [edge('object', value)]);
add('reject', 'fold-user-soul', [edge('principal', 's3rch/users/0xbob')]);
{
  const grant = seeRow(base({}), 1).row;
  add('accept', 'grant-on-chat_a-does-not-allow-chat_b', [
    put(chatA, p, 1),
    put(chatB, p, 1),
    { op: 'admit', row: grant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'delegate' },
    { op: 'check', object: chatB, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
    { op: 'check', object: chatB, accessor: p2, now: 10, allowed: false, reason: 'delegate', hint: true, hop: true },
  ]);
}
add('reject', 'object-without-embedded-principal', [
  { op: 'put', record: objectRecord(unbound, p, 1), rotations: 'genesis', ok: false, reason: 'bad-record' },
  { op: 'owner', object: unbound, absent: true },
  { op: 'check', object: unbound, accessor: p, now: 10, allowed: false, reason: 'unknown' },
]);
{
  const unsigned = base({});
  add('reject', 'unsigned-row-refused', [
    put(chatA, p, 1),
    { op: 'admit', row: unsigned, rotations: 'genesis', ok: false, reason: 'legacy-row' },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
  ]);
  const v1 = { ...seeRow(base({}), 1).row, domain: 'sociacl-see-grant-v1' };
  add('reject', 'see-grant-v1-refused', [
    put(chatA, p, 1),
    { op: 'admit', row: v1, rotations: 'genesis', ok: false, reason: 'legacy-row' },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
  ]);
  const forged = seeRow(base({}), 2).row;
  add('reject', 'row-signed-by-accessor-refused', [
    put(chatA, p, 1),
    { op: 'admit', row: forged, rotations: 'genesis', ok: false, reason: 'bad-signature' },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
  ]);
}
{
  const oldGrant = seeRow(base({ issuedAt: at }), 1).row;
  add('reject', 'rotation-drops-old-key-grant', [
    put(chatA, p, 1),
    { op: 'admit', row: oldGrant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 2 },
    { op: 'view', object: chatA, accessor: p2, absent: true },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'unknown' },
  ]);
  const resigned = seeRow(base({ issuedAt: at + 40, hamState: 2 }), 2).row;
  add('accept', 'resigned-row-allows', [
    put(chatA, p, 1),
    { op: 'admit', row: oldGrant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 2 },
    putCurrent(),
    { op: 'admit', row: resigned, rotations: 'rotated', ok: true, kept: true, mode: 'present', stated: 1, hamState: 2 },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'delegate' },
  ]);
}
{
  const oldGrant = seeRow(base({ issuedAt: at }), 1).row;
  add('accept', 'reverify-drops-the-object-label', [
    put(chatA, p, 1),
    { op: 'label', object: chatA, owner: p },
    { op: 'admit', row: oldGrant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 2 },
    { op: 'label', object: chatA, absent: true },
    { op: 'owner', object: chatA, absent: true },
  ]);
  add('reject', 'missing-history-drops-the-object-label', [
    put(chatA, p, 1),
    { op: 'label', object: chatA, owner: p },
    { op: 'reverify', principal: p, history: 'unavailable', ok: false, reason: 'missing-history' },
    { op: 'label', object: chatA, absent: true },
    { op: 'owner', object: chatA, absent: true },
  ]);
}
{
  const cancel = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, {}).row;
  add('accept', 'retired-witnessed-cancel-kept', [
    putCurrent(),
    { op: 'verify', row: cancel, rotations: 'rotated', ok: true, mode: 'witnessed' },
    { op: 'admit', row: cancel, rotations: 'rotated', ok: true, kept: true, mode: 'witnessed', stated: 0, hamState: 1 },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 0 },
    { op: 'view', object: chatA, accessor: p2, stated: 0, hamState: 1, mode: 'witnessed' },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
  ]);
  const span = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, { exp: retiredAt + 900 }).row;
  add('accept', 'witness-exp-900', [
    { op: 'verify', row: span, rotations: 'rotated', ok: true, mode: 'witnessed' },
  ]);
}
function retired(name, patch, reason) {
  const made = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, patch);
  add('reject', name, [
    { op: 'verify', row: made.row, rotations: 'rotated', ok: false, reason },
    put(chatA, p, 1),
    { op: 'admit', row: made.row, rotations: 'rotated', ok: false, reason },
  ]);
}
retired('witness-expired', { iat: retiredAt - 10, exp: retiredAt }, 'expired');
retired('witness-wrong-iat', { iat: retiredAt - 1, exp: retiredAt + 100 }, 'bad-attestation');
retired('witness-wrong-recordId', { recordId: '00'.repeat(32) }, 'bad-attestation');
retired('witness-cross-type', { typ: 'sociacl-revoke-attest-v1' }, 'bad-attestation');
retired('witness-window-901', { exp: retiredAt + 901 }, 'bad-attestation');
retired('witness-wrong-principal', { principal: p2 }, 'bad-attestation');
retired('witness-too-long', 'x'.repeat(16385), 'too-long');
{
  const original = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, {}).row;
  const flipped = { ...original, stated: 1 };
  add('reject', 'witness-stated-flip', [
    { op: 'verify', row: flipped, rotations: 'rotated', ok: false, reason: 'bad-attestation' },
    put(chatA, p, 1),
    { op: 'admit', row: original, rotations: 'rotated', ok: true, kept: true, mode: 'witnessed', stated: 0, hamState: 1 },
    { op: 'admit', row: flipped, rotations: 'rotated', ok: false, reason: 'bad-attestation' },
    { op: 'view', object: chatA, accessor: p2, stated: 0, hamState: 1, mode: 'witnessed' },
  ]);
}
{
  const grant = seeRow(base({ stated: 1, issuedAt: retiredAt }), 1, {}).row;
  add('reject', 'retired-grant-witnessed', [
    { op: 'verify', row: grant, rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
  ]);
  const relabel = { ...grant, kind: 'cancel' };
  add('reject', 'witness-kind-relabel', [
    { op: 'verify', row: relabel, rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
    put(chatA, p, 1),
    { op: 'admit', row: relabel, rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
  ]);
}
{
  const low = seeRow(base({ stated: 0, hamState: 1 }), 1).row;
  const high = seeRow(base({ stated: 1, hamState: 2 }), 1).row;
  add('accept', 'ham-higher-wins', [
    put(chatA, p, 1),
    { op: 'admit', row: high, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 2 },
    { op: 'admit', row: low, rotations: 'genesis', ok: true, kept: false, mode: 'present', stated: 1, hamState: 2 },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'delegate' },
  ]);
}
{
  const grant = seeRow(base({ hamState: 5, stated: 1 }), 1).row;
  const cancel = seeRow(base({ hamState: 5, stated: 0 }), 1).row;
  add('accept', 'equal-ham-cancel-wins', [
    put(chatA, p, 1),
    { op: 'admit', row: grant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 5 },
    { op: 'admit', row: cancel, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 5 },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
  ]);
}
{
  const wide = seeRow(base({ hamState: 5, from: 0, until: 100 }), 1).row;
  const narrow = seeRow(base({ hamState: 5, from: 0, until: 10 }), 1).row;
  add('accept', 'equal-ham-narrower-wins', [
    put(chatA, p, 1),
    { op: 'admit', row: wide, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 5 },
    { op: 'admit', row: narrow, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 5 },
    { op: 'check', object: chatA, accessor: p2, now: 5, allowed: true, reason: 'delegate' },
    { op: 'check', object: chatA, accessor: p2, now: 50, allowed: false, reason: 'delegate' },
  ]);
}
{
  const early = seeRow(base({ hamState: 4, issuedAt: at }), 1);
  const later = seeRow(base({ hamState: 4, issuedAt: at + 1 }), 1);
  const earlySmaller = compareBytes(early.bytes, later.bytes) < 0;
  const larger = earlySmaller ? later.row : early.row;
  const smaller = earlySmaller ? early.row : later.row;
  const smallerAt = earlySmaller ? at : at + 1;
  add('accept', 'equal-ham-smaller-bytes-wins', [
    put(chatA, p, 1),
    { op: 'admit', row: larger, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 4 },
    { op: 'admit', row: smaller, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 4 },
    { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 4, mode: 'present', issuedAt: smallerAt },
  ]);
}
function compareBytes(left, right) {
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i += 1) if (left[i] !== right[i]) return left[i] - right[i];
  return left.length - right.length;
}
{
  const grant = seeRow(base({}), 1).row;
  add('reject', 'resolver-history-unavailable', [
    put(chatA, p, 1),
    { op: 'verify', row: grant, history: 'unavailable', ok: false, reason: 'missing-history' },
    { op: 'admit', row: grant, history: 'unavailable', ok: false, reason: 'missing-history' },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
    { op: 'admit', row: grant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'reverify', principal: p, history: 'unavailable', ok: false, reason: 'missing-history' },
    { op: 'view', object: chatA, accessor: p2, absent: true },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'unknown' },
  ]);
}
{
  const row = seeRow(base({}), 1).row;
  add('reject', 'stated-negative-zero', [
    { op: 'verify', row, rotations: 'genesis', patch: { stated: '-0' }, ok: false, reason: 'bad-record' },
    put(chatA, p, 1),
    { op: 'admit', row, rotations: 'genesis', patch: { stated: '-0' }, ok: false, reason: 'bad-record' },
  ]);
  const numeric = { ...row, sig: 1 };
  const missing = { ...row, sig: null };
  add('reject', 'sig-numeric', [
    { op: 'verify', row: numeric, rotations: 'genesis', ok: false, reason: 'not-string' },
  ]);
  add('reject', 'id-field-not-string', [
    { op: 'admit', row, rotations: 'genesis', patch: { owner: 5 }, ok: false, reason: 'not-string' },
    { op: 'admit', row, rotations: 'genesis', patch: { object: 5 }, ok: false, reason: 'not-string' },
    { op: 'admit', row, rotations: 'genesis', patch: { accessor: 5 }, ok: false, reason: 'not-string' },
  ]);
  add('reject', 'sig-null', [
    { op: 'verify', row: missing, rotations: 'genesis', ok: false, reason: 'not-string' },
  ]);
}
{
  const self = seeRow(base({ owner: p2, accessor: p3 }), 2).row;
  add('reject', 'preadmitted-see-row-is-not-an-object-record', [
    { op: 'admit', row: self, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'put', record: self, rotations: 'genesis', ok: false, reason: 'bad-record' },
    { op: 'owner', object: chatA, absent: true },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'unknown' },
  ]);
  const grant = seeRow(base({}), 1).row;
  add('reject', 'stranger-record-does-not-freeze', [
    put(chatA, p, 1),
    { op: 'admit', row: grant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'put', record: objectRecord(chatA, p2, 2), rotations: 'genesis', ok: false, reason: 'bad-record' },
    { op: 'owner', object: chatA, owner: p, issuedAt: at },
    { op: 'check', object: chatA, accessor: p, now: 10, allowed: true, reason: 'owner' },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'delegate' },
    { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
  ]);
  add('reject', 'object-domain-v1', [
    { op: 'put', record: { ...objectRecord(chatA, p, 1), domain: 'sociacl-object-v1' }, rotations: 'genesis', ok: false, reason: 'bad-record' },
    { op: 'owner', object: chatA, absent: true },
  ]);
  add('reject', 'object-issued-at-negative-zero', [
    { op: 'put', record: objectRecord(chatA, p, 1), rotations: 'genesis', patch: { issuedAt: '-0' }, ok: false, reason: 'bad-record' },
    { op: 'owner', object: chatA, absent: true },
  ]);
  add('reject', 'object-wrong-signer', [
    { op: 'put', record: objectRecord(chatA, p, 2), rotations: 'genesis', ok: false, reason: 'bad-signature' },
    { op: 'owner', object: chatA, absent: true },
  ]);
  add('reject', 'object-future-record', [
    { op: 'put', record: objectRecord(chatA, p, 1, now + 1), rotations: 'genesis', ok: false, reason: 'future-record' },
    { op: 'owner', object: chatA, absent: true },
  ]);
  add('reject', 'object-put-without-history', [
    { op: 'put', record: { object: chatA, owner: p, issuedAt: at }, history: 'unavailable', ok: false, reason: 'bad-signature' },
    { op: 'put', record: objectRecord(chatA, p, 1), history: 'unavailable', ok: false, reason: 'missing-history' },
    { op: 'owner', object: chatA, absent: true },
  ]);
  {
    const retired = objectRecord(chatA, p, 1, at);
    retired.attest = attest(ids.objectRecordBytes(retired), at, p);
    add('reject', 'retired-object-record-ignores-witness', [
      { op: 'put', record: retired, rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
      { op: 'owner', object: chatA, absent: true },
    ]);
  }
  add('accept', 'object-resigned-after-rotation', [
    put(chatA, p, 1),
    { op: 'put', record: objectRecord(chatA, p, 2, at + 40), rotations: 'rotated', ok: true, kept: true },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 0 },
    { op: 'owner', object: chatA, owner: p, issuedAt: at + 40 },
    { op: 'check', object: chatA, accessor: p, now: at + 50, allowed: true, reason: 'owner' },
  ]);
  add('accept', 'object-resigned-on-a-fresh-peer', [
    putCurrent(),
    { op: 'owner', object: chatA, owner: p, issuedAt: at + 40 },
    { op: 'check', object: chatA, accessor: p, now: at + 50, allowed: true, reason: 'owner' },
  ]);
  add('reject', 'unsigned-object-record', [
    { op: 'put', record: { object: chatA, owner: p, issuedAt: at }, rotations: 'genesis', ok: false, reason: 'bad-signature' },
    { op: 'owner', object: chatA, absent: true },
    { op: 'check', object: chatA, accessor: p, now: 10, allowed: false, reason: 'unknown' },
  ]);
  add('reject', 'retired-object-record', [
    { op: 'put', record: objectRecord(chatA, p, 1, at), rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
    { op: 'owner', object: chatA, absent: true },
  ]);
  add('accept', 'object-owner-same-is-noop', [
    put(chatA, p, 1),
    { op: 'put', record: objectRecord(chatA, p, 1, at + 5), rotations: 'genesis', ok: true, kept: false },
    { op: 'owner', object: chatA, owner: p, issuedAt: at },
    { op: 'check', object: chatA, accessor: p, now: 10, allowed: true, reason: 'owner' },
  ]);
  add('accept', 'stale-history-does-not-downgrade', [
    put(chatA, p, 1),
    { op: 'put', record: objectRecord(chatA, p, 2, at + 40), rotations: 'rotated', ok: true, kept: true },
    { op: 'put', record: objectRecord(chatA, p, 1, at), rotations: 'genesis', ok: true, kept: false },
    { op: 'owner', object: chatA, owner: p, issuedAt: at + 40 },
    { op: 'check', object: chatA, accessor: p, now: at + 50, allowed: true, reason: 'owner' },
  ]);
  add('accept', 'regressed-history-retired-key-does-not-replace', [
    { op: 'put', record: objectRecord(chatA, p, 2, at + 40), rotations: 'rotated', ok: true, kept: true },
    { op: 'put', record: objectRecord(chatA, p, 1, at + 50), rotations: 'genesis', ok: true, kept: false },
    { op: 'owner', object: chatA, owner: p, issuedAt: at + 40 },
  ]);
}
{
  const bare = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1).row;
  const witnessed = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, {}).row;
  add('accept', 'equal-bytes-keep-witness', [
    putCurrent(),
    { op: 'admit', row: bare, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1, attest: false },
    { op: 'admit', row: witnessed, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1, attest: true },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 0 },
    { op: 'view', object: chatA, accessor: p2, stated: 0, hamState: 1, mode: 'witnessed', attest: true },
  ]);
  const junk = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, 'not-a-jws').row;
  const good = seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, {}).row;
  add('accept', 'equal-bytes-valid-witness-wins', [
    putCurrent(),
    { op: 'admit', row: junk, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1, attest: true },
    { op: 'admit', row: good, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1, attest: true },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 0 },
    { op: 'view', object: chatA, accessor: p2, stated: 0, hamState: 1, mode: 'witnessed', attest: true },
  ]);
  add('accept', 'equal-bytes-junk-does-not-replace-witness', [
    putCurrent(),
    { op: 'admit', row: good, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1, attest: true },
    { op: 'admit', row: junk, rotations: 'genesis', ok: true, kept: false, mode: 'present', stated: 0, hamState: 1, attest: true },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 0 },
    { op: 'view', object: chatA, accessor: p2, stated: 0, hamState: 1, mode: 'witnessed', attest: true },
  ]);
  add('accept', 'equal-bytes-witness-stays', [
    putCurrent(),
    { op: 'admit', row: witnessed, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1, attest: true },
    { op: 'admit', row: bare, rotations: 'genesis', ok: true, kept: false, mode: 'present', stated: 0, hamState: 1, attest: true },
  ]);
}
{
  add('reject', 'retired-cancel-unwitnessed', [
    { op: 'verify', row: seeRow(base({ stated: 0, issuedAt: retiredAt }), 1).row, rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
  ]);
  add('reject', 'retired-cancel-bad-jws', [
    { op: 'verify', row: seeRow(base({ stated: 0, issuedAt: retiredAt }), 1, 'not-a-jws').row, rotations: 'rotated', ok: false, reason: 'bad-attestation' },
  ]);
  const atRotation = seeRow(base({ stated: 0, issuedAt: at + 30 }), 1, {}).row;
  add('accept', 'cancel-at-rotation-time-witnessed', [
    { op: 'verify', row: atRotation, rotations: 'rotated', ok: true, mode: 'witnessed' },
  ]);
  add('reject', 'cancel-at-rotation-time-newkey', [
    { op: 'verify', row: seeRow(base({ stated: 0, issuedAt: at + 30 }), 2, {}).row, rotations: 'rotated', ok: false, reason: 'bad-signature' },
  ]);
  add('reject', 'backdated-next-key-cancel', [
    { op: 'verify', row: seeRow(base({ stated: 0, issuedAt: retiredAt }), 2, {}).row, rotations: 'rotated', ok: false, reason: 'bad-signature' },
  ]);
  add('reject', 'oldkey-cancel-after-rotation', [
    { op: 'verify', row: seeRow(base({ stated: 0, issuedAt: at + 40 }), 1).row, rotations: 'rotated', ok: false, reason: 'bad-signature' },
  ]);
}
{
  const stampRevoke = (r) => jws({ typ: 'sociacl-revoke-attest-v1', principal: r.principal, recordId: val(ids.linkId(r)), iat: r.issuedAt, exp: r.issuedAt + 600 });
  const rev = { v: 1, kind: 'revoke', principal: p, linkId: wid, issuedAt: at + 20 };
  rev.keySig = keySig(rev);
  rev.attest = stampRevoke(rev);
  const grant = seeRow(base({}), 1).row;
  add('reject', 'revoked-authorizer-fails-closed', [
    { op: 'verify', row: grant, rotations: 'rotated', revocations: [rev], ok: false, reason: 'rotation-conflict' },
    put(chatA, p, 1),
    { op: 'admit', row: grant, rotations: 'rotated', revocations: [rev], ok: false, reason: 'rotation-conflict' },
    { op: 'put', record: objectRecord(chatA, p, 2, at + 40), rotations: 'rotated', revocations: [rev], ok: false, reason: 'rotation-conflict' },
  ]);
  add('accept', 'reverify-drops-revoked-authorizer', [
    put(chatA, p, 1),
    { op: 'admit', row: grant, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'reverify', principal: p, rotations: 'rotated', revocations: [rev], dropped: 2 },
    { op: 'view', object: chatA, accessor: p2, absent: true },
    { op: 'check', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'unknown' },
  ]);
}
{
  add('reject', 'present-attest-too-long', [
    { op: 'verify', row: seeRow(base({}), 1, 'x'.repeat(16385)).row, rotations: 'genesis', ok: false, reason: 'too-long' },
  ]);
  add('accept', 'present-attest-at-cap', [
    { op: 'verify', row: seeRow(base({}), 1, 'x'.repeat(16384)).row, rotations: 'genesis', ok: true, mode: 'present' },
  ]);
}
{
  const left = seeRow(base({ hamState: 5, from: 0, until: 30 }), 1);
  const right = seeRow(base({ hamState: 5, from: 20, until: 80 }), 1);
  const leftSmaller = compareBytes(left.bytes, right.bytes) < 0;
  const winner = leftSmaller ? left : right;
  const loser = leftSmaller ? right : left;
  add('accept', 'equal-ham-incomparable-smaller-bytes', [
    put(chatA, p, 1),
    { op: 'admit', row: loser.row, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 5 },
    { op: 'admit', row: winner.row, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 5 },
    { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 5, mode: 'present', from: winner.row.from, until: winner.row.until },
  ]);
}
const body = { v: 1, family: 'see', context, accept, reject };
const path = new URL('../../../vectors/mesh/v2/see.json', import.meta.url);
writeFileSync(path, JSON.stringify(body, null, 2) + '\n');
console.log(`see accept ${accept.length} reject ${reject.length}`);
