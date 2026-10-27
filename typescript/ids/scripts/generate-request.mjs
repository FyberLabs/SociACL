// Author vectors/mesh/v2/request.json. Public test scalars only. Not part of CI.
import { writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import * as ids from '../src/index.js';
import { membershipAssentBytes, objectSetBytes } from '../../src/group.js';
import { runRequestCase } from '../../tests/request-case.js';
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
const date = (n) => new Date(n * 1000).toISOString().replace('.000Z', 'Z');
const bytesOf = (r) => val(ids.signingBytes(r));
const keySig = (r, n = 1) => b64(p256.sign(bytesOf(r), secret(n), { lowS: false }));
const jwkPrincipal = principal(5);
const jwks = { keys: [{ kty: 'EC', crv: 'P-256', kid: 'fixture-1', x: jwkPrincipal.slice(0, 43), y: jwkPrincipal.slice(44), alg: 'ES256', use: 'sig', key_ops: ['verify'], notBefore: 1699999000, notAfter: 1700010000 }] };
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
function objectRecord(object, owner, signer, issuedAt = at) {
  const bare = { object, owner, issuedAt, sig: '' };
  const bytes = ids.objectRecordBytes(bare);
  return { object, owner, issuedAt, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
}
function seeFields(extra) {
  return { owner: p, object: chatA, accessor: p2, stated: 1, from: 0, until: 100, hamState: 1, issuedAt: at, sig: '', ...extra };
}
function seeRow(extra, signer = 1) {
  const fields = seeFields(extra);
  const bytes = ids.seeGrantBytes(fields);
  return { ...fields, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
}
function postRow(extra, signer = 1) {
  const fields = seeFields(extra);
  const bytes = ids.postGrantBytes(fields);
  return { ...fields, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
}
function accessRow(fields, signer) {
  const requestId = val(ids.requestId(fields.requester, fields.object));
  const bare = { requestId, sig: '', ...fields };
  const bytes = ids.accessRequestBytes(bare);
  return { ...bare, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
}
const friends = val(ids.mintObjectId('set', p, () => new Uint8Array(16).fill(0x33)));
function memberAssent(role, signer) {
  const row = { role, predicate: 'same-group', set: friends, member: p2, setOwner: p, stated: 1, hamState: 1, issuedAt: now, cancels: [] };
  return { ...row, sig: val(ids.signWithKeyring(secret(signer), membershipAssentBytes(row), keyFor(signer))) };
}
function objectEdge() {
  const row = { owner: p, object: chatA, predicate: 'same-group', set: friends, stated: 1, hamState: 1, issuedAt: now, cancels: [] };
  return { ...row, sig: val(ids.signWithKeyring(secret(1), objectSetBytes(row), p)) };
}
const join = { op: 'join', rotations: 'genesis', member: memberAssent('member', 2), set: memberAssent('set', 1), edge: objectEdge() };
const put = (object = chatA, owner = p, signer = 1) => ({ op: 'put', record: objectRecord(object, owner, signer), rotations: 'genesis', ok: true, kept: true });
const window = { from: at, until: now + 100 };
const hamMax = 9007199254740991;
const badSig = b64(new Uint8Array(64).fill(0x11));
const idA = val(ids.requestId(p, chatA));
const idB = val(ids.requestId(p2, chatB));
if (idA === idB) throw new Error('distinct objects produced one request id');
const options = { ctx, rotations: (name) => context.rotationSets[name] };
const accept = [];
const reject = [];
function add(bucket, name, steps, note) {
  runRequestCase(steps, options);
  const row = { name, steps };
  if (note) row.note = note;
  (bucket === 'accept' ? accept : reject).push(row);
}
const reasonOf = (object) => {
  const got = ids.requestId(p, object);
  if (got.ok) throw new Error('parse accepted ' + object);
  return got.reason;
};
add('accept', 'request-id-equals-object-id-binding', [
  { op: 'request-id', requester: p, object: chatA, id: idA },
  { op: 'request-id', requester: p2, object: chatB, id: idB },
  { op: 'request-id', requester: p, object: 'room.alpha', reason: reasonOf('room.alpha') },
  { op: 'request-id', requester: p, object: 'room_alpha', reason: reasonOf('room_alpha') },
  { op: 'request-id', requester: p, object: 'room/alpha', reason: reasonOf('room/alpha') },
  { op: 'request-id', requester: p, object: 's3rch/items/room_alpha', reason: reasonOf('s3rch/items/room_alpha') },
]);
add('accept', 'grant-read-writes-see', [
  put(),
  { op: 'check', object: chatA, accessor: p2, now, allowed: false, reason: 'delegate' },
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 2), window, granted: true, requestId: val(ids.requestId(p2, chatA)), hamState: 1, post: false },
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
  { op: 'view-post', object: chatA, accessor: p2, absent: true },
  { op: 'check', object: chatA, accessor: p2, now, allowed: true, reason: 'delegate' },
]);
add('accept', 'grant-read-post-writes-both', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: accessRow({ requester: p2, object: chatA, scope: 'read+post', status: 'pending', message: 'hello', issuedAt: now }, 2), window, granted: true, hamState: 1, post: true, postHam: 1 },
  { op: 'check', object: chatA, accessor: p2, now, allowed: true, reason: 'delegate' },
  { op: 'check-post', object: chatA, accessor: p2, now, allowed: true, reason: 'post' },
]);
add('accept', 'members-gate-on-stored-id', [
  put(),
  join,
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 2), window, members: { predicate: 'same-group', now }, granted: true, hamState: 1, post: false },
  { op: 'check', object: chatA, accessor: p2, now, allowed: true, reason: 'delegate' },
]);
add('accept', 'factors-never-grant', [
  { op: 'factor', kind: 'request', grants: false },
  { op: 'factor', kind: 'hop', grants: false },
  { op: 'factor', kind: 'hint', grants: false },
  { op: 'factor', kind: 'wrap', grants: false },
  { op: 'factor', kind: 'inbox', grants: false },
]);
const shell = { requester: p2, scope: 'read', status: 'pending', message: '', issuedAt: now, sig: badSig };
add('reject', 'source-non-string', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: { ...shell, object: {}, requestId: idA }, window, granted: false, reason: 'not-string' },
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
add('reject', 'see-at-max-ham-writes-nothing', [
  put(),
  { op: 'admit', row: seeRow({ hamState: hamMax }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: hamMax },
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 2), window, granted: false, reason: 'see-ceiling' },
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: hamMax, mode: 'present' },
]);
add('reject', 'post-at-max-ham-writes-no-see', [
  put(),
  { op: 'admit', row: seeRow({ hamState: 2 }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 2 },
  { op: 'admit-post', row: postRow({ hamState: hamMax }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: hamMax },
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: accessRow({ requester: p2, object: chatA, scope: 'read+post', status: 'pending', message: '', issuedAt: now }, 2), window, granted: false, reason: 'post-ceiling' },
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 2, mode: 'present' },
  { op: 'view-post', object: chatA, accessor: p2, stated: 1, hamState: hamMax, mode: 'present' },
]);
add('reject', 'members-gate-item-soul-is-parse-reject', [
  put(),
  join,
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: { ...shell, object: `s3rch/items/${chatA}`, requestId: idA }, window, members: { predicate: 'same-group', now }, granted: false, reason: reasonOf(`s3rch/items/${chatA}`) },
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
add('reject', 'request-signed-by-retired-key-refused', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'rotated', request: accessRow({ requester: p, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: at }, 1), window, granted: false, reason: 'unwitnessed-retired-key' },
  { op: 'view', object: chatA, accessor: p, absent: true },
]);
add('reject', 'request-ed25519-refused', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: { ...accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 2), sig: badSig }, window, granted: false, reason: 'bad-signature' },
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
add('reject', 'owner-mismatch', [
  put(),
  { op: 'grant', owner: p2, signer: 2, rotations: 'genesis', request: accessRow({ requester: p3, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 3), window, granted: false, reason: 'owner-mismatch' },
  { op: 'view', object: chatA, accessor: p3, absent: true },
]);
add('reject', 'withdrawn-writes-nothing', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'withdrawn', message: '', issuedAt: now }, 2), window, granted: false, reason: 'withdrawn' },
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
add('reject', 'legacy-access-request-domain', [
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: { ...shell, object: chatA, requestId: idA, domain: 's3rch-access-request-v1' }, window, granted: false, reason: 'legacy-row' },
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: { ...shell, object: chatA, requestId: idA, domain: 's3rch-request' }, window, granted: false, reason: 'legacy-row' },
]);
add('reject', 'members-missing-is-not-member', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'genesis', request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 2), window, members: { predicate: 'same-group', now }, granted: false, reason: 'not-member' },
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
const pending = () => accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 2);
const grant = (request, extra) => ({ op: 'grant', owner: p, signer: 1, rotations: 'genesis', request, window, ...extra });
add('reject', 'members-owner-shortcut-is-not-member', [
  put(),
  grant(accessRow({ requester: p, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 1), { members: { predicate: 'same-group', now }, granted: false, reason: 'not-member' }),
  { op: 'view', object: chatA, accessor: p, absent: true },
]);
const mismatched = pending();
mismatched.requestId = '0'.repeat(64);
add('reject', 'stated-request-id-mismatch', [
  put(),
  grant(mismatched, { granted: false, reason: 'bad-record' }),
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
add('reject', 'wrong-owner-key', [
  put(),
  grant(pending(), { signer: 2, granted: false, reason: 'bad-key' }),
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
const fieldSteps = [];
for (const [field, missingReason] of [['requestId', 'bad-record'], ['sig', 'legacy-row']]) {
  for (const value of [undefined, null, 1, {}]) {
    const row = pending();
    if (value === undefined) delete row[field];
    else row[field] = value;
    fieldSteps.push(grant(row, { granted: false, reason: value === undefined ? missingReason : 'not-string' }));
  }
}
for (const field of ['scope', 'status', 'message', 'requester', 'object']) {
  for (const value of [undefined, null, 1, {}]) {
    const row = pending();
    if (value === undefined) delete row[field];
    else row[field] = value;
    fieldSteps.push(grant(row, { granted: false, reason: 'not-string' }));
  }
}
add('reject', 'missing-or-non-string-request-fields', [
  put(),
  ...fieldSteps,
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
const window2 = { from: now, until: now + 50 };
const readPost = () => accessRow({ requester: p2, object: chatA, scope: 'read+post', status: 'pending', message: '', issuedAt: now }, 2);
add('accept', 'approve-twice-same-window', [
  put(),
  grant(pending(), { granted: true, hamState: 1, post: false }),
  grant(pending(), { granted: true, hamState: 1, post: false, unchanged: true }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present', from: at, until: now + 100 },
]);
add('accept', 'approve-twice-new-window', [
  put(),
  grant(pending(), { granted: true, hamState: 1, post: false }),
  grant(pending(), { window: window2, granted: true, hamState: 2, post: false, bytesDiffer: true }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 2, mode: 'present', from: now, until: now + 50 },
  { op: 'check', object: chatA, accessor: p2, now, allowed: true, reason: 'delegate' },
]);
add('accept', 'approve-twice-read-post-same-window', [
  put(),
  grant(readPost(), { granted: true, hamState: 1, post: true, postHam: 1 }),
  grant(readPost(), { granted: true, hamState: 1, post: true, postHam: 1, unchanged: true }),
]);
add('accept', 'approve-read-then-post-keeps-see', [
  put(),
  grant(pending(), { granted: true, hamState: 1, post: false }),
  grant(readPost(), { granted: true, hamState: 1, post: true, postHam: 1, seeBytesSame: true }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
  { op: 'view-post', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
]);
const live = { from: at, until: now + 100 };
const members = { predicate: 'same-group', now };
add('reject', 'members-time-exceeds-safe-integer', [
  put(),
  join,
  grant(pending(), { members: { ...members, now: hamMax + 1 }, granted: false, reason: 'bad-record' }),
  { op: 'view', object: chatA, accessor: p2, absent: true },
  { op: 'view-post', object: chatA, accessor: p2, absent: true },
]);
add('accept', 'self-request-resolves-history-once', [
  put(),
  grant(accessRow({ requester: p, object: chatA, scope: 'read+post', status: 'pending', message: '', issuedAt: now }, 1),
    { granted: true, hamState: 1, post: true, postHam: 1, resolverCalls: 1 }),
]);
add('reject', 'members-approval-does-not-revive-cancel', [
  put(),
  join,
  { op: 'admit', row: seeRow({ stated: 0, hamState: 1, ...live }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1 },
  grant(pending(), { members, granted: false, reason: 'not-kept' }),
  { op: 'view', object: chatA, accessor: p2, stated: 0, hamState: 1, mode: 'present' },
  { op: 'check', object: chatA, accessor: p2, now, allowed: false, reason: 'delegate' },
]);
add('accept', 'manual-approval-after-cancel', [
  put(),
  { op: 'admit', row: seeRow({ stated: 0, hamState: 1, ...live }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1 },
  grant(pending(), { granted: true, hamState: 2, post: false }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 2, mode: 'present', from: at, until: now + 100 },
  { op: 'check', object: chatA, accessor: p2, now, allowed: true, reason: 'delegate' },
]);
add('reject', 'members-approval-does-not-revive-post-cancel', [
  put(),
  join,
  { op: 'admit', row: seeRow({ ...live }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
  { op: 'admit-post', row: postRow({ stated: 0, hamState: 1, ...live }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1 },
  grant(readPost(), { members, granted: false, reason: 'not-kept' }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
  { op: 'view-post', object: chatA, accessor: p2, stated: 0, hamState: 1, mode: 'present' },
  { op: 'check-post', object: chatA, accessor: p2, now, allowed: false, reason: 'cancelled' },
]);
add('accept', 'manual-approval-after-post-cancel', [
  put(),
  { op: 'admit', row: seeRow({ ...live }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
  { op: 'admit-post', row: postRow({ stated: 0, hamState: 1, ...live }), rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 1 },
  grant(readPost(), { granted: true, hamState: 1, post: true, postHam: 2 }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
  { op: 'view-post', object: chatA, accessor: p2, stated: 1, hamState: 2, mode: 'present' },
  { op: 'check-post', object: chatA, accessor: p2, now, allowed: true, reason: 'post' },
]);
add('accept', 'members-grant-uses-the-signed-owner', [
  put(),
  join,
  grant(pending(), { members, granted: true, hamState: 1, post: false }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
], 'Members auto-approve uses the admitted signed owner.');
const boundary = at + 30;
add('reject', 'rotation-boundary', [
  put(),
  { op: 'grant', owner: p, signer: 2, rotations: 'rotated', now: boundary, request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: boundary }, 2), window, granted: false, reason: 'rotation-boundary' },
  { op: 'grant', owner: p, signer: 1, rotations: 'rotated', now: boundary, request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: boundary }, 2), window, granted: false, reason: 'rotation-boundary' },
  { op: 'view', object: chatA, accessor: p2, absent: true },
]);
add('accept', 'rotation-boundary-old-key-before', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'rotated', now: boundary - 1, request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: boundary - 1 }, 2), window, granted: true, hamState: 1, post: false },
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present', issuedAt: boundary - 1 },
]);
add('reject', 'unchanged-wrong-scalar', [
  put(),
  grant(pending(), { granted: true, hamState: 1, post: false }),
  grant(pending(), { signer: 2, granted: false, reason: 'bad-key' }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present', from: at, until: now + 100 },
]);
add('reject', 'unchanged-non-member', [
  put(),
  grant(pending(), { granted: true, hamState: 1, post: false }),
  grant(pending(), { members, granted: false, reason: 'not-member' }),
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present', from: at, until: now + 100 },
]);
add('accept', 'unchanged-after-rotation-resigns', [
  put(),
  { op: 'grant', owner: p, signer: 1, rotations: 'rotated', now: boundary - 1, request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: boundary - 1 }, 2), window, granted: true, hamState: 1, post: false },
  { op: 'grant', owner: p, signer: 2, rotations: 'rotated', now, request: accessRow({ requester: p2, object: chatA, scope: 'read', status: 'pending', message: '', issuedAt: now }, 2), window, granted: true, hamState: 2, post: false, bytesDiffer: true },
  { op: 'view', object: chatA, accessor: p2, stated: 1, hamState: 2, mode: 'present', issuedAt: now },
]);
const body = { v: 1, family: 'request', context, accept, reject };
const path = new URL('../../../vectors/mesh/v2/request.json', import.meta.url);
writeFileSync(path, JSON.stringify(body, null, 2) + '\n');
console.log(`request accept ${accept.length} reject ${reject.length}`);
