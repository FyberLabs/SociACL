// Author vectors/mesh/v2/group.json. Public test scalars only. Not part of CI.
import { writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import * as ids from '../src/index.js';
import { groupCancelBytes, membershipAssentBytes, membershipSoul, objectSetBytes, objectSetSoul } from '../../src/group.js';
import { runGroupCase } from '../../tests/group-case.js';
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
const friends = val(ids.mintObjectId('set', p, () => new Uint8Array(16).fill(0x33)));
const otherSet = val(ids.mintObjectId('set', p, () => new Uint8Array(16).fill(0x44)));
const cancelId = 'cd'.repeat(32);
const unbound = 'set_' + 'ab'.repeat(16);
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
const sign = (bytes, n) => val(ids.signWithKeyring(secret(n), bytes, keyFor(n)));
function objectRecord(object, owner = p, signer = 1) {
  const bare = { object, owner, issuedAt: at, sig: '' };
  return { object, owner, issuedAt: at, sig: sign(ids.objectRecordBytes(bare), signer) };
}
const put = (object = chatA) => ({ op: 'put', record: objectRecord(object), rotations: 'genesis', ok: true, kept: true });
function assent(role, signer, extra) {
  const row = { role, predicate: 'same-group', set: friends, member: p2, setOwner: p, stated: 1, hamState: 1, issuedAt: at, cancels: [], ...extra };
  return { ...row, sig: sign(membershipAssentBytes(row), signer) };
}
function edge(signer, extra) {
  const row = { owner: p, object: chatA, predicate: 'same-group', set: friends, stated: 1, hamState: 1, issuedAt: at, cancels: [], ...extra };
  return { ...row, sig: sign(objectSetBytes(row), signer) };
}
const member = () => ({ op: 'admit-member', row: assent('member', 2), rotations: 'genesis', ok: true, kept: true });
const setAssent = () => ({ op: 'admit-member', row: assent('set', 1), rotations: 'genesis', ok: true, kept: true });
const objectEdge = (object = chatA) => ({ op: 'admit-object-set', row: edge(1, { object }), rotations: 'genesis', ok: true, kept: true });
const live = () => [put(), member(), setAssent(), objectEdge()];
const check = (object, accessor, allowed, reason, extra) => ({ op: 'check-group', predicate: 'same-group', object, accessor, now, allowed, reason, ...extra });
function aclAttest(bytes, issuedAt, principalId) {
  return jws({
    typ: 'sociacl-acl-attest-v1',
    principal: principalId,
    recordId: hex(sha256(bytes)),
    iat: issuedAt,
    exp: issuedAt + 600,
  });
}
function cancelRow(kind, signer, extra = {}) {
  const set = extra.set ?? friends;
  const object = extra.object ?? chatA;
  const predicate = extra.predicate ?? 'same-group';
  const issuedAt = extra.issuedAt ?? at;
  const row = {
    kind,
    predicate,
    set,
    member: p2,
    setOwner: p,
    signer: keyFor(signer),
    rowSoul: kind === 'object-set' ? objectSetSoul(p, object, predicate, set) : membershipSoul(p, predicate, set, p2),
    cancelId: extra.cancelId ?? cancelId,
    prior: extra.prior ?? [],
    issuedAt,
  };
  if (kind === 'object-set') row.object = object;
  const bytes = groupCancelBytes(row);
  const signed = { ...row, sig: sign(bytes, signer) };
  if (extra.attest) signed.attest = aclAttest(bytes, issuedAt, keyFor(signer));
  return signed;
}
const admitCancel = (row, rotations, extra) => ({ op: 'admit-cancel', row, rotations, ok: true, kept: true, ...extra });
const payload = { stated: 1, from: at, until: now + 100 };
const options = { ctx, rotations: (name) => context.rotationSets[name] };
const accept = [];
const reject = [];
function add(bucket, name, steps, note) {
  runGroupCase(structuredClone(steps), options);
  const row = { name, steps };
  if (note) row.note = note;
  (bucket === 'accept' ? accept : reject).push(row);
}
add('reject', 'set-id-must-be-minted', [
  { op: 'admit-member', row: assent('member', 2, { set: 'alice/friends' }), rotations: 'genesis', ok: false, reason: 'bad-alphabet' },
  { op: 'admit-member', row: assent('member', 2, { set: unbound }), rotations: 'genesis', ok: false, reason: 'bad-alphabet' },
]);
add('reject', 'member-assent-by-other-key-refused', [
  put(),
  { op: 'admit-member', row: assent('member', 1), rotations: 'genesis', ok: false, reason: 'bad-signature' },
  check(chatA, p2, false, 'missing'),
]);
add('reject', 'object-set-signed-by-non-owner-refused', [
  put(),
  member(),
  setAssent(),
  { op: 'admit-object-set', row: edge(2), rotations: 'genesis', ok: false, reason: 'bad-signature' },
  check(chatA, p2, false, 'missing'),
]);
const cancelShell = { kind: 'membership', predicate: 'same-group', set: friends, member: p2, setOwner: p, signer: p2, rowSoul: 's3rch/acl/x', cancelId: 'ab'.repeat(32), prior: [], issuedAt: at, sig: 'aa' };
add('reject', 'cancel-v1-refused', [
  { op: 'admit-cancel', row: { ...cancelShell, domain: 'sociacl-cancel-v1' }, rotations: 'genesis', ok: false, reason: 'legacy-row' },
  { op: 'admit-cancel', row: { ...cancelShell, domain: 'sociacl-cancel-id-v1' }, rotations: 'genesis', ok: false, reason: 'legacy-row' },
  { op: 'admit-member', row: { ...assent('member', 2), domain: 'sociacl-membership-assent-v1' }, rotations: 'genesis', ok: false, reason: 'legacy-row' },
  { op: 'admit-object-set', row: { ...edge(1), domain: 'sociacl-object-set-v1' }, rotations: 'genesis', ok: false, reason: 'legacy-row' },
  { op: 'admit-cancel', row: { kind: 'membership', predicate: 'same-group', set: friends }, rotations: 'genesis', ok: false, reason: 'legacy-row' },
]);
add('reject', 'rotation-drops-old-assent', [
  ...live(),
  check(chatA, p2, true, 'same-group'),
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 2 },
  check(chatA, p2, false, 'missing'),
]);
add('reject', 'merge-does-not-revive-a-retired-assent', [
  ...live(),
  check(chatA, p2, true, 'same-group'),
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 2 },
  check(chatA, p2, false, 'missing'),
  ...live().map((step) => ({ ...step, on: 'side' })),
  { op: 'merge', rotations: 'rotated' },
  check(chatA, p2, false, 'missing'),
]);
add('accept', 'group-gate-uses-stored-id', [
  ...live(),
  put(chatB),
  check(chatA, p2, true, 'same-group'),
  check(chatB, p2, false, 'missing'),
  check(chatA, p, true, 'owner'),
  { op: 'check-presentation', set: null, object: chatA, accessor: p2, payload, now, allowed: false, reason: 'missing' },
  { op: 'check-presentation', set: friends, object: chatA, accessor: p2, payload, now, allowed: true, reason: 'same-group' },
  { op: 'check-presentation', set: friends, object: chatA, accessor: p2, payload: { stated: 0, from: at, until: now + 100 }, now, allowed: false, reason: 'cancelled' },
]);
add('reject', 'one-sided-membership-is-not-a-grant', [
  put(),
  member(),
  objectEdge(),
  check(chatA, p2, false, 'missing'),
]);
add('accept', 'hop-does-not-grant', [
  put(),
  check(chatA, p2, false, 'missing', { hop: true }),
  member(),
  setAssent(),
  objectEdge(),
  check(chatA, p2, true, 'same-group', { hop: true }),
]);
add('reject', 'other-principal-is-not-the-owner', [
  ...live(),
  check(chatA, p3, false, 'missing'),
  check(chatA, p, true, 'owner'),
]);
add('reject', 'missing-signed-owner-is-not-owner', [
  member(),
  setAssent(),
  objectEdge(),
  check(chatA, p, false, 'missing'),
  check(chatA, p2, false, 'missing'),
  put(),
  check(chatA, p, true, 'owner'),
  check(chatA, p3, false, 'missing'),
  check(chatA, p2, true, 'same-group'),
]);
const lowEdge = () => ({ op: 'admit-object-set', row: edge(1, { hamState: 1 }), rotations: 'genesis', ok: true, kept: true });
const highEdge = () => ({ op: 'admit-object-set', row: edge(1, { hamState: 2 }), rotations: 'genesis', ok: true, kept: true });
const objectCancel = () => admitCancel(cancelRow('object-set', 1), 'genesis');
function side(step) {
  return { ...step, on: 'side' };
}
add('reject', 'merge-keeps-object-set-cancel-when-local-wins', [
  put(),
  member(),
  setAssent(),
  highEdge(),
  side(put()),
  side(member()),
  side(setAssent()),
  side(lowEdge()),
  side(objectCancel()),
  { op: 'merge' },
  check(chatA, p2, false, 'missing'),
]);
add('reject', 'merge-keeps-object-set-cancel-when-incoming-wins', [
  put(),
  member(),
  setAssent(),
  lowEdge(),
  objectCancel(),
  side(put()),
  side(member()),
  side(setAssent()),
  side(highEdge()),
  { op: 'merge' },
  check(chatA, p2, false, 'missing'),
]);
add('reject', 'merge-into-side-keeps-object-set-cancel-when-local-wins', [
  put(),
  member(),
  setAssent(),
  highEdge(),
  side(put()),
  side(member()),
  side(setAssent()),
  side(lowEdge()),
  side(objectCancel()),
  { op: 'merge', into: 'side' },
  side(check(chatA, p2, false, 'missing')),
]);
add('reject', 'merge-into-side-keeps-object-set-cancel-when-incoming-wins', [
  put(),
  member(),
  setAssent(),
  lowEdge(),
  objectCancel(),
  side(put()),
  side(member()),
  side(setAssent()),
  side(highEdge()),
  { op: 'merge', into: 'side' },
  side(check(chatA, p2, false, 'missing')),
]);
add('reject', 'merge-drops-an-object-set-that-arrives-first', [
  side(put()),
  side(member()),
  side(setAssent()),
  side(objectEdge()),
  { op: 'merge' },
  check(chatA, p2, false, 'missing'),
  put(),
  check(chatA, p2, false, 'missing'),
], 'An object-set row merged in before this graph holds the admitted signed object record is dropped. A later record does not revive it.');
const capturedCancel = cancelRow('object-set', 1);
add('reject', 'object-set-cancel-cannot-move-to-another-set', [
  put(),
  { op: 'admit-member', row: assent('member', 2, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(1, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-cancel', row: { ...capturedCancel, set: otherSet }, rotations: 'genesis', ok: false, reason: 'bad-record' },
  check(chatA, p2, true, 'same-group'),
]);
add('reject', 'object-set-cancel-cannot-move-to-another-predicate', [
  put(),
  member(),
  setAssent(),
  objectEdge(),
  { op: 'admit-cancel', row: { ...capturedCancel, predicate: 'named-circle' }, rotations: 'genesis', ok: false, reason: 'bad-record' },
  check(chatA, p2, true, 'same-group'),
]);
add('reject', 'object-set-cancel-recomputed-soul-is-bad-signature', [
  put(),
  { op: 'admit-member', row: assent('member', 2, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(1, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-cancel', row: { ...capturedCancel, set: otherSet, rowSoul: objectSetSoul(p, chatA, 'same-group', otherSet) }, rotations: 'genesis', ok: false, reason: 'bad-signature' },
  check(chatA, p2, true, 'same-group'),
]);
const mutableCancel = cancelRow('membership', 2);
add('reject', 'reverify-uses-stored-signature', [
  put(),
  member(),
  setAssent(),
  objectEdge(),
  admitCancel(mutableCancel, 'genesis'),
  check(chatA, p2, false, 'missing'),
  { op: 'mutate-row', field: 'sig', value: 'aa' },
  { op: 'reverify-group', principal: p2, rotations: 'genesis', ok: true, dropped: 0 },
  check(chatA, p2, false, 'missing'),
], 'mutate-row changes the caller row in TypeScript. Rust already stored its own copy, so the step does nothing there.');
add('accept', 'witnessed-retired-cancel-applies', [
  put(),
  { op: 'admit-member', row: assent('member', 2, { issuedAt: now }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 2, { issuedAt: now }), rotations: 'rotated', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(2, { issuedAt: now }), rotations: 'rotated', ok: true, kept: true },
  admitCancel(cancelRow('membership', 1, { issuedAt: at, attest: true }), 'rotated'),
  check(chatA, p2, false, 'missing'),
]);
const retiredSet = assent('set', 1, { issuedAt: at });
retiredSet.attest = aclAttest(membershipAssentBytes({ ...retiredSet, sig: undefined, attest: undefined }), at, p);
add('reject', 'witnessed-retired-assent-refused', [
  { op: 'admit-member', row: retiredSet, rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
]);
const snapEdge = { predicate: 'same-group', setId: friends, stated: 1, hamState: 1 };
add('accept', 'snapshot-understates-a-newer-edge', [
  ...live(),
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, hamState: 0 }, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: false },
  { op: 'snapshot', object: chatA, members: [], objectSet: null, understates: true },
]);
add('accept', 'snapshot-understates-a-cancelled-object-set', [
  ...live(),
  objectCancel(),
  check(chatA, p2, false, 'missing'),
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 0 }, understates: false },
]);
add('accept', 'snapshot-understates-a-stale-cancel', [
  ...live(),
  objectCancel(),
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 0, hamState: 0 }, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 1, hamState: 2 }, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 0, hamState: 2 }, understates: false },
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 0, setId: otherSet }, understates: true },
]);
add('accept', 'snapshot-of-a-readded-edge-that-observes-the-cancel', [
  ...live(),
  objectCancel(),
  { op: 'admit-object-set', row: edge(1, { hamState: 2, cancels: [cancelId] }), rotations: 'genesis', ok: true, kept: true },
  check(chatA, p2, true, 'same-group'),
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, hamState: 2 }, understates: false },
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 0, hamState: 2 }, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 0, hamState: 3 }, understates: true },
]);
add('accept', 'snapshot-of-a-readded-edge-that-misses-the-cancel', [
  ...live(),
  objectCancel(),
  { op: 'admit-object-set', row: edge(1, { hamState: 3 }), rotations: 'genesis', ok: true, kept: true },
  check(chatA, p2, false, 'missing'),
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, hamState: 3 }, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, stated: 0, hamState: 3 }, understates: false },
]);
const onOtherSet = (extra = {}) => ({ set: otherSet, ...extra });
add('accept', 'merge-drops-another-sets-cancel-when-local-wins', [
  put(),
  { op: 'admit-member', row: assent('member', 2, onOtherSet()), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, onOtherSet()), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(1, onOtherSet({ hamState: 3 })), rotations: 'genesis', ok: true, kept: true },
  check(chatA, p2, true, 'same-group'),
  side(put()),
  side(member()),
  side(setAssent()),
  side(objectEdge()),
  side(objectCancel()),
  side(check(chatA, p2, false, 'missing')),
  { op: 'merge' },
  check(chatA, p2, true, 'same-group'),
]);
add('accept', 'merge-drops-another-sets-cancel-when-incoming-wins', [
  put(),
  member(),
  setAssent(),
  objectEdge(),
  objectCancel(),
  check(chatA, p2, false, 'missing'),
  { op: 'admit-member', row: assent('member', 2, onOtherSet()), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, onOtherSet()), rotations: 'genesis', ok: true, kept: true },
  side(put()),
  side({ op: 'admit-member', row: assent('member', 2, onOtherSet()), rotations: 'genesis', ok: true, kept: true }),
  side({ op: 'admit-member', row: assent('set', 1, onOtherSet()), rotations: 'genesis', ok: true, kept: true }),
  side({ op: 'admit-object-set', row: edge(1, onOtherSet({ hamState: 3 })), rotations: 'genesis', ok: true, kept: true }),
  { op: 'merge' },
  check(chatA, p2, true, 'same-group'),
]);
add('accept', 'merge-into-side-drops-another-sets-cancel-when-local-wins', [
  put(),
  member(),
  setAssent(),
  objectEdge(),
  objectCancel(),
  side(put()),
  side({ op: 'admit-member', row: assent('member', 2, onOtherSet()), rotations: 'genesis', ok: true, kept: true }),
  side({ op: 'admit-member', row: assent('set', 1, onOtherSet()), rotations: 'genesis', ok: true, kept: true }),
  side({ op: 'admit-object-set', row: edge(1, onOtherSet({ hamState: 3 })), rotations: 'genesis', ok: true, kept: true }),
  side(check(chatA, p2, true, 'same-group')),
  { op: 'merge', into: 'side' },
  side(check(chatA, p2, true, 'same-group')),
]);
add('accept', 'merge-into-side-drops-another-sets-cancel-when-incoming-wins', [
  put(),
  { op: 'admit-member', row: assent('member', 2, onOtherSet()), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, onOtherSet()), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(1, onOtherSet({ hamState: 3 })), rotations: 'genesis', ok: true, kept: true },
  side(put()),
  side(member()),
  side(setAssent()),
  side(objectEdge()),
  side(objectCancel()),
  side({ op: 'admit-member', row: assent('member', 2, onOtherSet()), rotations: 'genesis', ok: true, kept: true }),
  side({ op: 'admit-member', row: assent('set', 1, onOtherSet()), rotations: 'genesis', ok: true, kept: true }),
  side(check(chatA, p2, false, 'missing')),
  { op: 'merge', into: 'side' },
  side(check(chatA, p2, true, 'same-group')),
]);
add('accept', 'merge-drops-another-predicates-cancel-when-local-wins', [
  put(),
  { op: 'admit-member', row: assent('member', 2, { predicate: 'named-circle' }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, { predicate: 'named-circle' }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(1, { predicate: 'named-circle', hamState: 3 }), rotations: 'genesis', ok: true, kept: true },
  check(chatA, p2, true, 'named-circle', { predicate: 'named-circle' }),
  side(put()),
  side(member()),
  side(setAssent()),
  side(objectEdge()),
  side(objectCancel()),
  { op: 'merge' },
  check(chatA, p2, true, 'named-circle', { predicate: 'named-circle' }),
]);
add('accept', 'reverify-drops-unwitnessed-object-set-cancel', [
  put(),
  { op: 'admit-member', row: assent('member', 2, { issuedAt: now }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 2, { issuedAt: now }), rotations: 'rotated', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(2, { issuedAt: now, hamState: 2 }), rotations: 'rotated', ok: true, kept: true },
  admitCancel(cancelRow('object-set', 1, { issuedAt: at }), 'genesis'),
  check(chatA, p2, false, 'missing'),
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 1 },
  check(chatA, p2, true, 'same-group'),
], 'Dropping an unwitnessed retired-key cancel on reverify follows the locked rule: only a witnessed cancel survives.');
add('accept', 'object-set-cancel-is-scoped-to-its-set', [
  put(),
  member(),
  setAssent(),
  objectEdge(),
  objectCancel(),
  check(chatA, p2, false, 'missing'),
  { op: 'admit-object-set', row: edge(1, { hamState: 2 }), rotations: 'genesis', ok: true, kept: true },
  check(chatA, p2, false, 'missing'),
  { op: 'admit-member', row: assent('member', 2, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, { set: otherSet }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(1, { set: otherSet, hamState: 3 }), rotations: 'genesis', ok: true, kept: true },
  check(chatA, p2, true, 'same-group'),
]);
add('accept', 'snapshot-without-an-edge', [
  { op: 'snapshot', object: chatA, members: [], objectSet: null, understates: false },
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: true },
]);
const currentEdge = () => ({ op: 'admit-object-set', row: edge(2, { issuedAt: now }), rotations: 'rotated', ok: true, kept: true });
const currentMember = () => ({ op: 'admit-member', row: assent('member', 2, { issuedAt: now }), rotations: 'genesis', ok: true, kept: true });
const currentSet = () => ({ op: 'admit-member', row: assent('set', 2, { issuedAt: now }), rotations: 'rotated', ok: true, kept: true });
const bareMemberCancel = cancelRow('membership', 1, { issuedAt: at });
const witnessedMemberCancel = cancelRow('membership', 1, { issuedAt: at, attest: true });
const bareObjectCancel = cancelRow('object-set', 1, { issuedAt: at });
const witnessedObjectCancel = cancelRow('object-set', 1, { issuedAt: at, attest: true });
add('accept', 'witnessed-duplicate-replaces-a-bare-membership-cancel', [
  put(),
  currentMember(),
  currentSet(),
  currentEdge(),
  admitCancel(bareMemberCancel, 'genesis'),
  admitCancel(witnessedMemberCancel, 'rotated'),
  check(chatA, p2, false, 'missing'),
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 0 },
  check(chatA, p2, false, 'missing'),
]);
add('accept', 'witnessed-duplicate-replaces-a-bare-object-set-cancel', [
  put(),
  currentMember(),
  currentSet(),
  currentEdge(),
  admitCancel(bareObjectCancel, 'genesis'),
  admitCancel(witnessedObjectCancel, 'rotated'),
  check(chatA, p2, false, 'missing'),
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 0 },
  check(chatA, p2, false, 'missing'),
]);
add('accept', 'merge-upgrades-a-bare-membership-cancel', [
  put(),
  currentMember(),
  currentSet(),
  currentEdge(),
  admitCancel(bareMemberCancel, 'genesis'),
  side(put()),
  side(currentMember()),
  side(currentSet()),
  side(currentEdge()),
  side(admitCancel(witnessedMemberCancel, 'rotated')),
  { op: 'merge', rotations: 'rotated' },
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 0 },
  check(chatA, p2, false, 'missing'),
]);
add('accept', 'merge-upgrades-a-bare-object-set-cancel', [
  put(),
  currentMember(),
  currentSet(),
  currentEdge(),
  admitCancel(bareObjectCancel, 'genesis'),
  side(put()),
  side(currentMember()),
  side(currentSet()),
  side(currentEdge()),
  side(admitCancel(witnessedObjectCancel, 'rotated')),
  { op: 'merge', rotations: 'rotated' },
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 0 },
  check(chatA, p2, false, 'missing'),
]);
add('accept', 'merge-upgrades-a-present-attested-copy-after-rotation', [
  put(),
  currentMember(),
  currentSet(),
  currentEdge(),
  admitCancel(bareObjectCancel, 'genesis'),
  side(put()),
  side(currentMember()),
  side(currentSet()),
  side(currentEdge()),
  side(admitCancel(witnessedObjectCancel, 'genesis')),
  { op: 'merge', rotations: 'rotated' },
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 0 },
  check(chatA, p2, false, 'missing'),
], 'Both copies were admitted while the key was current, so both were stored as present. Merge with the rotated history stores the witnessed mode on the incoming copy and that copy replaces the bare one.');
add('accept', 'merge-keeps-a-witnessed-cancel-over-a-bare-copy', [
  put(),
  currentMember(),
  currentSet(),
  currentEdge(),
  admitCancel(witnessedObjectCancel, 'rotated'),
  side(put()),
  side(currentMember()),
  side(currentSet()),
  side(currentEdge()),
  side(admitCancel(bareObjectCancel, 'genesis')),
  { op: 'merge' },
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 0 },
  check(chatA, p2, false, 'missing'),
]);
add('accept', 'reverify-keeps-a-witnessed-cancel-when-the-edge-retires', [
  put(),
  currentMember(),
  currentSet(),
  { op: 'admit-object-set', row: edge(1, { issuedAt: at }), rotations: 'genesis', ok: true, kept: true },
  admitCancel(witnessedObjectCancel, 'genesis'),
  check(chatA, p2, false, 'missing'),
  { op: 'reverify-group', principal: p, rotations: 'rotated', ok: true, dropped: 1 },
  { op: 'admit-object-set', row: edge(2, { issuedAt: now, hamState: 2 }), rotations: 'rotated', ok: true, kept: true },
  check(chatA, p2, false, 'missing'),
  { op: 'admit-object-set', row: edge(2, { issuedAt: now, hamState: 3, cancels: [cancelId] }), rotations: 'rotated', ok: true, kept: true },
  check(chatA, p2, true, 'same-group'),
]);
add('accept', 'snapshot-ignores-a-one-sided-join', [
  put(),
  member(),
  objectEdge(),
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: false },
]);
const retiredMember = { accessor: p2, predicate: 'same-group', setId: friends, stated: 0, hamState: 1 };
add('accept', 'snapshot-understates-a-stated-zero-membership', [
  put(),
  { op: 'admit-member', row: assent('member', 2, { stated: 0 }), rotations: 'genesis', ok: true, kept: true },
  setAssent(),
  objectEdge(),
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: true },
  { op: 'snapshot', object: chatA, members: [{ ...retiredMember, stated: 1 }], objectSet: snapEdge, understates: true },
  { op: 'snapshot', object: chatA, members: [retiredMember], objectSet: snapEdge, understates: false },
]);
add('accept', 'snapshot-understates-an-uncovered-membership-cancel', [
  ...live(),
  admitCancel(cancelRow('membership', 2), 'genesis'),
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: true },
  { op: 'snapshot', object: chatA, members: [retiredMember], objectSet: snapEdge, understates: false },
]);
add('accept', 'predicate-change-drops-the-previous-cancels', [
  ...live(),
  objectCancel(),
  check(chatA, p2, false, 'missing'),
  { op: 'admit-member', row: assent('member', 2, { predicate: 'named-circle' }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-member', row: assent('set', 1, { predicate: 'named-circle' }), rotations: 'genesis', ok: true, kept: true },
  { op: 'admit-object-set', row: edge(1, { predicate: 'named-circle', hamState: 2 }), rotations: 'genesis', ok: true, kept: true },
  check(chatA, p2, true, 'named-circle', { predicate: 'named-circle' }),
]);
const movedCancel = cancelRow('membership', 2);
add('reject', 'cancel-issued-at-is-signed', [
  ...live(),
  { op: 'admit-cancel', row: { ...movedCancel, issuedAt: at + 1 }, rotations: 'genesis', ok: false, reason: 'bad-signature' },
  check(chatA, p2, true, 'same-group'),
]);
const witnessedRewrite = cancelRow('membership', 1, { issuedAt: at, attest: true });
add('reject', 'zz-witnessed-cancel-issuedat-rewrite', [
  ...live(),
  { op: 'admit-cancel', row: { ...witnessedRewrite, issuedAt: at + 1 }, rotations: 'rotated', ok: false, reason: 'bad-attestation' },
  check(chatA, p2, true, 'same-group'),
]);
const body = { v: 1, family: 'group', context, accept, reject };
const path = new URL('../../../vectors/mesh/v2/group.json', import.meta.url);
writeFileSync(path, JSON.stringify(body, null, 2) + '\n');
console.log(`group accept ${accept.length} reject ${reject.length}`);
