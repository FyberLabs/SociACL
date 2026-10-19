// Author vectors/mesh/v2/group.json. Public test scalars only. Not part of CI.
import { writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import * as ids from '../src/index.js';
import { membershipAssentBytes, objectSetBytes } from '../../src/group.js';
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
const payload = { stated: 1, from: at, until: now + 100 };
const options = { ctx, rotations: (name) => context.rotationSets[name] };
const accept = [];
const reject = [];
function add(bucket, name, steps) {
  runGroupCase(steps, options);
  (bucket === 'accept' ? accept : reject).push({ name, steps });
}
add('reject', 'set-id-must-be-minted', [
  { op: 'admit-member', row: assent('member', 2, { set: 'alice/friends' }), rotations: 'genesis', ok: false, reason: 'bad-alphabet' },
  { op: 'admit-member', row: assent('member', 2, { set: unbound }), rotations: 'genesis', ok: false, reason: 'bad-template' },
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
add('reject', 'label-owner-mismatch-denies', [
  ...live(),
  { op: 'label-owner', object: chatA, owner: p3 },
  check(chatA, p2, false, 'missing'),
]);
const snapEdge = { predicate: 'same-group', setId: friends, stated: 1, hamState: 1 };
add('accept', 'snapshot-understates-a-newer-edge', [
  ...live(),
  { op: 'snapshot', object: chatA, members: [], objectSet: { ...snapEdge, hamState: 0 }, understates: true },
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: false },
  { op: 'snapshot', object: chatA, members: [], objectSet: null, understates: true },
]);
add('accept', 'snapshot-without-an-edge', [
  { op: 'snapshot', object: chatA, members: [], objectSet: null, understates: false },
  { op: 'snapshot', object: chatA, members: [], objectSet: snapEdge, understates: true },
]);
const body = { v: 1, family: 'group', context, accept, reject };
const path = new URL('../../../vectors/mesh/v2/group.json', import.meta.url);
writeFileSync(path, JSON.stringify(body, null, 2) + '\n');
console.log(`group accept ${accept.length} reject ${reject.length}`);
