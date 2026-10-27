// Author vectors/mesh/v2/post.json. Public test scalars only. Not part of CI.
import { writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import * as ids from '../src/index.js';
import { runPostCase } from '../../src/post.js';
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
function signed(bytesFor, fields, signer, patch) {
  const bare = { ...fields, sig: '' };
  const bytes = bytesFor(bare);
  const row = { ...fields, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
  if (patch !== undefined) row.attest = typeof patch === 'string' ? patch : attest(bytes, fields.issuedAt, fields.owner, patch);
  return row;
}
const seeBase = (extra) => ({ owner: p, object: chatA, accessor: p2, stated: 1, from: 0, until: 100, hamState: 1, issuedAt: at, ...extra });
const postBase = (extra) => ({ owner: p, object: chatA, accessor: p2, stated: 1, from: 0, until: 100, hamState: 1, issuedAt: at, ...extra });
const seeRow = (extra, signer = 1, patch) => signed(ids.seeGrantBytes, seeBase(extra), signer, patch);
const postRow = (extra, signer = 1, patch) => signed(ids.postGrantBytes, postBase(extra), signer, patch);
function objectRecord(object, owner, signer, issuedAt = at) {
  const bare = { object, owner, issuedAt, sig: '' };
  const bytes = ids.objectRecordBytes(bare);
  return { object, owner, issuedAt, sig: val(ids.signWithKeyring(secret(signer), bytes, keyFor(signer))) };
}
function put(object, owner, signer, issuedAt = at) {
  return { op: 'put', record: objectRecord(object, owner, signer, issuedAt), rotations: 'genesis', ok: true, kept: true };
}
const options = { ctx, rotations: (name) => context.rotationSets[name] };
const accept = [];
const reject = [];
function add(bucket, name, steps) {
  runPostCase(steps, options);
  (bucket === 'accept' ? accept : reject).push({ name, steps });
}
const edge = (kind, value) => {
  const got = kind === 'object' ? ids.parseObjectId(value) : ids.parsePrincipalId(value);
  if (got.ok) throw Error('edge accepted ' + value);
  return { op: 'edge', kind, value, reason: got.reason };
};
function compareBytes(left, right) {
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i += 1) if (left[i] !== right[i]) return left[i] - right[i];
  return left.length - right.length;
}

add('reject', 'item-soul-spelling-is-parse-reject', [edge('object', 's3rch/items/room_alpha')]);
{
  const see = seeRow({});
  const post = postRow({});
  add('reject', 'no-second-row-for-alias', [
    put(chatA, p, 1),
    { op: 'admit', row: see, rotations: 'genesis', ok: true, kept: true },
    { op: 'admit-post', row: post, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'post' },
    edge('object', `s3rch/items/${chatA}`),
  ]);
}
{
  const see = seeRow({});
  const post = postRow({});
  const cancel = seeRow({ stated: 0, hamState: 2 });
  add('accept', 'cancel-see-denies-post', [
    put(chatA, p, 1),
    { op: 'admit', row: see, rotations: 'genesis', ok: true, kept: true },
    { op: 'admit-post', row: post, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'post' },
    { op: 'admit', row: cancel, rotations: 'genesis', ok: true, kept: true },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
    { op: 'view-post', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
  ]);
}
{
  const max = Number.MAX_SAFE_INTEGER;
  const left = postRow({ hamState: max, from: 0, until: 30 });
  const right = postRow({ hamState: max, from: 20, until: 80 });
  const leftRow = { row: left, bytes: ids.postGrantBytes(left) };
  const rightRow = { row: right, bytes: ids.postGrantBytes(right) };
  const leftSmaller = compareBytes(leftRow.bytes, rightRow.bytes) < 0;
  const winner = leftSmaller ? left : right;
  const loser = leftSmaller ? right : left;
  add('accept', 'post-ceiling-refuses-without-write', [
    put(chatA, p, 1),
    { op: 'admit', row: seeRow({}), rotations: 'genesis', ok: true, kept: true },
    { op: 'admit-post', row: winner, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: max },
    { op: 'admit-post', row: loser, rotations: 'genesis', ok: true, kept: false },
    { op: 'view-post', object: chatA, accessor: p2, stated: 1, hamState: max, mode: 'present', from: winner.from, until: winner.until },
    { op: 'check-post', object: chatA, accessor: p2, now: 25, allowed: true, reason: 'post' },
  ]);
}
add('accept', 'hint-and-hop-do-not-grant', [
  put(chatA, p, 1),
  { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate', hint: true, hop: true },
  { op: 'view-post', object: chatA, accessor: p2, absent: true },
]);
{
  const post = postRow({});
  add('accept', 'hint-and-hop-do-not-mint-on-a-live-row', [
    put(chatA, p, 1),
    { op: 'admit', row: seeRow({}), rotations: 'genesis', ok: true, kept: true },
    { op: 'admit-post', row: post, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'post', hint: true, hop: true },
    { op: 'view-post', object: chatA, accessor: p2, stated: 1, hamState: 1, mode: 'present' },
  ]);
}
add('accept', 'owner-posts-from-the-object-record', [
  put(chatA, p, 1),
  { op: 'check-post', object: chatA, accessor: p, now: 10, allowed: true, reason: 'owner' },
  { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'delegate' },
]);
{
  const post = postRow({});
  const cancel = postRow({ stated: 0, hamState: 2 });
  add('accept', 'delegate-post-cancel-denies', [
    put(chatA, p, 1),
    { op: 'admit', row: seeRow({}), rotations: 'genesis', ok: true, kept: true },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'missing' },
    { op: 'admit-post', row: post, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: true, reason: 'post' },
    { op: 'admit-post', row: cancel, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 0, hamState: 2 },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'cancelled' },
  ]);
}
add('reject', 'post-row-without-object-record', [
  { op: 'admit-post', row: postRow({}), rotations: 'genesis', ok: false, reason: 'unknown' },
]);
add('reject', 'post-row-owner-must-match-record', [
  put(chatA, p, 1),
  { op: 'admit-post', row: postRow({ owner: p2 }, 2), rotations: 'genesis', ok: false, reason: 'bad-record' },
  { op: 'view-post', object: chatA, accessor: p2, absent: true },
]);
{
  const row = postRow({});
  add('reject', 'id-field-not-string', [
    { op: 'admit-post', row, rotations: 'genesis', patch: { owner: 5 }, ok: false, reason: 'not-string' },
    { op: 'admit-post', row, rotations: 'genesis', patch: { object: 5 }, ok: false, reason: 'not-string' },
    { op: 'admit-post', row, rotations: 'genesis', patch: { accessor: 5 }, ok: false, reason: 'not-string' },
  ]);
}
{
  const live = postRow({ stated: 1, issuedAt: retiredAt }, 1, {});
  add('reject', 'retired-post-grant-witnessed', [
    { op: 'admit-post', row: live, rotations: 'rotated', ok: false, reason: 'unwitnessed-retired-key' },
  ]);
}
function retiredPost(name, patch, reason) {
  const made = postRow({ stated: 0, issuedAt: retiredAt }, 1, patch);
  add('reject', name, [
    { op: 'admit-post', row: made, rotations: 'rotated', ok: false, reason },
  ]);
}
retiredPost('witness-wrong-iat', { iat: retiredAt - 1, exp: retiredAt + 100 }, 'bad-attestation');
retiredPost('witness-wrong-recordId', { recordId: '00'.repeat(32) }, 'bad-attestation');
retiredPost('witness-window-901', { exp: retiredAt + 901 }, 'bad-attestation');
retiredPost('witness-wrong-principal', { principal: p2 }, 'bad-attestation');
retiredPost('witness-too-long', 'x'.repeat(16385), 'too-long');
add('reject', 'post-grant-v1-refused', [
  put(chatA, p, 1),
  { op: 'admit-post', row: { ...postRow({}), domain: 's3rch-post-grant-v1' }, rotations: 'genesis', ok: false, reason: 'legacy-row' },
]);
{
  const cancel = postRow({ stated: 0, issuedAt: retiredAt }, 1, {});
  add('accept', 'retired-witnessed-post-cancel', [
    { op: 'put', record: objectRecord(chatA, p, 2, at + 40), rotations: 'rotated', ok: true, kept: true },
    { op: 'admit', row: seeRow({ issuedAt: at + 40 }, 2), rotations: 'rotated', ok: true, kept: true },
    { op: 'admit-post', row: cancel, rotations: 'rotated', ok: true, kept: true, mode: 'witnessed', stated: 0, hamState: 1 },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'cancelled' },
  ]);
}

{
  const see = seeRow({ issuedAt: at });
  const post = postRow({ issuedAt: at });
  add('reject', 'rotation-drops-old-post', [
    put(chatA, p, 1),
    { op: 'admit', row: see, rotations: 'genesis', ok: true, kept: true },
    { op: 'admit-post', row: post, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'reverify', principal: p, rotations: 'rotated', dropped: 3 },
    { op: 'view-post', object: chatA, accessor: p2, absent: true },
    { op: 'check-post', object: chatA, accessor: p2, now: 10, allowed: false, reason: 'unknown' },
  ]);
  add('reject', 'missing-history-drops-post', [
    put(chatA, p, 1),
    { op: 'admit-post', row: post, rotations: 'genesis', ok: true, kept: true, mode: 'present', stated: 1, hamState: 1 },
    { op: 'reverify', principal: p, history: 'unavailable', ok: false, reason: 'missing-history' },
    { op: 'view-post', object: chatA, accessor: p2, absent: true },
    { op: 'owner', object: chatA, absent: true },
  ]);
}
const body = { v: 1, family: 'post', context, accept, reject };
const path = new URL('../../../vectors/mesh/v2/post.json', import.meta.url);
writeFileSync(path, JSON.stringify(body, null, 2) + '\n');
console.log(`post accept ${accept.length} reject ${reject.length}`);
