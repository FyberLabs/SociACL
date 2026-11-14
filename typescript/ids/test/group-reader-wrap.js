import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync,writeFileSync } from 'node:fs';
import { createECDH, createHash, createDecipheriv } from 'node:crypto';
import { wrapGroupKeyToMembers, openGroupKeyReaderWrap } from '../src/group-reader-wrap.js';
const load = name => JSON.parse(readFileSync(new URL(`../../../vectors/encrypted-discovery/${name}.json`, import.meta.url), 'utf8'));
const fixture = load('sea-fixture'), vector = load('wrap');
const context = { epoch: vector.epoch, group: vector.object.replace('item_','set_'), revisionId: fixture.revisionId };
const reader = { account: fixture.signing.pub, pub: fixture.signing.pub, identityPub: fixture.signing.pub, epub: fixture.encryption.epub };
const groupHex='33'.repeat(32);
const dek = Uint8Array.from(Buffer.from(groupHex, 'hex'));
const wrap = (await wrapGroupKeyToMembers(dek,context,[reader],[reader.account])).value[0];
const open = (value = wrap, scope = context, secret = fixture.encryption.epriv, epub = reader.epub) => openGroupKeyReaderWrap(value, secret, epub, scope);
const seal = (readers = [reader], named = [reader.account], scope = context, key = dek) => wrapGroupKeyToMembers(key, scope, readers, named);
function lp(fields) {
  return Buffer.concat(fields.map(field => { const bytes = Buffer.from(field), size = Buffer.alloc(4); size.writeUInt32LE(bytes.length); return Buffer.concat([size, bytes]); }));
}
test('opens the actual Rust group member wrap', {skip:!process.env.GROUP_MEMBER_RUST_VECTOR},async () => {
  const result = await open(JSON.parse(readFileSync(process.env.GROUP_MEMBER_RUST_VECTOR)));  assert.equal(result.ok, true); assert.deepEqual(result.value, dek);
});
test('fresh browser wraps decrypt with an independent Node crypto implementation', async () => {
  const first = await seal(), second = await seal();
  assert.equal(first.ok, true); assert.equal(second.ok, true);
  assert.notEqual(first.value[0].wrappedKey, second.value[0].wrappedKey);
  if(process.env.GROUP_MEMBER_TS_VECTOR)writeFileSync(process.env.GROUP_MEMBER_TS_VECTOR,JSON.stringify(first.value[0]));
  const row = first.value[0], bytes = Buffer.from(row.wrappedKey, 'hex');
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(Buffer.from(fixture.encryption.epriv, 'base64url'));
  const shared = ecdh.computeSecret(bytes.subarray(1, 66));
  const key = createHash('sha256').update(lp(['s3rch-sea-secret-v1', shared.toString('hex')])).digest();
  const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(66, 78)); decipher.setAuthTag(bytes.subarray(-16));
  const plain = Buffer.concat([decipher.update(bytes.subarray(78, -16)), decipher.final()]);
  assert.deepEqual(plain, lp(['s3rch-wrapped-key-v1', 'group-key', String(context.epoch), 'reader-epub', reader.epub, '', context.group, context.revisionId, groupHex]));
  assert.deepEqual((await open(row)).value, dek);
  assert.equal(Object.isFrozen(first.value), true); assert.equal(Object.isFrozen(row), true);
  assert.deepEqual(dek, Uint8Array.from(Buffer.from(groupHex, 'hex')));
});
test('sealed labels, expected epoch, ciphertext and recipient must all agree', async () => {
  for (const patch of [{ epoch: 4 }, { group: context.group.replace(/1$/, '2') }, { revisionId: 'a'.repeat(64) },
    { target: 'group-epoch' }, { scope: 'item-dek' }, { targetId: fixture.signing.pub }, { extra: true },
    { wrappedKey: '02' + wrap.wrappedKey.slice(2) }, { wrappedKey: wrap.wrappedKey.slice(0, -2) + (parseInt(wrap.wrappedKey.slice(-2),16)^1).toString(16).padStart(2,'0') },
    { wrappedKey: wrap.wrappedKey.toUpperCase() }, { wrappedKey: '00'.repeat(8193) }, { wrappedKey: '00' }]) {
    assert.deepEqual(await open({ ...wrap, ...patch }), { ok: false, reason: 'bad-record' });
  }
  assert.equal((await open(wrap, { ...context, epoch: 4 })).ok, false);
  assert.equal((await open(wrap, context, fixture.signing.priv)).ok, false);
  assert.equal((await open(wrap, context, fixture.encryption.epriv, fixture.signing.pub)).ok, false);
  assert.equal((await open(wrap, context, 'invalid')).ok, false);
});
test('unnamed, duplicate, mismatched and malformed readers fail without partial wraps', async () => {
  for (const readers of [[reader, reader], [reader, { ...reader, account: 'wallet' }], [{ ...reader, identityPub: reader.epub }],
    [{ ...reader, epub: 'bad' }], [{ ...reader, extra: true }], new Array(65).fill(reader)]) {
    assert.deepEqual(await seal(readers), { ok: false, reason: 'bad-record' });
  }
  for (const named of [[], [reader.account, reader.account], ['wallet']]) assert.equal((await seal([reader], named)).ok, false);
  for (const scope of [{ ...context, epoch: -0 }, { ...context, epoch: NaN }, { ...context, epoch: 2 ** 53 },
    { ...context, group: 'invalid' }, { ...context, revisionId: 'A'.repeat(64) }]) assert.equal((await seal([reader], [reader.account], scope)).ok, false);
  assert.equal((await seal([reader], [reader.account], context, new Uint8Array(31))).ok, false);
});
test('input arrays and records are snapshotted without invoking accessors', async () => {
  let called = 0; const readers = [reader]; Object.defineProperty(readers, '0', { get() { called++; return reader; } });
  assert.equal((await seal(readers)).ok, false); assert.equal(called, 0);
  const altered = [reader]; altered.map = () => { called++; return []; };
  assert.equal((await seal(altered)).ok, false); assert.equal(called, 0);
  const poison = { ...reader }; Object.defineProperty(poison, 'epub', { get() { called++; return reader.epub; } });
  assert.equal((await seal([poison])).ok, false); assert.equal(called, 0);
  const mutable = { ...reader }, key = new Uint8Array(dek), scope = { ...context };
  const pending = seal([mutable], [reader.account], scope, key);
  mutable.epub = fixture.signing.pub; key.fill(0); scope.epoch++;
  const result = await pending; assert.equal(result.ok, true); assert.deepEqual((await open(result.value[0])).value, dek);
  const revoked = Proxy.revocable([], {}); revoked.revoke(); assert.equal((await seal(revoked.proxy)).ok, false);
});

test('typed-array length overrides never forge a DEK or execute a getter', async () => {
  let calls = 0;
  const short = new Uint8Array(31);
  Object.defineProperty(short, 'length', { get() { calls++; return 32; } });
  assert.equal((await seal([reader], [reader.account], context, short)).ok, false);
  class DecoratedKey extends Uint8Array { get length() { calls++; throw Error('must not read caller length'); } }
  const valid = new DecoratedKey(dek);
  const result = await seal([reader], [reader.account], context, valid);
  assert.equal(result.ok, true); assert.deepEqual((await open(result.value[0])).value, dek);
  assert.equal(calls, 0);
});
